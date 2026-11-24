<?php

declare(strict_types=1);

/**
 * Unit tests for TOTP, Base32, Crypto and the router's access defaults.
 * TOTP vectors come from RFC 6238 Appendix B (SHA-1).
 */

use Sentinel\Auth\Auth;
use Sentinel\Auth\Permissions;
use Sentinel\Auth\Totp;
use Sentinel\Core\Crypto;
use Sentinel\Core\HttpException;
use Sentinel\Core\Router;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'RFC 6238 SHA-1 test vectors (last 6 digits)' => function (TestContext $ctx): void {
        $secret = Totp::base32Encode('12345678901234567890');
        $vectors = [59 => '287082', 1111111109 => '081804', 1111111111 => '050471', 1234567890 => '005924', 2000000000 => '279037', 20000000000 => '353130'];
        foreach ($vectors as $time => $expected) {
            Assert::same($expected, Totp::code($secret, intdiv($time, 30)), "time {$time}");
        }
    },
    'TOTP accepts +/-1 step, rejects replay and older steps' => function (TestContext $ctx): void {
        $secret = Totp::generateSecret();
        $now = 1_800_000_000;
        $step = intdiv($now, 30);
        Assert::same($step, Totp::verify($secret, Totp::code($secret, $step), null, $now));
        Assert::same($step - 1, Totp::verify($secret, Totp::code($secret, $step - 1), null, $now));
        Assert::same($step + 1, Totp::verify($secret, Totp::code($secret, $step + 1), null, $now));
        Assert::same(null, Totp::verify($secret, Totp::code($secret, $step + 2), null, $now), 'outside window');
        Assert::same(null, Totp::verify($secret, Totp::code($secret, $step), $step, $now), 'replay of same step');
        Assert::same(null, Totp::verify($secret, 'abcdef', null, $now), 'non-numeric');
        Assert::same(null, Totp::verify($secret, '', null, $now), 'empty');
    },
    'Base32 round trip' => function (TestContext $ctx): void {
        $bytes = random_bytes(20);
        Assert::same($bytes, Totp::base32Decode(Totp::base32Encode($bytes)));
    },
    'Crypto v2 values are bound to their place (setting or user)' => function (TestContext $ctx): void {
        $crypto = new Crypto(random_bytes(32));
        $enc = $crypto->encryptFor('setting:smtp_password', 'pw');
        Assert::true(str_starts_with($enc, 'v2:'), 'v2 format');
        Assert::same('pw', $crypto->decryptFor('setting:smtp_password', $enc));
        foreach (['setting:itflow_api_key', 'totp:1', ''] as $other) {
            $threw = false;
            try {
                $crypto->decryptFor($other, $enc);
            } catch (RuntimeException) {
                $threw = true;
            }
            Assert::true($threw, 'moved to ' . $other . ': refused');
        }
        $legacy = $crypto->encrypt('old');
        $threw = false;
        try {
            $crypto->decryptFor('setting:smtp_password', $legacy);
        } catch (RuntimeException) {
            $threw = true;
        }
        Assert::true($threw, 'an unbound v1 value is refused unless allowed');
        Assert::same('old', $crypto->decryptFor('setting:smtp_password', $legacy, true), 'the migration may read v1');
    },
    'Crypto round trip and tamper detection' => function (TestContext $ctx): void {
        $crypto = new Crypto(random_bytes(32));
        $enc = $crypto->encrypt('secret-value');
        Assert::same('secret-value', $crypto->decrypt($enc));
        Assert::true($crypto->encrypt('x') !== $crypto->encrypt('x'), 'fresh nonce each time');
        $raw = base64_decode(substr($enc, 3));
        $raw[30] = chr(ord($raw[30]) ^ 1);
        $threw = false;
        try {
            $crypto->decrypt('v1:' . base64_encode($raw));
        } catch (RuntimeException) {
            $threw = true;
        }
        Assert::true($threw, 'tampered ciphertext must be rejected');
        $threw = false;
        try {
            (new Crypto(random_bytes(32)))->decrypt($enc);
        } catch (RuntimeException) {
            $threw = true;
        }
        Assert::true($threw, 'wrong key must be rejected');
    },
    'Router defaults to any signed-in user and validates {id}' => function (TestContext $ctx): void {
        $r = new Router();
        $r->add('GET', '/things/{id}', ['X', 'y']);
        $m = $r->match('GET', '/things/42');
        Assert::same('user', $m['opts']['auth']);
        Assert::same([], $m['opts']['perm'], 'no permission needed by default');
        foreach ([['perm' => 'no.such'], ['role' => 'admin']] as $bad) {
            $threw = false;
            try {
                $r->add('GET', '/bad', ['X', 'y'], $bad);
            } catch (\InvalidArgumentException) {
                $threw = true;
            }
            Assert::true($threw, 'unknown permissions and old role options are refused: ' . json_encode($bad));
        }
        Assert::same('42', $m['params']['id']);
        foreach (['/things/abc', '/things/0', '/things/1/../2', '/things/'] as $bad) {
            try {
                $r->match('GET', $bad);
                Assert::true(false, "should not match {$bad}");
            } catch (HttpException $ex) {
                Assert::same(404, $ex->status, $bad);
            }
        }
    },
    'IPv6 addresses are throttled per /64, IPv4 per address' => function (TestContext $ctx): void {
        Assert::same(Auth::ipBucketKey('2001:db8:1:2::1'), Auth::ipBucketKey('2001:db8:1:2:ffff:ffff:ffff:ffff'), 'same /64');
        Assert::true(Auth::ipBucketKey('2001:db8:1:2::1') !== Auth::ipBucketKey('2001:db8:1:3::1'), 'different /64');
        Assert::same('192.0.2.10', Auth::ipBucketKey('192.0.2.10'));
    },
    'username rule rejects look-alikes and odd characters' => function (TestContext $ctx): void {
        foreach (['alice', 'a.b-c_d', 'ABC'] as $ok) {
            Assert::true(Auth::isValidUsername($ok), $ok);
        }
        foreach (["\u{00E4}dmin", "adm\u{200B}in", "admin\n", 'ab', str_repeat('a', 51), 'a b', ''] as $bad) {
            Assert::true(!Auth::isValidUsername($bad), json_encode($bad));
        }
    },
    'Built-in roles: Admin holds everything, Technician a subset, Viewer nothing; unknown names never granted' => function (TestContext $ctx): void {
        Assert::true(Permissions::isComplete(Permissions::builtin('admin')), 'admin holds every permission');
        Assert::same([], array_diff(Permissions::builtin('technician'), Permissions::builtin('admin')), 'technician within admin');
        Assert::true(!in_array('users.manage', Permissions::builtin('technician'), true), 'technician cannot manage users');
        Assert::same([], Permissions::builtin('viewer'));
        Assert::same([], Permissions::builtin('bogus'), 'unknown role gets nothing');
        Assert::same(['clients.manage', 'findings.due'], Permissions::clean(['findings.due', 'no.such', 7, 'clients.manage', 'findings.due']), 'cleaned and ordered');
    },
];
