<?php

declare(strict_types=1);

/**
 * End-to-end tests: sign-in, mandatory 2FA, recovery codes, throttling and sessions.
 * All users and passwords are made up.
 */

use Sentinel\Auth\Auth;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'login page renders with security headers and a hardened cookie' => function (TestContext $ctx): void {
        $res = $ctx->client()->get('/login');
        Assert::status(200, $res);
        Assert::contains("default-src 'self'", (string) $res->header('content-security-policy'));
        Assert::contains("frame-ancestors 'none'", (string) $res->header('content-security-policy'));
        Assert::same('DENY', $res->header('x-frame-options'));
        Assert::same('nosniff', $res->header('x-content-type-options'));
        Assert::same('no-store', $res->header('cache-control'));
        $cookie = (string) $res->header('set-cookie');
        Assert::contains('sentinel_session=', $cookie);
        Assert::contains('HttpOnly', $cookie);
        Assert::contains('SameSite=Lax', $cookie);
    },
    'unauthenticated visitors are sent to the login page' => function (TestContext $ctx): void {
        $c = $ctx->client();
        foreach (['/', '/users', '/admin/audit', '/admin/settings', '/profile', '/help'] as $path) {
            Assert::redirect('/login', $c->get($path), $path);
        }
        Assert::redirect('/login', $c->get('/login/2fa'), '2FA page without password step');
        Assert::redirect('/login', $c->get('/2fa/setup'), 'enroll page without password step');
    },
    'wrong password and unknown user get the same generic message' => function (TestContext $ctx): void {
        $c = $ctx->client();
        $bad = $c->submit('/login', '/login', ['username' => 'admin', 'password' => 'wrong-password-123']);
        $unknown = $c->submit('/login', '/login', ['username' => 'nobody-here', 'password' => 'wrong-password-123']);
        Assert::status(422, $bad);
        Assert::status(422, $unknown);
        Assert::contains('Incorrect username or password.', $bad->body);
        Assert::contains('Incorrect username or password.', $unknown->body);
    },
    'POST without or with a wrong CSRF token is rejected' => function (TestContext $ctx): void {
        $c = $ctx->client();
        $c->get('/login');
        Assert::status(400, $c->post('/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!']), 'missing token');
        Assert::status(400, $c->post('/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!', '_csrf' => str_repeat('a', 64)]), 'wrong token');
    },
    'first sign-in forces 2FA enrollment and shows recovery codes once' => function (TestContext $ctx): void {
        $c = $ctx->client();
        $res = $c->submit('/login', '/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!']);
        Assert::redirect('/2fa/setup', $res);
        // While pending, the app itself is still locked.
        Assert::redirect('/login', $c->get('/'), 'dashboard while pending');
        $page = $c->get('/2fa/setup');
        Assert::status(200, $page);
        Assert::contains('data-otpauth="otpauth://totp/', $page->body);
        preg_match('/data-testid="totp-secret">([A-Z2-7 ]+)</', $page->body, $m);
        $ctx->secrets['admin'] = str_replace(' ', '', $m[1]);

        $wrong = $c->post('/2fa/setup', ['_csrf' => $page->csrf(), 'code' => '000000' === $ctx->totp('admin') ? '111111' : '000000']);
        Assert::status(422, $wrong, 'wrong enrollment code');

        $res = $c->post('/2fa/setup', ['_csrf' => $wrong->csrf(), 'code' => $ctx->totp('admin')]);
        Assert::redirect('/recovery-codes', $res);
        $codes = $c->get('/recovery-codes');
        Assert::status(200, $codes);
        preg_match_all('/<code class="d-block p-2 bg-body-tertiary rounded text-center">([A-Z0-9-]{11})<\/code>/', $codes->body, $cm);
        Assert::same(10, count($cm[1]), 'ten recovery codes');
        $ctx->secrets['admin-recovery'] = implode(',', $cm[1]);
        Assert::redirect('/profile', $c->get('/recovery-codes'), 'codes are shown only once');
        Assert::status(200, $c->get('/'), 'dashboard after enrollment');
    },
    'secrets are stored encrypted or hashed, never in plain text' => function (TestContext $ctx): void {
        $row = $ctx->db->query("SELECT totp_secret_enc FROM users WHERE username = 'admin'")->fetch();
        Assert::true(str_starts_with((string) $row['totp_secret_enc'], 'v2:'), 'TOTP secret is encrypted');
        Assert::notContains($ctx->secrets['admin'], (string) $row['totp_secret_enc']);
        $hashes = $ctx->db->query("SELECT code_hash FROM user_recovery_codes")->fetchAll(PDO::FETCH_COLUMN);
        foreach (explode(',', $ctx->secrets['admin-recovery']) as $code) {
            Assert::true(!in_array(str_replace('-', '', $code), $hashes, true) && !in_array($code, $hashes, true), 'recovery code not stored in plain text');
        }
    },
    'sign-in with a TOTP code works and the same code cannot be replayed' => function (TestContext $ctx): void {
        $ctx->allowFreshCode('admin');
        $code = $ctx->totp('admin');
        $c1 = $ctx->client();
        $c1->submit('/login', '/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!']);
        Assert::redirect('/', $c1->submit('/login/2fa', '/login/2fa', ['code' => $code]));

        $c2 = $ctx->client();
        $c2->submit('/login', '/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!']);
        $replay = $c2->submit('/login/2fa', '/login/2fa', ['code' => $code]);
        Assert::status(422, $replay, 'replayed code must fail');
    },
    'a recovery code signs in once only' => function (TestContext $ctx): void {
        $code = explode(',', $ctx->secrets['admin-recovery'])[0];
        $c = $ctx->client();
        $c->submit('/login', '/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!']);
        Assert::redirect('/', $c->submit('/login/2fa', '/login/2fa', ['code' => strtolower($code)]), 'first use (case-insensitive)');
        Assert::contains('recovery code', $c->get('/')->body, 'warning shown after using a recovery code');

        $c2 = $ctx->client();
        $c2->submit('/login', '/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!']);
        Assert::status(422, $c2->submit('/login/2fa', '/login/2fa', ['code' => $code]), 'second use must fail');
    },
    'session ID changes at every sign-in step (no session fixation)' => function (TestContext $ctx): void {
        $c = $ctx->client();
        $c->get('/login');
        $before = $c->cookie('sentinel_session');
        $c->submit('/login', '/login', ['username' => 'admin', 'password' => 'Admin-Pass-0001!']);
        $pending = $c->cookie('sentinel_session');
        $ctx->allowFreshCode('admin');
        $c->submit('/login/2fa', '/login/2fa', ['code' => $ctx->totp('admin')]);
        $after = $c->cookie('sentinel_session');
        Assert::true($before !== $pending && $pending !== $after && $before !== $after, 'session ID must rotate');
    },
    'sign-out needs POST with CSRF and ends the session' => function (TestContext $ctx): void {
        $c = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::redirect('/', $c->get('/logout'), 'GET logout does not sign out (sent to the dashboard)');
        Assert::status(400, $c->post('/logout', []), 'logout without CSRF');
        Assert::status(200, $c->get('/'), 'still signed in after a forged logout');
        Assert::redirect('/login', $c->submit('/', '/logout', []));
        Assert::redirect('/login', $c->get('/'), 'signed out');
    },
    'password guessing is throttled per username' => function (TestContext $ctx): void {
        $ctx->createUser('throttle-target', 'viewer', 'Throttle-Pass-01!');
        $c = $ctx->client();
        for ($i = 0; $i < 5; $i++) {
            $c->submit('/login', '/login', ['username' => 'throttle-target', 'password' => 'guess-' . $i . '-xxxxxx']);
        }
        $res = $c->submit('/login', '/login', ['username' => 'throttle-target', 'password' => 'Throttle-Pass-01!']);
        Assert::status(422, $res);
        Assert::contains('Too many failed attempts', $res->body, 'even the right password is refused while throttled');
    },
    'look-alike spellings of a username share one throttle allowance' => function (TestContext $ctx): void {
        $ctx->createUser('lookalike', 'viewer', 'Lookalike-Pass-01!');
        $c = $ctx->client();
        // Accents, full-width letters, invisible and non-breaking characters: the database
        // collation could match these to "lookalike", so they must never reach it.
        // Malformed spellings are refused before the lookup, so they can't even be tried.
        foreach (["l\u{00F6}okalike", "\u{FF4C}ookalike", "look\u{200B}alike", "lookalike\u{00A0}"] as $v) {
            Assert::status(422, $c->submit('/login', '/login', ['username' => $v, 'password' => 'Lookalike-Pass-01!']), 'look-alike refused even with the right password');
        }
        // Case variants are the same account (user-ID bucket): 5 failures in total lock it.
        foreach (['LOOKALIKE', 'Lookalike', 'lookALIKE', 'LookAlike', 'lOOKALIKE'] as $i => $v) {
            $c->submit('/login', '/login', ['username' => $v, 'password' => 'guess-' . $i . '-xxxxxx']);
        }
        $ok = $c->submit('/login', '/login', ['username' => 'lookalike', 'password' => 'Lookalike-Pass-01!']);
        Assert::status(422, $ok, 'case variants count against the same account');
        Assert::contains('Too many failed attempts', $ok->body);
        $ctx->clearThrottle();
        $unicode = $c->submit('/login', '/login', ['username' => "l\u{00F6}okalike", 'password' => 'Lookalike-Pass-01!']);
        Assert::status(422, $unicode, 'a look-alike spelling never signs in, even with the right password');
        $audit = implode(' ', $ctx->db->query("SELECT username FROM audit_log WHERE action = 'auth.login_failed'")->fetchAll(PDO::FETCH_COLUMN));
        Assert::notContains("look\u{200B}alike", $audit, 'malformed usernames are not copied into the audit log');
    },
    'login timing does not reveal whether a username exists' => function (TestContext $ctx): void {
        $c = $ctx->client();
        $time = function (string $user) use ($c): float {
            $samples = [];
            for ($i = 0; $i < 3; $i++) {
                $t = microtime(true);
                $c->submit('/login', '/login', ['username' => $user, 'password' => 'wrong-password-' . $i]);
                $samples[] = microtime(true) - $t;
            }
            sort($samples);
            return $samples[1];
        };
        $known = $time('admin');
        $ctx->clearThrottle();
        $unknown = $time('no-such-user-xyz');
        $ctx->clearThrottle();
        // Before the fix, unknown users took about twice as long (two Argon2 operations).
        Assert::true($unknown < $known * 1.5 && $known < $unknown * 1.5, sprintf('median known %.0f ms vs unknown %.0f ms', $known * 1000, $unknown * 1000));
    },
    'wrong 2FA codes are throttled and end the pending sign-in' => function (TestContext $ctx): void {
        $ctx->createUser('otp-guesser', 'viewer', 'Otp-Guess-Pass-01!');
        $ctx->login('otp-guesser', 'Otp-Guess-Pass-01!'); // enrol
        $c = $ctx->client();
        $c->submit('/login', '/login', ['username' => 'otp-guesser', 'password' => 'Otp-Guess-Pass-01!']);
        $good = $ctx->totp('otp-guesser');
        $wrong = $good === '123456' ? '654321' : '123456';
        for ($i = 0; $i < 5; $i++) {
            Assert::status(422, $c->submit('/login/2fa', '/login/2fa', ['code' => $wrong]), 'attempt ' . ($i + 1));
        }
        Assert::redirect('/login', $c->submit('/login/2fa', '/login/2fa', ['code' => $good]), 'locked out after 5 wrong codes');
    },
    'disabled users cannot sign in and lose their session' => function (TestContext $ctx): void {
        $id = $ctx->createUser('soon-disabled', 'viewer', 'Disabled-Pass-01!');
        $c = $ctx->login('soon-disabled', 'Disabled-Pass-01!');
        Assert::status(200, $c->get('/'));
        $ctx->db->prepare('UPDATE users SET is_active = 0, session_version = session_version + 1 WHERE id = :id')->execute(['id' => $id]);
        Assert::redirect('/login', $c->get('/'), 'existing session ended');
        $res = $ctx->client()->submit('/login', '/login', ['username' => 'soon-disabled', 'password' => 'Disabled-Pass-01!']);
        Assert::status(422, $res);
        Assert::contains('Incorrect username or password.', $res->body, 'same generic message for disabled accounts');
    },
    'idle sessions expire after the idle timeout' => function (TestContext $ctx): void {
        // Simulated by back-dating the session file's "seen_at" value, without waiting 30 minutes.
        $c = $ctx->login('admin', 'Admin-Pass-0001!');
        $sid = $c->cookie('sentinel_session');
        $file = rtrim(session_save_path() ?: sys_get_temp_dir(), '/') . '/sess_' . $sid;
        Assert::true(is_file($file), 'session file found');
        $data = (string) file_get_contents($file);
        $data = preg_replace('/seen_at\|i:\d+;/', 'seen_at|i:' . (time() - Auth::IDLE_TIMEOUT - 1) . ';', $data);
        file_put_contents($file, $data);
        Assert::redirect('/login', $c->get('/'), 'idle session must expire');
    },
];
