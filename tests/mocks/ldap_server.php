<?php

declare(strict_types=1);

/**
 * Mock Active Directory domain controller for tests, on 127.0.0.1 only. Never used in production.
 *
 * Usage: php tests/mocks/ldap_server.php <port> <ldaps|plain> <pem-or-"-"> <directory.json> <log-file>
 *
 * - ldaps: TLS from the first byte (the throwaway test certificate). Bind succeeds only for the account and password in
 *   the fixture; searches need a successful bind (as AD), and support base/subtree scope, AND / equality / presence
 *   filters (case-insensitive) and the paged-results control (the cookie is the offset).
 * - plain: the signing probe only. Answers every bind with "stronger authentication required" (8) when the file
 *   ldap-signing.txt next to the log says "required", else "invalid credentials" (49).
 * Every bind is logged as JSON: the bind name, the port mode and a SHA-256 of the password (never the password), so
 * tests can prove the real password went only over LDAPS and only after the certificate was trusted.
 *
 * Times in the fixture can be written "@days:N" (N days ago, as a Windows FILETIME), so the data never ages; SIDs as
 * "@sid:S-1-5-21-..." (stored binary, as AD does).
 * Made-up data only.
 */

require dirname(__DIR__, 2) . '/src/Directory/BerException.php';
require dirname(__DIR__, 2) . '/src/Directory/Ber.php';

use Sentinel\Directory\Ber;

if (PHP_SAPI !== 'cli' || $argc < 6) {
    exit(2);
}
[$script, $port, $mode, $pem, $fixtureFile, $log] = $argv;
$fixture = json_decode((string) file_get_contents($fixtureFile), true);
$filetime = static fn (int $unix): string => (string) (($unix + 11644473600) * 10000000);
// "S-1-5-21-a-b-c[-rid]" as the binary SID AD stores (objectSid).
$sid = static function (string $text): string {
    $p = explode('-', $text);
    $subs = array_slice($p, 3);
    return chr((int) $p[1]) . chr(count($subs)) . substr(pack('J', (int) $p[2]), 2) . implode('', array_map(static fn (string $s): string => pack('V', (int) $s), $subs));
};
$entries = [];
foreach ($fixture['entries'] as $e) {
    $attrs = [];
    foreach ($e['attrs'] as $k => $vals) {
        $attrs[strtolower($k)] = ['name' => $k, 'values' => array_map(static fn ($v): string => match (true) {
            is_string($v) && str_starts_with($v, '@days:') => $filetime(time() - (int) substr($v, 6) * 86400),
            is_string($v) && str_starts_with($v, '@sid:') => $sid(substr($v, 5)),
            default => (string) $v,
        }, (array) $vals)];
    }
    $entries[] = ['dn' => $e['dn'], 'attrs' => $attrs];
}
$ctx = stream_context_create($mode === 'ldaps' ? ['ssl' => ['local_cert' => $pem, 'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER]] : []);
$server = stream_socket_server('tcp://127.0.0.1:' . $port, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if ($server === false) {
    fwrite(STDERR, "mock ldap: cannot bind {$port}: {$errstr}\n");
    exit(1);
}

/** Read one LDAP message (or null at the end). */
$readMessage = static function ($conn): ?string {
    $head = (string) fread($conn, 2);
    if (strlen($head) < 2) {
        return null;
    }
    $extra = ord($head[1]) & 0x80 ? ord($head[1]) & 0x7F : 0;
    if ($extra > 0) {
        $head .= (string) fread($conn, $extra);
    }
    [$len] = Ber::readLength($head, 1);
    $body = '';
    while (strlen($body) < $len) {
        $chunk = fread($conn, $len - strlen($body));
        if ($chunk === false || $chunk === '') {
            return null;
        }
        $body .= $chunk;
    }
    return $head . $body;
};
$result = static fn (int $id, int $op, int $code, string $controls = ''): string => Ber::seq(Ber::int($id), Ber::tlv($op, Ber::int($code, Ber::ENUMERATED) . Ber::str('') . Ber::str('')) . $controls);

/** Does an entry match a filter TLV? */
$matches = static function (array $entry, array $f) use (&$matches): bool {
    if ($f['tag'] === 0xA0) {
        foreach (Ber::children($f['value']) as $c) {
            if (!$matches($entry, $c)) {
                return false;
            }
        }
        return true;
    }
    if ($f['tag'] === 0x87) {
        return isset($entry['attrs'][strtolower($f['value'])]);
    }
    if ($f['tag'] === 0xA3) {
        [$a, $v] = Ber::children($f['value']);
        foreach ($entry['attrs'][strtolower($a['value'])]['values'] ?? [] as $have) {
            if (strcasecmp($have, $v['value']) === 0) {
                return true;
            }
        }
        return false;
    }
    return false;
};

while (true) {
    $conn = @stream_socket_accept($server, 60);
    if ($conn === false) {
        continue;
    }
    stream_set_timeout($conn, 5);
    if ($mode === 'ldaps' && @stream_socket_enable_crypto($conn, true, STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER) !== true) {
        fclose($conn);
        continue;
    }
    $bound = false;
    while (($raw = $readMessage($conn)) !== null) {
        try {
            $parts = Ber::children(Ber::read($raw)['value']);
            $id = Ber::toInt($parts[0]['value']);
            $op = $parts[1];
            if ($op['tag'] === 0x42) {
                break; // unbind
            }
            if ($op['tag'] === 0x60) {
                $b = Ber::children($op['value']);
                $name = $b[1]['value'];
                $password = $b[2]['value'];
                file_put_contents($log, json_encode(['mode' => $mode, 'name' => $name, 'pw_sha256' => hash('sha256', $password)]) . "\n", FILE_APPEND);
                if ($mode === 'plain') {
                    $required = trim((string) @file_get_contents(dirname($log) . '/ldap-signing.txt')) === 'required';
                    fwrite($conn, $result($id, 0x61, $required ? 8 : 49));
                    continue;
                }
                $bound = strcasecmp($name, $fixture['account']['name']) === 0 && hash_equals($fixture['account']['password'], $password);
                fwrite($conn, $result($id, 0x61, $bound ? 0 : 49));
                continue;
            }
            if ($op['tag'] === 0x63) {
                if (!$bound) {
                    fwrite($conn, $result($id, 0x65, 1)); // operationsError: AD needs a bind first
                    continue;
                }
                $s = Ber::children($op['value']);
                $base = strtolower($s[0]['value']);
                $scope = Ber::toInt($s[1]['value']);
                $filter = $s[6];
                $wanted = array_map(static fn (array $a): string => strtolower($a['value']), Ber::children($s[7]['value']));
                $size = 1000;
                $offset = 0;
                foreach (isset($parts[2]) ? Ber::children($parts[2]['value']) : [] as $c) {
                    $cp = Ber::children($c['value']);
                    if ($cp[0]['value'] === '1.2.840.113556.1.4.319') {
                        $inner = Ber::children(Ber::read(end($cp)['value'])['value']);
                        $size = max(1, Ber::toInt($inner[0]['value']));
                        $offset = $inner[1]['value'] === '' ? 0 : (int) $inner[1]['value'];
                    }
                }
                $hits = array_values(array_filter($entries, static function (array $e) use ($base, $scope, $filter, $matches): bool {
                    $dn = strtolower($e['dn']);
                    $inScope = $scope === 0 ? $dn === $base : ($dn === $base || str_ends_with($dn, ',' . $base));
                    return $inScope && $matches($e, $filter);
                }));
                foreach (array_slice($hits, $offset, $size) as $e) {
                    $attrs = '';
                    foreach ($e['attrs'] as $lower => $a) {
                        if (in_array($lower, $wanted, true)) {
                            $attrs .= Ber::seq(Ber::str($a['name']), Ber::tlv(Ber::SET, implode('', array_map(static fn (string $v): string => Ber::str($v), $a['values']))));
                        }
                    }
                    fwrite($conn, Ber::seq(Ber::int($id), Ber::tlv(0x64, Ber::str($e['dn']) . Ber::seq($attrs))));
                }
                $next = $offset + $size < count($hits) ? (string) ($offset + $size) : '';
                $control = Ber::tlv(0xA0, Ber::seq(Ber::str('1.2.840.113556.1.4.319'), Ber::str(Ber::seq(Ber::int(0), Ber::str($next)))));
                fwrite($conn, $result($id, 0x65, 0, $control));
                continue;
            }
            fwrite($conn, $result($id, 0x65, 53)); // unwillingToPerform: nothing else is supported (nothing writes)
        } catch (\Throwable $ex) {
            fwrite(STDERR, 'mock ldap: ' . $ex->getMessage() . "\n");
            break;
        }
    }
    fclose($conn);
}
