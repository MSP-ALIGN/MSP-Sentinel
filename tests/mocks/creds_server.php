<?php

declare(strict_types=1);

/**
 * Fake login servers for the default-credential tests (127.0.0.1 only; never used in production).
 *
 * Usage: php tests/mocks/creds_server.php <port> <mode> <user> <password> <attempt-log>
 *
 * Modes: ftp, ftp-locked (421 after the first failed login), http-basic, mysql-native, mysql-sha2, pg-md5,
 * pg-scram, redis-open, redis-auth, mongo-open, mongo-auth, es-open, memcached-open.
 * Exactly one account (<user>/<password>) is accepted. Every login attempt is logged as
 * "<unix time with ms> <mode> <user>" (never the password) so tests can count attempts and check the spacing.
 */

if (PHP_SAPI !== 'cli' || $argc < 6) {
    exit(2);
}
[, $port, $mode, $goodUser, $goodPass, $log] = $argv;
$srv = stream_socket_server('tcp://127.0.0.1:' . (int) $port, $errno, $errstr);
if ($srv === false) {
    fwrite(STDERR, "creds mock: cannot bind {$port}: {$errstr}\n");
    exit(1);
}
$attempt = static function (string $user) use ($log, $mode): void {
    file_put_contents($log, sprintf('%.3f', microtime(true)) . ' ' . $mode . ' ' . $user . "\n", FILE_APPEND);
};
$failures = 0;

while (true) {
    $c = @stream_socket_accept($srv, 60);
    if ($c === false) {
        continue;
    }
    stream_set_timeout($c, 5);
    $readN = static function (int $n) use ($c): string {
        $b = '';
        while (strlen($b) < $n && !feof($c)) {
            $x = fread($c, $n - strlen($b));
            if ($x === false || $x === '') {
                break;
            }
            $b .= $x;
        }
        return $b;
    };
    switch ($mode) {
        case 'ftp':
        case 'ftp-locked':
            fwrite($c, "220-Example FTP\r\n220 ready\r\n");
            $user = '';
            while (($l = fgets($c, 1024)) !== false) {
                $l = rtrim($l, "\r\n");
                if (str_starts_with($l, 'USER ')) {
                    $user = substr($l, 5);
                    fwrite($c, $mode === 'ftp-locked' && $failures > 0 ? "421 Too many failed logins\r\n" : "331 Password required\r\n");
                } elseif (str_starts_with($l, 'PASS ')) {
                    $attempt($user);
                    $ok = $user === $goodUser && substr($l, 5) === $goodPass;
                    $failures += $ok ? 0 : 1;
                    fwrite($c, $ok ? "230 Logged in\r\n" : "530 Login incorrect\r\n");
                } elseif ($l === 'QUIT') {
                    fwrite($c, "221 Bye\r\n");
                    break;
                }
            }
            break;
        case 'http-basic':
        case 'es-open':
            $req = '';
            while (($l = fgets($c, 4096)) !== false && rtrim($l) !== '') {
                $req .= $l;
            }
            if ($mode === 'es-open') {
                $body = '{"name":"node-1","cluster_name":"example-cluster","version":{"number":"7.17.0"},"tagline":"You Know, for Search"}';
                fwrite($c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
                break;
            }
            if (preg_match('/^Authorization: Basic (\S+)/mi', $req, $m) === 1) {
                $pair = (string) base64_decode($m[1]);
                [$u, $p] = array_pad(explode(':', $pair, 2), 2, '');
                $attempt($u);
                if ($u === $goodUser && $p === $goodPass) {
                    fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n<html>Welcome</html>\n");
                    break;
                }
            }
            fwrite($c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Example Camera\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            break;
        case 'mysql-native':
        case 'mysql-sha2':
            $plugin = $mode === 'mysql-native' ? 'mysql_native_password' : 'caching_sha2_password';
            $salt = substr(strtr(base64_encode(random_bytes(30)), '+/=', 'abc'), 0, 20);
            $hs = "\x0a" . "8.0.0-example\0" . pack('V', 7) . substr($salt, 0, 8) . "\0" . pack('v', 0xffff) . chr(45) . pack('v', 2) . pack('v', 0xffff)
                . chr(21) . str_repeat("\0", 10) . substr($salt, 8) . "\0" . $plugin . "\0";
            fwrite($c, substr(pack('V', strlen($hs)), 0, 3) . "\x00" . $hs);
            $h = $readN(4);
            if (strlen($h) !== 4) {
                break;
            }
            $body = $readN(unpack('V', substr($h, 0, 3) . "\0")[1]);
            $o = 32;
            $ue = strpos($body, "\0", $o);
            $user = substr($body, $o, $ue - $o);
            $alen = ord($body[$ue + 1]);
            $auth = substr($body, $ue + 2, $alen);
            $attempt($user);
            $expected = $goodPass === '' ? '' : ($plugin === 'caching_sha2_password'
                ? hash('sha256', $goodPass, true) ^ hash('sha256', hash('sha256', hash('sha256', $goodPass, true), true) . $salt, true)
                : sha1($goodPass, true) ^ sha1($salt . sha1(sha1($goodPass, true), true), true));
            $send = static fn (int $seq, string $b) => fwrite($c, substr(pack('V', strlen($b)), 0, 3) . chr($seq) . $b);
            if ($user === $goodUser && hash_equals($expected, $auth)) {
                if ($plugin === 'caching_sha2_password') {
                    $send(2, "\x01\x03");
                    $send(3, "\x00\x00\x00\x02\x00\x00\x00");
                } else {
                    $send(2, "\x00\x00\x00\x02\x00\x00\x00");
                }
            } else {
                $send(2, "\xff" . pack('v', 1045) . '#28000Access denied for user');
            }
            usleep(100000);
            break;
        case 'pg-md5':
        case 'pg-scram':
            $h = $readN(4);
            if (strlen($h) !== 4) {
                break;
            }
            $start = $readN(unpack('N', $h)[1] - 4);
            $parts = explode("\0", substr($start, 4));
            $params = [];
            for ($i = 0; $i + 1 < count($parts); $i += 2) {
                $params[$parts[$i]] = $parts[$i + 1];
            }
            $user = $params['user'] ?? '';
            $msg = static fn (string $t, string $b) => fwrite($c, $t . pack('N', strlen($b) + 4) . $b);
            $readMsg = static function () use ($readN): array {
                $h = $readN(5);
                return strlen($h) === 5 ? [$h[0], $readN(unpack('N', substr($h, 1))[1] - 4)] : ['', ''];
            };
            $deny = static fn () => $msg('E', "SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed for user \"{$user}\"\0\0");
            if ($mode === 'pg-md5') {
                $salt = random_bytes(4);
                $msg('R', pack('N', 5) . $salt);
                [, $b] = $readMsg();
                $attempt($user);
                $ok = $user === $goodUser && rtrim($b, "\0") === 'md5' . md5(md5($goodPass . $goodUser) . $salt);
            } else {
                $msg('R', pack('N', 10) . "SCRAM-SHA-256\0\0");
                [, $b] = $readMsg();
                $me = strpos($b, "\0");
                $first = substr($b, $me + 5);
                $bare = substr($first, 3);
                preg_match('/r=([^,]+)/', $bare, $m);
                $nonce = $m[1] . 'server';
                $salt = random_bytes(16);
                $serverFirst = 'r=' . $nonce . ',s=' . base64_encode($salt) . ',i=4096';
                $msg('R', pack('N', 11) . $serverFirst);
                [, $final] = $readMsg();
                $attempt($user);
                $salted = hash_pbkdf2('sha256', $goodPass, $salt, 4096, 32, true);
                $clientKey = hash_hmac('sha256', 'Client Key', $salted, true);
                $without = substr($final, 0, (int) strpos($final, ',p='));
                $proof = base64_decode(substr($final, (int) strpos($final, ',p=') + 3));
                $sig = hash_hmac('sha256', $bare . ',' . $serverFirst . ',' . $without, hash('sha256', $clientKey, true), true);
                $ok = $user === $goodUser && is_string($proof) && hash_equals($clientKey ^ $sig, $proof);
                if ($ok) {
                    $msg('R', pack('N', 12) . 'v=' . base64_encode(hash_hmac('sha256', 'x', 'y', true)));
                }
            }
            $ok ? $msg('R', pack('N', 0)) : $deny();
            usleep(100000);
            break;
        case 'redis-open':
        case 'redis-auth':
            fgets($c, 1024);
            fwrite($c, $mode === 'redis-open' ? "+PONG\r\n" : "-NOAUTH Authentication required.\r\n");
            break;
        case 'memcached-open':
            fgets($c, 1024);
            fwrite($c, "VERSION 1.6.21\r\n");
            break;
        case 'mongo-open':
        case 'mongo-auth':
            $h = $readN(16);
            if (strlen($h) !== 16) {
                break;
            }
            $readN(unpack('V', substr($h, 0, 4))[1] - 16);
            $doc = $mode === 'mongo-open'
                ? "\x04databases\0" . pack('V', 5) . "\0" . "\x01ok\0" . pack('e', 1.0)
                : "\x01ok\0" . pack('e', 0.0) . "\x10code\0" . pack('V', 13) . "\x02errmsg\0" . pack('V', 14) . "Unauthorized!\0";
            $doc = pack('V', strlen($doc) + 5) . $doc . "\0";
            $body = pack('V', 0) . "\0" . $doc;
            fwrite($c, pack('VVVV', 16 + strlen($body), 1, unpack('V', substr($h, 4, 4))[1], 2013) . $body);
            break;
    }
    fclose($c);
}
