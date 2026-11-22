<?php

declare(strict_types=1);

/**
 * Fake SMTP server for tests (127.0.0.1 only; never used in production).
 *
 * Usage: php tests/mocks/smtp_server.php <port> <mode: plain|starttls> <spool-dir> [pem]
 * Accepts AUTH PLAIN/LOGIN with any credentials, records each message as a JSON
 * file in the spool dir ({from, to, auth_user, tls, data}). Passwords are not recorded.
 */

[$script, $port, $mode, $spool] = $argv;
$pem = $argv[4] ?? null;
$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "mock smtp: cannot bind: {$errstr}\n");
    exit(1);
}
$send = static function ($c, string $line): void {
    fwrite($c, $line . "\r\n");
};
while (true) {
    $c = @stream_socket_accept($server, 60);
    if ($c === false) {
        continue;
    }
    stream_set_timeout($c, 5);
    $send($c, '220 mock.example ESMTP test');
    $msg = ['from' => '', 'to' => [], 'auth_user' => '', 'tls' => false, 'data' => ''];
    $authStep = null;
    while (($line = fgets($c, 2048)) !== false) {
        $line = rtrim($line, "\r\n");
        if ($authStep === 'login-user') {
            $msg['auth_user'] = (string) base64_decode($line);
            $authStep = 'login-pass';
            $send($c, '334 UGFzc3dvcmQ6');
            continue;
        }
        if ($authStep === 'login-pass') {
            $authStep = null;
            $send($c, '235 ok');
            continue;
        }
        $cmd = strtoupper(substr($line, 0, 4));
        if ($cmd === 'EHLO' || $cmd === 'HELO') {
            $caps = ['250-mock.example', '250-AUTH PLAIN LOGIN'];
            if ($mode === 'starttls' && !$msg['tls']) {
                $caps[] = '250-STARTTLS';
            }
            $caps[] = '250 8BITMIME';
            foreach ($caps as $cap) {
                $send($c, $cap);
            }
        } elseif ($cmd === 'STAR' && $mode === 'starttls') {
            $send($c, '220 go ahead');
            stream_context_set_option($c, 'ssl', 'local_cert', $pem);
            if (@stream_socket_enable_crypto($c, true, STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER) !== true) {
                break;
            }
            $msg['tls'] = true;
        } elseif (str_starts_with(strtoupper($line), 'AUTH PLAIN ')) {
            $parts = explode("\0", (string) base64_decode(substr($line, 11)));
            $msg['auth_user'] = $parts[1] ?? '';
            $send($c, '235 ok');
        } elseif (strtoupper($line) === 'AUTH LOGIN') {
            $authStep = 'login-user';
            $send($c, '334 VXNlcm5hbWU6');
        } elseif (str_starts_with(strtoupper($line), 'MAIL FROM:')) {
            $msg['from'] = trim(substr($line, 10), '<> ');
            $send($c, '250 ok');
        } elseif (str_starts_with(strtoupper($line), 'RCPT TO:')) {
            $msg['to'][] = trim(substr($line, 8), '<> ');
            $send($c, '250 ok');
        } elseif ($cmd === 'DATA') {
            $send($c, '354 end with .');
            $data = '';
            while (($l = fgets($c, 4096)) !== false && rtrim($l, "\r\n") !== '.') {
                $data .= $l;
            }
            $msg['data'] = $data;
            file_put_contents($spool . '/' . microtime(true) . '-' . bin2hex(random_bytes(3)) . '.json', json_encode($msg));
            $send($c, '250 queued');
            $msg = ['from' => '', 'to' => [], 'auth_user' => $msg['auth_user'], 'tls' => $msg['tls'], 'data' => ''];
        } elseif ($cmd === 'QUIT') {
            $send($c, '221 bye');
            break;
        } else {
            $send($c, '250 ok');
        }
    }
    fclose($c);
}
