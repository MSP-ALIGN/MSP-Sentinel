<?php

declare(strict_types=1);

/**
 * Mock TLS/HTTP server for tests, on 127.0.0.1 only. Never used in production.
 *
 * Usage: php tests/mocks/tls_server.php <port> <mode> <pem-or-"-"> <html-file>
 *   mode: modern (TLS 1.2+), legacy (also TLS 1.0/1.1, weak keys allowed), plain (HTTP, no TLS)
 * Answers each connection with a fixed HTML page, then closes it. If <html-file>
 * ends in .json it is a route map instead: {"/path": {"status": 200, "headers":
 * {"Name": "value" or [values]}, "body": "...", "body_b64": "..."}, "*": fallback}
 * (unknown paths get 404, or the "*" route, e.g. a soft-404 page answering 200).
 */

if (PHP_SAPI !== 'cli' || $argc < 5) {
    exit(2);
}
[$script, $port, $mode, $pem, $htmlFile] = $argv;
$html = (string) file_get_contents($htmlFile);
$routes = str_ends_with($htmlFile, '.json') ? json_decode($html, true) : null;
$methods = [
    'modern' => STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
    'legacy' => STREAM_CRYPTO_METHOD_TLSv1_0_SERVER | STREAM_CRYPTO_METHOD_TLSv1_1_SERVER | STREAM_CRYPTO_METHOD_TLSv1_2_SERVER,
];
$ctx = stream_context_create($mode === 'plain' ? [] : ['ssl' => ['local_cert' => $pem, 'ciphers' => 'DEFAULT@SECLEVEL=0', 'crypto_method' => $methods[$mode]]]);
$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if ($server === false) {
    fwrite(STDERR, "mock tls: cannot bind {$port}: {$errstr}\n");
    exit(1);
}
while (true) {
    $conn = @stream_socket_accept($server, 60);
    if ($conn === false) {
        continue;
    }
    stream_set_timeout($conn, 3);
    if ($mode !== 'plain' && @stream_socket_enable_crypto($conn, true, $methods[$mode]) !== true) {
        fclose($conn); // e.g. a TLS 1.0 probe against a modern server
        continue;
    }
    $request = '';
    while (!str_contains($request, "\r\n\r\n") && strlen($request) < 8192 && !feof($conn)) {
        $chunk = fread($conn, 1024);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $request .= $chunk;
    }
    if ($request !== '' && is_array($routes)) {
        $path = preg_match('#^[A-Z]+ (\S+) HTTP#', $request, $rm) ? (string) parse_url($rm[1], PHP_URL_PATH) : '/';
        $route = $routes[$path] ?? ($routes['*'] ?? ['status' => 404, 'body' => 'Not found']);
        $body = isset($route['body_b64']) ? base64_decode($route['body_b64']) : (string) ($route['body'] ?? '');
        $head = 'HTTP/1.1 ' . (int) ($route['status'] ?? 200) . " X\r\nServer: ExampleServer/1.0\r\n";
        $headers = ($route['headers'] ?? []) + ['Content-Type' => 'text/html'];
        foreach ($headers as $name => $values) {
            foreach ((array) $values as $v) {
                $head .= $name . ': ' . $v . "\r\n";
            }
        }
        @fwrite($conn, $head . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
    } elseif ($request !== '') {
        @fwrite($conn, "HTTP/1.1 200 OK\r\nServer: ExampleServer/1.0\r\nContent-Type: text/html\r\nContent-Length: " . strlen($html) . "\r\nConnection: close\r\n\r\n" . $html);
    }
    fclose($conn);
}
