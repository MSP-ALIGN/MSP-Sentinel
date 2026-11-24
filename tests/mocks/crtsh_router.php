<?php

declare(strict_types=1);

/**
 * Fake crt.sh for tests (router script for PHP's built-in server on 127.0.0.1).
 * Never used in production.
 *
 * GET /?q=%.<domain>&output=json returns tests/fixtures/crtsh/<domain>.json.
 * Special domains: crtsh-down.example -> HTTP 500, crtsh-huge.example -> 11 MB body,
 * crtsh-html.example -> an HTML page (not JSON). Unknown domains -> [] (no certificates).
 */

$q = (string) ($_GET['q'] ?? '');
$domain = str_starts_with($q, '%.') ? substr($q, 2) : $q;
if (($_GET['output'] ?? '') !== 'json' || !preg_match('/^[a-z0-9.-]+$/', $domain)) {
    http_response_code(400);
    exit;
}
file_put_contents(sys_get_temp_dir() . '/crtsh-mock-' . getmypid() . '.log', $domain . "\n", FILE_APPEND);
switch ($domain) {
    case 'crtsh-down.example':
        http_response_code(500);
        echo 'Internal error';
        exit;
    case 'crtsh-huge.example':
        header('Content-Type: application/json');
        echo '[';
        $chunk = str_repeat('{"name_value":"x.crtsh-huge.example"},', 1000);
        for ($i = 0; $i < 300; $i++) {
            echo $chunk;
        }
        echo '{}]';
        exit;
    case 'crtsh-html.example':
        header('Content-Type: text/html');
        echo '<html><body>Service unavailable</body></html>';
        exit;
}
$file = __DIR__ . '/../fixtures/crtsh/' . $domain . '.json';
header('Content-Type: application/json');
echo is_file($file) ? file_get_contents($file) : '[]';
