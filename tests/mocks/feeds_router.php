<?php

declare(strict_types=1);

/**
 * Mock threat feeds for tests (router for PHP's built-in server on 127.0.0.1).
 * Never used in production. Made-up CVE IDs only.
 *
 * - GET /rest/json/cves/2.0?virtualMatchString=...  NVD CVE API 2.0 (fixtures by match string;
 *   "cpe:2.3:a:example:bigproduct:1.0" generates 2500 results to exercise pagination)
 * - GET /kev.json, /kev-broken.json                 CISA KEV catalog / an HTML error page
 * - GET /data/v1/epss?cve=A,B                       FIRST EPSS
 * Each request is logged (path, query, whether an apiKey header was present) to $FEEDS_LOG.
 */

$path = (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);
$log = getenv('FEEDS_LOG');
if (is_string($log) && $log !== '') {
    file_put_contents($log, json_encode(['path' => $path, 'query' => $_GET, 'apikey_header' => isset($_SERVER['HTTP_APIKEY'])]) . "\n", FILE_APPEND);
}
$fixtures = __DIR__ . '/../fixtures/feeds/';
header('Content-Type: application/json');
if (str_starts_with($path, '/ninja/')) {
    require __DIR__ . '/ninjaone_mock.php'; // mock NinjaOne Public API (exits)
}

if ($path === '/rest/json/cves/2.0') {
    $match = (string) ($_GET['virtualMatchString'] ?? '');
    $start = (int) ($_GET['startIndex'] ?? 0);
    if ($match === 'cpe:2.3:a:example:bigproduct:1.0') {
        $items = [];
        for ($i = $start; $i < min($start + 2000, 2500); $i++) {
            $items[] = ['cve' => ['id' => sprintf('CVE-2099-%05d', 10000 + $i), 'descriptions' => [['lang' => 'en', 'value' => 'Bulk test entry']], 'metrics' => [],
                'configurations' => [['nodes' => [['cpeMatch' => [['vulnerable' => true, 'criteria' => 'cpe:2.3:a:example:bigproduct:1.0:*:*:*:*:*:*:*']]]]]]]];
        }
        echo json_encode(['totalResults' => 2500, 'startIndex' => $start, 'vulnerabilities' => $items]);
        exit;
    }
    if ($match === 'cpe:2.3:a:example:ratelimited:1.0') {
        http_response_code(429);
        header('Retry-After: 120');
        echo '{"message":"slow down"}';
        exit;
    }
    $map = ['cpe:2.3:a:openbsd:openssh:8.9p1' => 'nvd_openssh.json', 'cpe:2.3:a:openbsd:openssh:8.9:p1' => 'nvd_openssh_split.json',
            'cpe:2.3:a:example:webserver' => 'nvd_webserver.json', 'cpe:2.3:a:jquery:jquery:1.12.4' => 'nvd_jquery.json',
            'cpe:2.3:a:google:chrome:120.0.6099.130' => 'nvd_chrome.json',
            'cpe:2.3:a:wordpress:wordpress:5.0.3' => 'nvd_wordpress.json'];
    echo isset($map[$match]) ? file_get_contents($fixtures . $map[$match]) : json_encode(['totalResults' => 0, 'vulnerabilities' => []]);
    exit;
}
if ($path === '/webhook') {
    // Fake webhook receiver: record the posted JSON body.
    $log = getenv('FEEDS_LOG');
    if (is_string($log) && $log !== '') {
        file_put_contents(dirname($log) . '/webhook-posts.log', file_get_contents('php://input') . "\n", FILE_APPEND);
    }
    echo '{"ok":true}';
    exit;
}
if ($path === '/releases/latest') {
    // Fake releases feed for the update check.
    header('Content-Type: application/json');
    echo json_encode(['tag_name' => 'v9.9.9', 'prerelease' => false, 'draft' => false, 'html_url' => 'javascript:alert(1)']);
    exit;
}
if (preg_match('#^/compare/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/([0-9a-f]{40})\.\.\.([A-Za-z0-9._%-]+)$#', $path, $m) === 1) {
    // Fake GitHub compare API: the branch is 3 commits ahead of any installed commit, except one marked current.
    header('Content-Type: application/json');
    $current = $m[2] === str_repeat('c', 40);
    echo json_encode(['status' => $current ? 'identical' : 'ahead', 'ahead_by' => $current ? 0 : 3, 'behind_by' => 0,
        'commits' => $current ? [] : [['sha' => str_repeat('1', 40)], ['sha' => str_repeat('2', 40)], ['sha' => 'abcdef0123456789abcdef0123456789abcdef01', 'html_url' => 'javascript:alert(1)']]]);
    exit;
}
if ($path === '/releases/pre') {
    header('Content-Type: application/json');
    echo json_encode(['tag_name' => 'v10.0.0', 'prerelease' => true]);
    exit;
}
if ($path === '/events') {
    // Fake event receiver: record the signature, event header and exact body (one JSON line each).
    $log = getenv('FEEDS_LOG');
    if (is_string($log) && $log !== '') {
        file_put_contents(dirname($log) . '/event-posts.log', json_encode([
            'event' => $_SERVER['HTTP_X_SENTINEL_EVENT'] ?? '', 'signature' => $_SERVER['HTTP_X_SENTINEL_SIGNATURE'] ?? '', 'body' => file_get_contents('php://input'),
        ]) . "\n", FILE_APPEND);
    }
    echo '{"ok":true}';
    exit;
}
if ($path === '/kev.json') {
    echo file_get_contents($fixtures . 'kev.json');
    exit;
}
if ($path === '/kev-broken.json') {
    http_response_code(503);
    header('Content-Type: text/html');
    echo '<html>Maintenance</html>';
    exit;
}
if ($path === '/data/v1/epss') {
    $data = [];
    foreach (explode(',', (string) ($_GET['cve'] ?? '')) as $id) {
        if (preg_match('/^CVE-\d{4}-\d+$/', $id)) {
            $n = (int) substr($id, -2);
            $data[] = ['cve' => $id, 'epss' => sprintf('%.5f', $n === 1 ? 0.97123 : 0.0123), 'percentile' => sprintf('%.5f', $n === 1 ? 0.99950 : 0.4), 'date' => '2099-03-05'];
        }
    }
    echo json_encode(['status' => 'OK', 'data' => $data]);
    exit;
}
http_response_code(404);
echo '{}';
