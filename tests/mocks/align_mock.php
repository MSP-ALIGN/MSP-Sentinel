<?php

declare(strict_types=1);

/**
 * Mock MSP Align public API v1 for tests (included by feeds_router.php for /align/...). Never used in production.
 * Made-up clients and a small made-up framework; shapes follow MSP Align's src/Api/Resources.
 *
 * Key "msa_TESTKEY1_" + 32 x "a" has clients:read and compliance:read; "msa_NOSCOPE1_..." only clients:read.
 * Client 501 has one framework (id 7) with controls tagged from MSP Align's crosswalk vocabulary.
 */

$sub = substr($path, strlen('/align'));
$json = static function (int $status, $data): void {
    http_response_code($status);
    echo json_encode($data);
    exit;
};
$auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
$good = 'Bearer msa_TESTKEY1_' . str_repeat('a', 32);
$noScope = 'Bearer msa_NOSCOPE1_' . str_repeat('b', 32);
if ($auth !== $good && $auth !== $noScope) {
    $json(401, ['error' => ['status' => 401, 'message' => 'Invalid API key']]);
}
$page = static function (array $rows) use ($json): void {
    $p = max(1, (int) ($_GET['page'] ?? 1));
    $per = max(1, min(200, (int) ($_GET['per_page'] ?? 50)));
    $json(200, ['data' => array_slice($rows, ($p - 1) * $per, $per), 'meta' => ['page' => $p, 'per_page' => $per, 'total' => count($rows), 'has_more' => $p * $per < count($rows)]]);
};
if ($sub === '/api/v1/') {
    $json(200, ['data' => ['name' => 'MSP Sentinel', 'prefix' => 'TESTKEY1', 'scopes' => $auth === $good ? ['clients:read', 'compliance:read'] : ['clients:read'],
        'client_ids' => null, 'api_version' => 'v1', 'app_version' => '2.41.0']]);
}
if ($sub === '/api/v1/clients') {
    $page([['id' => 500, 'name' => 'Other Example Co'], ['id' => 501, 'name' => 'Harbour Align Example'], ['id' => 502, 'name' => 'Quay Example Inc']]);
}
if ($auth === $noScope) {
    $json(403, ['error' => ['status' => 403, 'message' => 'Missing scope compliance:read']]);
}
if ($sub === '/api/v1/clients/501/compliance') {
    $page([['client_id' => 501, 'framework_id' => 7, 'framework' => 'CIS Controls v8 IG1 (example)', 'slug' => 'cis-v8-ig1', 'score' => ['percent' => 42],
            'url' => 'https://align.msp.example/clients/501/compliance/7']]);
}
if ($sub === '/api/v1/clients/501/compliance/7/controls') {
    $page([
        ['id' => 71, 'ref' => '4.4', 'section' => 'Secure configuration', 'title' => 'Firewall on servers and at the boundary', 'crosswalk_tags' => ['net_firewall', 'cfg_ports_services'], 'status' => 'met'],
        ['id' => 72, 'ref' => '9.5', 'section' => 'Email', 'title' => 'Implement DMARC', 'crosswalk_tags' => ['email_auth'], 'status' => 'not_assessed'],
        ['id' => 73, 'ref' => '10.1', 'section' => 'Malware defenses', 'title' => 'Deploy anti-malware', 'crosswalk_tags' => ['ep_malware', 'ep_edr'], 'status' => 'partial'],
        ['id' => 74, 'ref' => '14.1', 'section' => 'Awareness', 'title' => 'Security awareness programme', 'crosswalk_tags' => ['awareness_training'], 'status' => 'met'],
        ['id' => 75, 'ref' => '3.11', 'section' => 'Data protection', 'title' => 'Encrypt data in transit <script>x</script>', 'crosswalk_tags' => ['net_encrypt_transit'], 'status' => 'not_met'],
    ]);
}
$json(404, ['error' => ['status' => 404, 'message' => 'Not found']]);
