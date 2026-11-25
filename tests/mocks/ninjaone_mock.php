<?php

declare(strict_types=1);

/**
 * Mock NinjaOne Public API 2.0 for tests (included by feeds_router.php for /ninja/...). Never used in
 * production. Made-up organisations, devices and software only; shapes follow NinjaOne's OpenAPI description.
 *
 * - POST /ninja/ws/oauth/token: client credentials; client_id "test-client", secret "test-secret-value", scope
 *   "monitoring" (any other secret answers 400 invalid_client).
 * - GET /ninja/v2/organizations, /ninja/v2/devices-detailed?df=org = N (Bearer token required)
 * - GET /ninja/v2/queries/{software,os-patches,antivirus-status,volumes}: cursor paging honouring pageSize
 *   (so a small pageSize exercises the cursor), filtered by df.
 * Organisation 900 answers HTTP 500 for its software report (to test that a failed page fails the sync).
 */

$sub = substr($path, strlen('/ninja'));
$json = static function (int $status, $data): void {
    http_response_code($status);
    echo json_encode($data);
    exit;
};
if ($sub === '/ws/oauth/token') {
    if (($_POST['grant_type'] ?? '') !== 'client_credentials' || ($_POST['client_id'] ?? '') !== 'test-client' || ($_POST['client_secret'] ?? '') !== 'test-secret-value'
        || ($_POST['scope'] ?? '') !== 'monitoring') {
        $json(400, ['error' => 'invalid_client', 'error_description' => 'The client credentials are not valid']);
    }
    $json(200, ['access_token' => 'mock-token-123', 'expires_in' => 3600, 'token_type' => 'bearer']);
}
if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer mock-token-123') {
    $json(401, ['error' => 'unauthorized']);
}
$orgFrom = static function (): ?int {
    return preg_match('/^org = (\d+)$/', (string) ($_GET['df'] ?? ''), $m) === 1 ? (int) $m[1] : null;
};
$devices = [
    ['id' => 11, 'organizationId' => 901, 'systemName' => 'HARBOUR-LT-01', 'dnsName' => 'harbour-lt-01.harbour.example', 'nodeClass' => 'WINDOWS_WORKSTATION', 'approvalStatus' => 'APPROVED',
     'os' => ['name' => 'Windows 10 Pro', 'buildNumber' => '19045', 'releaseId' => '22H2'], 'ipAddresses' => ['10.30.0.11'], 'lastContact' => time() - 600],
    ['id' => 12, 'organizationId' => 901, 'systemName' => 'HARBOUR-SRV-01', 'dnsName' => '', 'nodeClass' => 'WINDOWS_SERVER', 'approvalStatus' => 'APPROVED',
     'os' => ['name' => 'Windows Server 2022 Standard', 'buildNumber' => '20348', 'releaseId' => '21H2'], 'ipAddresses' => ['10.30.0.12'], 'lastContact' => time() - 300],
    ['id' => 13, 'organizationId' => 901, 'systemName' => 'HARBOUR-LT-02', 'nodeClass' => 'WINDOWS_WORKSTATION', 'approvalStatus' => 'APPROVED',
     'os' => ['name' => 'Windows 11 Pro', 'buildNumber' => '26200', 'releaseId' => '25H2'], 'ipAddresses' => ['10.30.0.13'], 'lastContact' => time() - 60],
    ['id' => 14, 'organizationId' => 901, 'systemName' => 'HARBOUR-SW-01', 'nodeClass' => 'NMS_SWITCH', 'approvalStatus' => 'APPROVED'],
    ['id' => 15, 'organizationId' => 901, 'systemName' => 'HARBOUR-NEW', 'nodeClass' => 'WINDOWS_WORKSTATION', 'approvalStatus' => 'PENDING'],
    ['id' => 16, 'organizationId' => 900, 'systemName' => 'BROKEN-LT-01', 'nodeClass' => 'WINDOWS_WORKSTATION', 'approvalStatus' => 'APPROVED', 'os' => ['name' => 'Windows 11 Pro', 'buildNumber' => '26200']],
    // Offline for a month and no inventory yet: its antivirus is unknown, not missing.
    ['id' => 17, 'organizationId' => 901, 'systemName' => 'HARBOUR-OLD', 'nodeClass' => 'WINDOWS_WORKSTATION', 'approvalStatus' => 'APPROVED',
     'os' => ['name' => 'Windows 11 Pro', 'buildNumber' => '26200', 'releaseId' => '25H2'], 'lastContact' => time() - 86400 * 30],
    // Organisation 902 (1.49): an online workstation with software, but the antivirus report has no rows for anyone:
    // a gap in the data, never "no antivirus".
    ['id' => 19, 'organizationId' => 902, 'systemName' => 'QUAY-LT-01', 'nodeClass' => 'WINDOWS_WORKSTATION', 'approvalStatus' => 'APPROVED',
     'os' => ['name' => 'Windows 11 Pro', 'buildNumber' => '26200', 'releaseId' => '25H2'], 'ipAddresses' => ['10.40.0.19'], 'lastContact' => time() - 120],
    // Organisation 903: its software report ignores the cursor and returns the same page forever.
    ['id' => 18, 'organizationId' => 903, 'systemName' => 'STUCK-LT-01', 'nodeClass' => 'WINDOWS_WORKSTATION', 'approvalStatus' => 'APPROVED', 'os' => ['name' => 'Windows 11 Pro', 'buildNumber' => '26200']],
];
$page = static function (array $rows, string $kind): array {
    $size = max(1, min(1000, (int) ($_GET['pageSize'] ?? 100)));
    $offset = isset($_GET['cursor']) && preg_match('/^' . $kind . '-(\d+)$/', (string) $_GET['cursor'], $m) === 1 ? (int) $m[1] : 0;
    $slice = array_slice($rows, $offset, $size);
    return ['cursor' => ['name' => $kind . '-' . ($offset + $size), 'offset' => $offset, 'count' => count($slice), 'expires' => time() + 60], 'results' => $slice];
};
if ($sub === '/v2/organizations') {
    $all = [['id' => 900, 'name' => 'Broken Example'], ['id' => 901, 'name' => 'Harbour Example Ltd'], ['id' => 902, 'name' => 'Quay Example Inc']]; // by ID, like the API
    $after = (int) ($_GET['after'] ?? 0);
    $json(200, array_values(array_slice(array_filter($all, static fn ($o) => $o['id'] > $after), 0, (int) ($_GET['pageSize'] ?? 100))));
}
$org = $orgFrom();
if ($org === null) {
    $json(400, ['error' => 'df must be org = N in this mock']);
}
$mine = array_values(array_filter($devices, static fn ($d) => ($d['organizationId'] ?? 0) === $org));
$ids = array_column($mine, 'id');
if ($sub === '/v2/devices-detailed') {
    $after = (int) ($_GET['after'] ?? 0);
    $json(200, array_values(array_slice(array_filter($mine, static fn ($d) => $d['id'] > $after), 0, (int) ($_GET['pageSize'] ?? 100))));
}
$only = static fn (array $rows): array => array_values(array_filter($rows, static fn ($r) => in_array($r['deviceId'], $ids, true)));
if ($sub === '/v2/queries/software') {
    if ($org === 900) {
        $json(500, ['error' => 'internal']);
    }
    if ($org === 903) {
        $size = (int) ($_GET['pageSize'] ?? 100);
        $json(200, ['cursor' => ['name' => 'stuck', 'offset' => 0, 'count' => $size], 'results' => array_fill(0, $size, ['deviceId' => 18, 'name' => 'Loop', 'publisher' => 'x', 'version' => '1'])]);
    }
    $json(200, $page($only([
        ['deviceId' => 11, 'name' => 'Google Chrome', 'publisher' => 'Google LLC', 'version' => '116.0.5845.96'],
        ['deviceId' => 11, 'name' => '7-Zip 23.01 (x64)', 'publisher' => 'Igor Pavlov', 'version' => '23.01'],
        ['deviceId' => 12, 'name' => 'Microsoft Edge', 'publisher' => 'Microsoft Corporation', 'version' => '120.0.2210.61'],
        ['deviceId' => 13, 'name' => 'Mozilla Firefox (x64 en-US)', 'publisher' => 'Mozilla', 'version' => '115.0'],
        ['deviceId' => 13, 'name' => '<script>alert(1)</script>', 'publisher' => 'Example', 'version' => '1.0'],
        ['deviceId' => 19, 'name' => '7-Zip 23.01 (x64)', 'publisher' => 'Igor Pavlov', 'version' => '23.01'],
    ]), 'sw'));
}
if ($sub === '/v2/queries/os-patches') {
    $json(200, $page($only([
        ['id' => 'aaaaaaaa-0000-0000-0000-000000000001', 'deviceId' => 11, 'name' => '2026-10 Cumulative Update for Windows 10', 'kbNumber' => 'KB5099999', 'severity' => 'CRITICAL', 'status' => 'MANUAL', 'timestamp' => time() - 86400 * 45],
        ['id' => 'aaaaaaaa-0000-0000-0000-000000000002', 'deviceId' => 12, 'name' => 'Security update', 'kbNumber' => 'KB5088888', 'severity' => 'IMPORTANT', 'status' => 'MANUAL', 'timestamp' => time() - 86400 * 3],
        ['id' => 'aaaaaaaa-0000-0000-0000-000000000003', 'deviceId' => 13, 'name' => 'Declined update', 'kbNumber' => 'KB5077777', 'severity' => 'CRITICAL', 'status' => 'REJECTED', 'timestamp' => time() - 86400 * 60],
    ]), 'pt'));
}
if ($sub === '/v2/queries/os-patch-installs') {
    // Failed attempts: device 12's KB5088888 failed two days ago (counts); device 11's failed 40 days ago (too old).
    $json(200, $page(array_values(array_filter($only([
        ['id' => 'bbbbbbbb-0000-0000-0000-000000000001', 'deviceId' => 12, 'name' => 'Security update', 'kbNumber' => 'KB5088888', 'status' => 'FAILED', 'installedAt' => time() - 86400 * 2],
        ['id' => 'bbbbbbbb-0000-0000-0000-000000000002', 'deviceId' => 11, 'name' => '2026-10 Cumulative Update for Windows 10', 'kbNumber' => 'KB5099999', 'status' => 'FAILED', 'installedAt' => time() - 86400 * 40],
        ['id' => 'bbbbbbbb-0000-0000-0000-000000000003', 'deviceId' => 13, 'name' => 'Installed fine', 'kbNumber' => 'KB5066666', 'status' => 'INSTALLED', 'installedAt' => time() - 86400],
    ]), static fn ($r) => ($_GET['status'] ?? '') === '' || $r['status'] === $_GET['status'])), 'pi'));
}
if ($sub === '/v2/queries/antivirus-status') {
    $json(200, $page($only([
        ['deviceId' => 11, 'productName' => 'Windows Defender', 'productState' => 'OFF', 'definitionStatus' => 'OUT_OF_DATE'],
        ['deviceId' => 12, 'productName' => 'Example EDR', 'productState' => 'ON', 'definitionStatus' => 'UP_TO_DATE'],
    ]), 'av'));
}
if ($sub === '/v2/queries/volumes') {
    $json(200, $page($only([
        ['deviceId' => 11, 'driveLetter' => 'C:', 'bitLockerStatus' => ['conversionStatus' => 'FULLY_DECRYPTED', 'protectionStatus' => 'UNPROTECTED']],
        ['deviceId' => 13, 'driveLetter' => 'C:', 'bitLockerStatus' => ['conversionStatus' => 'FULLY_ENCRYPTED', 'protectionStatus' => 'PROTECTED']],
        ['deviceId' => 13, 'driveLetter' => 'D:', 'bitLockerStatus' => ['conversionStatus' => 'FULLY_DECRYPTED', 'protectionStatus' => 'UNPROTECTED']],
    ]), 'vol'));
}
$json(404, ['error' => 'not found']);
