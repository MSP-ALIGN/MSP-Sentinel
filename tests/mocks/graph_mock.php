<?php

declare(strict_types=1);

/**
 * Mock Microsoft Graph for "Connect to Microsoft 365" (1.63). Never used in production; made-up tenant, apps and IDs.
 * Included by feeds_router.php for paths under /graph/v1.0/. State (apps, service principals, consent grants, secrets)
 * lives in graph.json in the state folder; every request is appended to graph-log.json for the tests to inspect.
 *
 * scenario.json "graph": {"tenant": GUID, "org": name, "forbidden": true (every call 403, as for an account that can't
 * register apps), "consent_fail": true (consent grants refused), "sp_fail": n (the first n service principal creations
 * fail, as while a new app replicates), "remove_fail": true (removing an old secret fails)}.
 * Only the bearer token "mock-graph-token" is accepted.
 */

$dir = dirname((string) getenv('FEEDS_LOG')) . '/entra';
@mkdir($dir, 0700, true);
header('Content-Type: application/json');
$sc = is_file($dir . '/scenario.json') ? (array) json_decode((string) file_get_contents($dir . '/scenario.json'), true) : [];
$g = (array) ($sc['graph'] ?? []);
$stateFile = $dir . '/graph.json';
$state = is_file($stateFile) ? (array) json_decode((string) file_get_contents($stateFile), true) : [];
$state += ['apps' => [], 'sps' => [], 'grants' => [], 'sp_fails' => 0];
$save = static function () use (&$state, $stateFile): void {
    file_put_contents($stateFile, json_encode($state));
};
$method = (string) $_SERVER['REQUEST_METHOD'];
$uri = (string) $_SERVER['REQUEST_URI'];
$path = (string) parse_url($uri, PHP_URL_PATH);
parse_str((string) parse_url($uri, PHP_URL_QUERY), $q);
$body = (array) json_decode((string) file_get_contents('php://input'), true);
$log = is_file($dir . '/graph-log.json') ? (array) json_decode((string) file_get_contents($dir . '/graph-log.json'), true) : [];
$log[] = ['method' => $method, 'path' => $path, 'filter' => (string) ($q['$filter'] ?? ''), 'body' => $body];
file_put_contents($dir . '/graph-log.json', json_encode($log));
$out = static function (int $status, array $data = []): void {
    http_response_code($status);
    echo $status === 204 ? '' : json_encode($data);
    exit;
};
if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer mock-graph-token') {
    $out(401, ['error' => ['code' => 'InvalidAuthenticationToken']]);
}
if (!empty($g['forbidden'])) {
    $out(403, ['error' => ['code' => 'Authorization_RequestDenied', 'message' => 'Insufficient privileges to complete the operation.']]);
}
$p = substr($path, strlen('/graph/v1.0'));
$guid = static function (): string {
    $h = bin2hex(random_bytes(16));
    return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-4' . substr($h, 13, 3) . '-8' . substr($h, 17, 3) . '-' . substr($h, 20, 12);
};
$filter = (string) ($q['$filter'] ?? '');

if ($method === 'GET' && $p === '/organization') {
    $out(200, ['value' => [['id' => (string) ($g['tenant'] ?? 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'), 'displayName' => (string) ($g['org'] ?? 'Example MSP Tenant')]]]);
}
if ($method === 'GET' && $p === '/applications') {
    preg_match("/t eq '(.*)'\\)/", $filter, $m);
    $found = array_values(array_filter($state['apps'], static fn (array $a): bool => in_array(str_replace("''", "'", $m[1] ?? ''), $a['tags'] ?? [], true)));
    $out(200, ['value' => $found]);
}
if ($method === 'POST' && $p === '/applications') {
    $app = $body + ['id' => 'obj-' . bin2hex(random_bytes(4)), 'appId' => $guid(), 'passwordCredentials' => []];
    $state['apps'][$app['id']] = $app;
    $save();
    $out(201, $app);
}
if (preg_match('#^/applications/([a-z0-9-]+)(/addPassword|/removePassword)?$#', $p, $m) === 1) {
    $id = $m[1];
    if (!isset($state['apps'][$id])) {
        $out(404, ['error' => ['code' => 'Request_ResourceNotFound']]);
    }
    if ($method === 'PATCH' && ($m[2] ?? '') === '') {
        $state['apps'][$id] = array_merge($state['apps'][$id], $body);
        $save();
        $out(204);
    }
    if ($method === 'GET' && ($m[2] ?? '') === '') {
        $out(200, ['passwordCredentials' => array_values($state['apps'][$id]['passwordCredentials'])]);
    }
    if ($method === 'POST' && $m[2] === '/addPassword') {
        $cred = ['keyId' => $guid(), 'displayName' => (string) ($body['passwordCredential']['displayName'] ?? ''), 'endDateTime' => (string) ($body['passwordCredential']['endDateTime'] ?? '')];
        $state['apps'][$id]['passwordCredentials'][] = $cred;
        $save();
        $out(200, $cred + ['secretText' => 'Mock~Secret.' . bin2hex(random_bytes(12))]);
    }
    if ($method === 'POST' && $m[2] === '/removePassword') {
        if (!empty($g['remove_fail'])) {
            $out(500, ['error' => ['code' => 'made-up']]);
        }
        $state['apps'][$id]['passwordCredentials'] = array_values(array_filter($state['apps'][$id]['passwordCredentials'], static fn (array $c): bool => $c['keyId'] !== ($body['keyId'] ?? '')));
        $save();
        $out(204);
    }
}
if ($p === '/servicePrincipals') {
    if ($method === 'GET') {
        preg_match("/appId eq '([0-9a-f-]+)'/", $filter, $m);
        if (($m[1] ?? '') === '00000003-0000-0000-c000-000000000000') {
            $out(200, ['value' => [['id' => 'graph-sp-id']]]);
        }
        $out(200, ['value' => array_values(array_filter($state['sps'], static fn (array $s): bool => $s['appId'] === ($m[1] ?? '')))]);
    }
    if ($method === 'POST') {
        if ($state['sp_fails'] < (int) ($g['sp_fail'] ?? 0)) {
            $state['sp_fails']++;
            $save();
            $out(400, ['error' => ['code' => 'Request_BadRequest', 'message' => 'not replicated yet']]);
        }
        $sp = ['id' => 'sp-' . bin2hex(random_bytes(4)), 'appId' => (string) ($body['appId'] ?? '')];
        $state['sps'][] = $sp;
        $save();
        $out(201, $sp);
    }
}
if ($p === '/oauth2PermissionGrants' || str_starts_with($p, '/oauth2PermissionGrants/')) {
    if (!empty($g['consent_fail'])) {
        $out(403, ['error' => ['code' => 'Authorization_RequestDenied']]);
    }
    if ($method === 'GET') {
        preg_match("/clientId eq '([a-z0-9-]+)'/", $filter, $m);
        $out(200, ['value' => array_values(array_filter($state['grants'], static fn (array $x): bool => $x['clientId'] === ($m[1] ?? '')))]);
    }
    if ($method === 'POST') {
        $grant = $body + ['id' => 'grant-' . bin2hex(random_bytes(4))];
        $state['grants'][] = $grant;
        $save();
        $out(201, $grant);
    }
    if ($method === 'PATCH') {
        $id = substr($p, strlen('/oauth2PermissionGrants/'));
        foreach ($state['grants'] as &$x) {
            if ($x['id'] === $id) {
                $x = array_merge($x, $body);
            }
        }
        unset($x);
        $save();
        $out(204);
    }
}
$out(404, ['error' => ['code' => 'not_found', 'path' => $p]]);
