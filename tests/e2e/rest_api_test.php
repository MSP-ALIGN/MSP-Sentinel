<?php

declare(strict_types=1);

/**
 * End-to-end tests for the API: tokens shown once and stored hashed, bearer
 * authentication only (no cookies), client limits, pagination and filters,
 * opt-in write permissions (triage, queue scan), expiry/revocation/IP
 * allowlist/rate limits, report downloads, OpenAPI, and signed outbound
 * events to a fake receiver on 127.0.0.1. Made-up data only.
 */

use Sentinel\Api\EventPublisher;
use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$setup = static function (TestContext $ctx): array {
    $a = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Api Example A'")->fetchColumn();
    if ($a === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $now = (int) gmdate('G');
        $ids = [];
        foreach (['Api Example A', 'Api Example B'] as $name) {
            $res = $admin->submit('/clients/new', '/clients', ['name' => $name, 'itflow_client_id' => '', 'timezone' => 'UTC',
                'scan_window_start' => sprintf('%02d:00', ($now + 23) % 24), 'scan_window_end' => sprintf('%02d:00', ($now + 1) % 24), 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
            $cid = (int) basename((string) $res->location());
            $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
                'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
                'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '', 'scope' => '203.0.113.160', 'confirm' => '1']);
            $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
            $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
            $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
            $ids[] = $cid;
        }
        // Client B's finding gets a recognisable title so leaks are easy to spot.
        $ctx->db->exec("UPDATE findings SET title = 'CLIENT-B-ONLY finding' WHERE client_id = {$ids[1]}");
        $a = $ids[0];
    }
    $b = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Api Example B'")->fetchColumn();
    $ctx->db->exec("DELETE FROM auth_throttle"); // each test starts with clean rate-limit counters
    return [$a, $b];
};
$adminId = static fn (TestContext $ctx): int => (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
$token = static function (TestContext $ctx, array $clients, bool $triage = false, bool $scan = false, array $ips = []) use ($adminId): array {
    return App::apiTokens()->create('Test token', $clients === [], $clients, $triage, $scan, $ips, 30, $adminId($ctx));
};

return [
    'admins create tokens: shown once, stored only as a keyed hash' => function (TestContext $ctx) use ($setup): void {
        [$a] = $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::redirect('/admin/api', $admin->submit('/admin/api', '/admin/api/tokens', ['name' => 'MSP Align', 'clients' => [(string) $a], 'expires_days' => '90', 'ip_allowlist' => '']));
        $page = $admin->get('/admin/api')->body;
        Assert::true((bool) preg_match('/id="new-token">(snt_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43})</', $page, $m), 'token shown');
        $plain = $m[1];
        Assert::notContains($plain, $admin->get('/admin/api')->body, 'shown only once');
        $row = $ctx->db->query("SELECT * FROM api_tokens WHERE name = 'MSP Align'")->fetch();
        Assert::true(!str_contains(json_encode($row), substr($plain, 18)), 'secret part not stored');
        Assert::same(64, strlen($row['token_hash']));
        Assert::same(['0', '0'], [(string) $row['can_triage'], (string) $row['can_scan']], 'write permissions off unless ticked');
        Assert::notContains(substr($plain, 18), (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'api.token_created' ORDER BY id DESC LIMIT 1")->fetchColumn());
        Assert::same(200, $ctx->api('GET', '/api/v1/me', $plain)->status);

        $admin->submit('/admin/api', '/admin/api/tokens', ['name' => '', 'all_clients' => '1', 'expires_days' => '90']);
        Assert::contains('Give the token a name', $admin->get('/admin/api')->body);
        $admin->submit('/admin/api', '/admin/api/tokens', ['name' => 'Forever', 'all_clients' => '1', 'expires_days' => '5000']);
        Assert::contains('Choose when the token expires', $admin->get('/admin/api')->body);
        $admin->submit('/admin/api', '/admin/api/tokens', ['name' => 'Bad IP', 'all_clients' => '1', 'expires_days' => '30', 'ip_allowlist' => '203.0.113.7/24']);
        Assert::contains('is not an IP address or network', $admin->get('/admin/api')->body);

        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'apitech'")->fetchColumn() === 0) {
            $ctx->createUser('apitech', 'technician', 'Apitech-Pass-01!');
        }
        $tech = $ctx->login('apitech', 'Apitech-Pass-01!');
        Assert::status(403, $tech->get('/admin/api'));
        Assert::status(403, $tech->post('/admin/api/tokens', ['_csrf' => $tech->get('/')->csrf(), 'name' => 'x', 'all_clients' => '1', 'expires_days' => '30']));
    },
    'authentication: bearer token only, never cookies or query strings' => function (TestContext $ctx) use ($setup, $token): void {
        [$a] = $setup($ctx);
        [, $plain] = $token($ctx, [$a]);
        $none = $ctx->api('GET', '/api/v1/me', null);
        Assert::same(401, $none->status);
        Assert::same('Bearer', $none->header('www-authenticate'));
        Assert::same(401, $ctx->api('GET', '/api/v1/me', 'not-a-token')->status);
        Assert::same(401, $ctx->api('GET', '/api/v1/me', substr($plain, 0, -4) . 'AAAA')->status, 'right prefix, wrong secret');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::status(401, $admin->get('/api/v1/me'), 'a signed-in browser session does not work for the API');
        Assert::same(401, $ctx->api('GET', '/api/v1/me?token=' . urlencode($plain), null)->status);
        $ok = $ctx->api('GET', '/api/v1/me', $plain);
        Assert::same(200, $ok->status);
        Assert::contains("default-src 'none'", (string) $ok->header('content-security-policy'));
        Assert::true($ok->header('set-cookie') === null && $ok->header('access-control-allow-origin') === null, 'no cookies, no CORS');
        $me = json_decode($ok->body, true)['data'];
        Assert::same(['read'], $me['permissions']);
        Assert::same([$a], $me['clients']);
        Assert::same(404, $ctx->api('GET', '/api/v1/nothing', $plain)->status);
        Assert::same(405, $ctx->api('DELETE', '/api/v1/clients', $plain)->status);
    },
    'reads are limited to the token\'s clients; pagination and filters' => function (TestContext $ctx) use ($setup, $token): void {
        [$a, $b] = $setup($ctx);
        [, $plain] = $token($ctx, [$a]);
        $clients = json_decode($ctx->api('GET', '/api/v1/clients', $plain)->body, true);
        Assert::same([$a], array_column($clients['data'], 'id'));
        Assert::same(404, $ctx->api('GET', '/api/v1/clients/' . $b, $plain)->status, 'other client looks like it does not exist');
        Assert::same(404, $ctx->api('GET', '/api/v1/clients/' . $b . '/summary', $plain)->status);
        $all = $ctx->api('GET', '/api/v1/findings?per_page=500', $plain);
        Assert::notContains('CLIENT-B-ONLY', $all->body);
        $rows = json_decode($all->body, true)['data'];
        Assert::true($rows !== [] && array_unique(array_column($rows, 'client_id')) === [$a], 'only client A findings');
        Assert::same([], json_decode($ctx->api('GET', '/api/v1/findings?client_id=' . $b, $plain)->body, true)['data'], 'filtering by another client gives nothing');
        $bFinding = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$b} LIMIT 1")->fetchColumn();
        Assert::same(404, $ctx->api('GET', '/api/v1/findings/' . $bFinding, $plain)->status);
        $one = json_decode($ctx->api('GET', '/api/v1/findings/' . $rows[0]['id'], $plain)->body, true)['data'];
        Assert::true(isset($one['history']) && $one['history'][0]['event'] === 'opened', 'history included');

        $p1 = json_decode($ctx->api('GET', '/api/v1/findings?per_page=1', $plain)->body, true);
        Assert::same(['page' => 1, 'per_page' => 1, 'total' => count($rows), 'next_page' => 2], $p1['meta']);
        Assert::same(400, $ctx->api('GET', '/api/v1/findings?per_page=9999', $plain)->status);
        Assert::same(400, $ctx->api('GET', '/api/v1/findings?status=everything', $plain)->status);
        Assert::same(400, $ctx->api('GET', '/api/v1/findings?updated_since=yesterday', $plain)->status);
        Assert::same(0, json_decode($ctx->api('GET', '/api/v1/findings?updated_since=2099-01-01T00:00:00Z', $plain)->body, true)['meta']['total']);
        Assert::same(count($rows), json_decode($ctx->api('GET', '/api/v1/findings?updated_since=' . urlencode('2000-01-01T00:00:00+02:00'), $plain)->body, true)['meta']['total']);
        $fails = json_decode($ctx->api('GET', '/api/v1/findings?severity=fail&status=open', $plain)->body, true)['data'];
        Assert::true($fails !== [] && array_unique(array_column($fails, 'severity')) === ['fail'], 'severity filter');

        $assets = json_decode($ctx->api('GET', '/api/v1/assets', $plain)->body, true)['data'];
        Assert::same('203.0.113.160', $assets[0]['ip']);
        Assert::true(in_array(3389, array_column($assets[0]['open_services'], 'port'), true), 'open services listed');
        $sum = json_decode($ctx->api('GET', '/api/v1/clients/' . $a . '/summary', $plain)->body, true)['data'];
        Assert::same('at_risk', $sum['rating']);
        Assert::true($sum['last_scan']['scan_id'] > 0 && str_ends_with($sum['last_scan']['finished_at'], 'Z'), 'last scan in ISO 8601 UTC');
        $scans = json_decode($ctx->api('GET', '/api/v1/scans', $plain)->body, true)['data'];
        Assert::same([$a], array_values(array_unique(array_column($scans, 'client_id'))));
        $spec = json_decode($ctx->api('GET', '/api/v1/openapi.json', $plain)->body, true);
        Assert::same('3.1.0', $spec['openapi']);
        Assert::true(isset($spec['paths']['/findings/{id}/triage']['post']), 'documented');
    },
    'reports through the API: list, frozen HTML with its hash, CSV' => function (TestContext $ctx) use ($setup, $token): void {
        [$a, $b] = $setup($ctx);
        $client = App::clients()->find($a);
        $id = App::reportService()->generate($client, 'technical', gmdate('Y-m-d', time() - 29 * 86400), gmdate('Y-m-d'), null, 'Test');
        $other = App::reportService()->generate(App::clients()->find($b), 'executive', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        [, $plain] = $token($ctx, [$a]);
        $list = json_decode($ctx->api('GET', '/api/v1/reports', $plain)->body, true)['data'];
        Assert::true(in_array($id, array_column($list, 'id'), true) && !in_array($other, array_column($list, 'id'), true), 'only own client reports');
        $html = $ctx->api('GET', '/api/v1/reports/' . $id . '/html', $plain);
        Assert::same(hash('sha256', $html->body), $html->header('x-report-sha256'));
        Assert::contains('sandbox', (string) $html->header('content-security-policy'));
        Assert::contains('status,severity', $ctx->api('GET', '/api/v1/reports/' . $id . '/csv', $plain)->body);
        Assert::same(404, $ctx->api('GET', '/api/v1/reports/' . $other . '/html', $plain)->status);
        Assert::same('risk', json_decode($ctx->api('GET', '/api/v1/reports/' . $id, $plain)->body, true)['data']['rating']);
    },
    'writes need opt-in permissions: triage with a note, queue scans' => function (TestContext $ctx) use ($setup, $token): void {
        [$a, $b] = $setup($ctx);
        [, $read] = $token($ctx, [$a]);
        [, $triage] = $token($ctx, [$a], true);
        [, $scan] = $token($ctx, [$a], false, true);
        $f = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$a} AND status = 'open' AND severity = 'warn' ORDER BY id LIMIT 1")->fetchColumn();
        Assert::same(403, $ctx->api('POST', '/api/v1/findings/' . $f . '/triage', $read, ['status' => 'accepted', 'note' => 'x'])->status);
        Assert::same(422, $ctx->api('POST', '/api/v1/findings/' . $f . '/triage', $triage, ['status' => 'accepted', 'note' => ''])->status);
        Assert::same(422, $ctx->api('POST', '/api/v1/findings/' . $f . '/triage', $triage, ['status' => 'deleted', 'note' => 'x'])->status);
        Assert::same(400, $ctx->api('POST', '/api/v1/findings/' . $f . '/triage', $triage, null, '{not json')->status);
        $res = $ctx->api('POST', '/api/v1/findings/' . $f . '/triage', $triage, ['status' => 'accepted', 'note' => 'Accepted by the client in the QBR.']);
        Assert::same(200, $res->status);
        $out = json_decode($res->body, true);
        Assert::same([true, 'accepted'], [$out['changed'], $out['data']['status']]);
        Assert::same('[API: Test token] Accepted by the client in the QBR.', $out['data']['triage_note']);
        $audit = json_decode((string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'finding.triaged' ORDER BY id DESC LIMIT 1")->fetchColumn(), true);
        Assert::same('api', $audit['via']);
        $bf = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$b} LIMIT 1")->fetchColumn();
        Assert::same(404, $ctx->api('POST', '/api/v1/findings/' . $bf . '/triage', $triage, ['status' => 'accepted', 'note' => 'x'])->status, 'cannot triage another client');

        Assert::same(403, $ctx->api('POST', '/api/v1/clients/' . $a . '/scans', $read)->status);
        $ctx->db->exec("UPDATE scan_jobs SET status = 'done' WHERE client_id = {$a} AND status IN ('queued','running')");
        $q = $ctx->api('POST', '/api/v1/clients/' . $a . '/scans', $scan);
        Assert::same(202, $q->status);
        $sid = json_decode($q->body, true)['data']['scan_id'];
        Assert::true((int) $ctx->db->query("SELECT api_token_id FROM scan_jobs WHERE id = {$sid}")->fetchColumn() > 0, 'scan records the token');
        Assert::same(0, (int) $ctx->db->query("SELECT outside_window FROM scan_jobs WHERE id = {$sid}")->fetchColumn(), 'API scans never skip the window');
        Assert::same(409, $ctx->api('POST', '/api/v1/clients/' . $a . '/scans', $scan)->status, 'already queued');
        Assert::same(404, $ctx->api('POST', '/api/v1/clients/' . $b . '/scans', $scan)->status);
        $ctx->db->exec("UPDATE scan_jobs SET status = 'cancelled' WHERE id = {$sid}");
        $ctx->db->exec("UPDATE clients SET scanning_paused = 1 WHERE id = {$a}");
        Assert::same(409, $ctx->api('POST', '/api/v1/clients/' . $a . '/scans', $scan)->status, 'paused client');
        $ctx->db->exec("UPDATE clients SET scanning_paused = 0 WHERE id = {$a}");
    },
    'expiry, revocation, creator status, IP allowlist and rate limits' => function (TestContext $ctx) use ($setup, $token): void {
        [$a] = $setup($ctx);
        [$id, $plain] = $token($ctx, [$a]);
        $ctx->db->exec("UPDATE api_tokens SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 MINUTE WHERE id = {$id}");
        Assert::same(401, $ctx->api('GET', '/api/v1/me', $plain)->status, 'expired');
        $ctx->db->exec("UPDATE api_tokens SET expires_at = UTC_TIMESTAMP() + INTERVAL 1 DAY WHERE id = {$id}");
        Assert::same(200, $ctx->api('GET', '/api/v1/me', $plain)->status);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/api', '/admin/api/tokens/' . $id . '/revoke', []);
        Assert::same(401, $ctx->api('GET', '/api/v1/me', $plain)->status, 'revoked');

        // A token stops working when its creator is no longer an active admin.
        $uid = $ctx->createUser('apiadmin' . bin2hex(random_bytes(2)), 'admin', 'Apiadmin-Pass-01!');
        [, $t2] = App::apiTokens()->create('Creator test', true, [], false, false, [], 30, $uid);
        Assert::same(200, $ctx->api('GET', '/api/v1/me', $t2)->status);
        $ctx->db->exec("UPDATE users SET role = 'technician' WHERE id = {$uid}");
        Assert::same(401, $ctx->api('GET', '/api/v1/me', $t2)->status, 'creator demoted');
        $ctx->db->exec("UPDATE users SET role = 'admin', is_active = 0 WHERE id = {$uid}");
        Assert::same(401, $ctx->api('GET', '/api/v1/me', $t2)->status, 'creator deactivated');

        [, $far] = $token($ctx, [$a], false, false, ['198.51.100.0/24']);
        Assert::same(403, $ctx->api('GET', '/api/v1/me', $far)->status, 'not from an allowed address');
        [$nearId, $near] = $token($ctx, [$a], false, false, ['127.0.0.1']);
        Assert::same(200, $ctx->api('GET', '/api/v1/me', $near)->status);

        $ctx->db->exec("DELETE FROM auth_throttle");
        $bucket = $ctx->db->quote(hash('sha256', 'api:' . $nearId));
        $ctx->db->exec("INSERT INTO auth_throttle (bucket, attempted_at) SELECT {$bucket}, UTC_TIMESTAMP() FROM information_schema.COLUMNS LIMIT 120");
        Assert::same(429, $ctx->api('GET', '/api/v1/me', $near)->status, '120 requests a minute per token');
        $ctx->db->exec("DELETE FROM auth_throttle");
        for ($i = 0; $i < 20; $i++) {
            $ctx->api('GET', '/api/v1/me', 'snt_AAAAAAAAAAAA_' . str_repeat('x', 43));
        }
        Assert::same(429, $ctx->api('GET', '/api/v1/me', $near)->status, 'too many failures from one address');
        $ctx->db->exec("DELETE FROM auth_throttle");
    },
    'outbound events: signed, shown-once secret, SSRF checks, all event kinds' => function (TestContext $ctx) use ($setup, $token): void {
        [$a] = $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $feeds = (require $ctx->configPath)['nvd']['base_url'];
        $admin->submit('/admin/api', '/admin/api/events', ['event_webhook_enabled' => '1', 'event_webhook_url' => 'https://10.0.0.5/hook']);
        Assert::contains('private or reserved address', $admin->get('/admin/api')->body);
        $admin->submit('/admin/api', '/admin/api/events', ['event_webhook_enabled' => '1', 'event_webhook_url' => $feeds . '/events']);
        $page = $admin->get('/admin/api')->body;
        Assert::true((bool) preg_match('/id="new-secret">(whsec_[A-Za-z0-9_-]{43})</', $page, $m), 'secret shown once');
        $secret = $m[1];
        Assert::notContains($secret, $admin->get('/admin/api')->body);
        Assert::true(str_starts_with((string) $ctx->db->query("SELECT value FROM settings WHERE name = 'event_webhook_secret'")->fetchColumn(), 'v1:'), 'stored encrypted');

        @unlink($ctx->eventLog);
        $admin->submit('/admin/api', '/admin/api/events/test', []);
        Assert::contains('Test event delivered', $admin->get('/admin/api')->body);
        $verify = static function (array $post) use ($secret): array {
            Assert::true((bool) preg_match('/^t=(\d+),v1=([0-9a-f]{64})$/', $post['signature'], $s), 'signature header format');
            Assert::true(abs(time() - (int) $s[1]) < 300, 'recent timestamp');
            Assert::same(hash_hmac('sha256', $s[1] . '.' . $post['body'], $secret), $s[2], 'signature verifies');
            return json_decode($post['body'], true);
        };
        $posts = array_map(static fn (string $l): array => json_decode($l, true), file($ctx->eventLog, FILE_IGNORE_NEW_LINES));
        $ping = $verify($posts[0]);
        Assert::same(['ping', 'ping'], [$ping['type'], $posts[0]['event']]);

        // Triage, report and findings changes become events.
        App::settings()->set('event_webhook_enabled', '1'); // refresh this process's cache
        [, $tri] = $token($ctx, [$a], true);
        $f = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$a} AND status = 'open' ORDER BY id LIMIT 1")->fetchColumn();
        $ctx->api('POST', '/api/v1/findings/' . $f . '/triage', $tri, ['status' => 'false_positive', 'note' => 'Backported fix confirmed.']);
        App::reportService()->generate(App::clients()->find($a), 'executive', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        $rdp = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$a} AND finding_key = 'port:203.0.113.160:3389'")->fetchColumn();
        $ctx->db->exec("UPDATE findings SET status = 'open' WHERE id = {$rdp}");
        $svc = "SELECT s.id FROM services s JOIN assets x ON x.id = s.asset_id WHERE x.client_id = {$a} AND s.port = 3389";
        $ctx->db->exec("UPDATE services SET is_open = 0 WHERE id = ({$svc})");
        App::alerts()->findingsChanged($a, App::findingsEngine()->refreshClient($a), false);
        $ctx->db->exec("UPDATE services SET is_open = 1 WHERE id = ({$svc})");
        App::alerts()->findingsChanged($a, App::findingsEngine()->refreshClient($a), false);
        @unlink($ctx->eventLog);
        App::outbox()->flush(100);
        $types = [];
        foreach (file($ctx->eventLog, FILE_IGNORE_NEW_LINES) as $line) {
            $e = $verify(json_decode($line, true));
            $types[] = $e['type'];
            Assert::same(['id', 'type', 'created_at', 'data'], array_keys($e));
        }
        foreach (['finding.triaged', 'report.created', 'finding.resolved', 'finding.reopened'] as $t) {
            Assert::true(in_array($t, $types, true), 'event sent: ' . $t);
        }
        // Turned off: nothing is queued.
        $admin->submit('/admin/api', '/admin/api/events', ['event_webhook_url' => '']);
        App::settings()->set('event_webhook_enabled', '0');
        $before = (int) $ctx->db->query("SELECT COUNT(*) FROM deliveries WHERE channel = 'event'")->fetchColumn();
        App::events()->publish('scan.finished', ['scan_id' => 1]);
        Assert::same($before, (int) $ctx->db->query("SELECT COUNT(*) FROM deliveries WHERE channel = 'event'")->fetchColumn());
    },
];
