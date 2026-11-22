<?php

declare(strict_types=1);

/**
 * End-to-end tests: findings built from scan data, the lifecycle (open, resolved,
 * reopened, reappeared), triage rules and permissions, the all-clients list and
 * the dashboard. Self-contained: creates its own client, runs the worker (fake nmap)
 * and the feeds job (mock feeds). Made-up names, documentation IPs, CVE-2099 IDs only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$clientId = static fn (TestContext $ctx): int => (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Findings Example'")->fetchColumn();
$finding = static function (TestContext $ctx, int $client, string $key): array {
    $stmt = $ctx->db->prepare('SELECT * FROM findings WHERE client_id = :c AND finding_key = :k');
    $stmt->execute(['c' => $client, 'k' => $key]);
    return $stmt->fetch() ?: [];
};
$events = static function (TestContext $ctx, int $findingId): array {
    return $ctx->db->query("SELECT event FROM finding_events WHERE finding_id = {$findingId} ORDER BY id")->fetchAll(PDO::FETCH_COLUMN);
};

return [
    'scan results and vulnerability data become graded findings' => function (TestContext $ctx) use ($clientId, $finding): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $now = (int) gmdate('G');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Findings Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => sprintf('%02d:00', ($now + 23) % 24), 'scan_window_end' => sprintf('%02d:00', ($now + 1) % 24), 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $id = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $id . '/authorisations/new', '/clients/' . $id . '/authorisations', [
            'approved_by_name' => 'Lee Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
            'document_ref' => '', 'notes' => '', 'scope' => "203.0.113.160\n203.0.113.161", 'confirm' => '1',
        ]);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$id}")->fetchColumn();
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
        Assert::true($finding($ctx, $id, 'port:203.0.113.160:3389') !== [], 'RDP finding created right after the scan');
        [$code, $out] = $ctx->cli('bin/feeds.php');
        Assert::contains('Findings: refreshed', $out);

        $rdp = $finding($ctx, $id, 'port:203.0.113.160:3389');
        Assert::same(['fail', 'open', 'port'], [$rdp['severity'], $rdp['status'], $rdp['finding_type']]);
        Assert::same('Remote Desktop open to the internet', $rdp['title']);
        $kev = $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001');
        Assert::same('fail', $kev['severity'], 'confirmed known-exploited vulnerability fails');
        Assert::true(str_starts_with($kev['title'], 'Known exploited: CVE-2099-0001'), $kev['title']);
        Assert::same('warn', $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0002')['severity'], 'confirmed high warns');
        Assert::same('warn', $finding($ctx, $id, 'vuln:203.0.113.161:80:CVE-2099-0101')['severity'], 'possible known-exploited warns');
        Assert::same([], $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0003'), 'medium (info) does not become a finding');

        $page = $admin->get('/clients/' . $id)->body;
        Assert::contains('Remote Desktop open to the internet', $page);
        Assert::contains('2 Fail', $page);
        $show = $admin->get('/findings/' . (int) $kev['id'])->body;
        Assert::notContains('<script>alert(1)</script>', $show, 'finding text from feeds is escaped');
        Assert::contains('First seen', $show);
    },
    'triage needs a technician and a note; it is recorded' => function (TestContext $ctx) use ($clientId, $finding, $events): void {
        $id = $clientId($ctx);
        $rdp = $finding($ctx, $id, 'port:203.0.113.160:3389');
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'ftech'")->fetchColumn() === 0) {
            $ctx->createUser('ftech', 'technician', 'Ftech-Pass-0001!');
            $ctx->createUser('fview', 'viewer', 'Fview-Pass-0001!');
        }
        $view = $ctx->login('fview', 'Fview-Pass-0001!');
        $page = $view->get('/findings/' . (int) $rdp['id']);
        Assert::status(200, $page, 'viewers can read findings');
        Assert::notContains('Save decision', $page->body);
        Assert::status(403, $view->post('/findings/' . (int) $rdp['id'] . '/triage', ['_csrf' => $page->csrf(), 'status' => 'accepted', 'note' => 'x']));

        $tech = $ctx->login('ftech', 'Ftech-Pass-0001!');
        $res = $tech->submit('/findings/' . (int) $rdp['id'], '/findings/' . (int) $rdp['id'] . '/triage', ['status' => 'accepted', 'note' => '']);
        Assert::status(422, $res);
        Assert::contains('A note is required', $res->body);
        $res = $tech->submit('/findings/' . (int) $rdp['id'], '/findings/' . (int) $rdp['id'] . '/triage', ['status' => 'resolved', 'note' => 'done']);
        Assert::status(422, $res, 'resolving by hand is not allowed (only checks resolve)');
        Assert::redirect('/findings/' . (int) $rdp['id'], $tech->submit('/findings/' . (int) $rdp['id'], '/findings/' . (int) $rdp['id'] . '/triage',
            ['status' => 'accepted', 'note' => 'Client needs RDP for a supplier until March; VPN migration planned.']));
        $rdp = $finding($ctx, $id, 'port:203.0.113.160:3389');
        Assert::same('accepted', $rdp['status']);
        Assert::same(['opened', 'alerted', 'triaged_accepted'], $events($ctx, (int) $rdp['id']));
        Assert::contains('VPN migration planned', $tech->get('/findings/' . (int) $rdp['id'])->body);
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'finding.triaged' AND target_id = " . (int) $rdp['id'])->fetchColumn() === 1, 'audited');

        App::findingsEngine()->refreshClient($id);
        Assert::same('accepted', $finding($ctx, $id, 'port:203.0.113.160:3389')['status'], 'accepted risk stays accepted while still seen');
    },
    'problems that disappear resolve; when they come back the same finding reopens' => function (TestContext $ctx) use ($clientId, $finding, $events): void {
        $id = $clientId($ctx);
        $svc = "SELECT s.id FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id = {$id} AND a.ip = '203.0.113.160' AND s.port = 3389";
        $ctx->db->exec("UPDATE services SET is_open = 0, closed_at = UTC_TIMESTAMP() WHERE id = ({$svc})");
        App::findingsEngine()->refreshClient($id);
        $rdp = $finding($ctx, $id, 'port:203.0.113.160:3389');
        Assert::same('resolved', $rdp['status']);
        Assert::true($rdp['resolved_at'] !== null, 'resolution date recorded');

        $ctx->db->exec("UPDATE services SET is_open = 1, closed_at = NULL WHERE id = ({$svc})");
        App::findingsEngine()->refreshClient($id);
        $rdp = $finding($ctx, $id, 'port:203.0.113.160:3389');
        Assert::same(['accepted', 1, 1], [$rdp['status'], (int) $rdp['reappeared'], (int) $rdp['reopened_count']], 'back with unchanged evidence: the accepted decision is restored, flagged as reappeared');
        Assert::same(null, $rdp['resolved_at']);
        Assert::same(['opened', 'alerted', 'triaged_accepted', 'resolved', 'reopened'], $events($ctx, (int) $rdp['id']), 'full history kept');
        Assert::contains('earlier decision (accepted) still applies', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$rdp['id']} ORDER BY id DESC LIMIT 1")->fetchColumn());

        // An untriaged finding that comes back is open again.
        $kev = $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001');
        $ctx->db->exec("UPDATE services s JOIN assets a ON a.id = s.asset_id SET s.is_open = 0 WHERE a.client_id = {$id} AND a.ip = '203.0.113.160' AND s.port = 22");
        App::findingsEngine()->refreshClient($id);
        $ctx->db->exec("UPDATE services s JOIN assets a ON a.id = s.asset_id SET s.is_open = 1 WHERE a.client_id = {$id} AND a.ip = '203.0.113.160' AND s.port = 22");
        App::findingsEngine()->refreshClient($id);
        Assert::same(['open', 1], [$finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001')['status'], (int) $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001')['reappeared']]);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('Reappeared', $admin->get('/findings/' . (int) $rdp['id'])->body);

        // A resolved finding can't be triaged.
        $ctx->db->exec("UPDATE services SET is_open = 0 WHERE id = ({$svc})");
        App::findingsEngine()->refreshClient($id);
        $res = $admin->submit('/findings/' . (int) $rdp['id'], '/findings/' . (int) $rdp['id'] . '/triage', ['status' => 'accepted', 'note' => 'n']);
        Assert::status(422, $res);
        $ctx->db->exec("UPDATE services SET is_open = 1 WHERE id = ({$svc})");
        App::findingsEngine()->refreshClient($id);

        // A triage decision clears the "reappeared" flag.
        $kev = $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001');
        $admin->submit('/findings/' . (int) $kev['id'], '/findings/' . (int) $kev['id'] . '/triage', ['status' => 'accepted', 'note' => 'Patch window booked.']);
        Assert::same(0, (int) $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001')['reappeared']);
        $admin->submit('/findings/' . (int) $kev['id'], '/findings/' . (int) $kev['id'] . '/triage', ['status' => 'open', 'note' => 'Undo for the next test.']);
    },
    'vulnerability findings wait while new data is pending; long keys never collide; archived clients are read-only' => function (TestContext $ctx) use ($clientId, $finding): void {
        $id = $clientId($ctx);
        $svcWhere = "a.client_id = {$id} AND a.ip = '203.0.113.160' AND s.port = 22";
        // New version, NVD not asked yet: matches are cleared, but the findings are not resolved.
        $ctx->db->exec("UPDATE services s JOIN assets a ON a.id = s.asset_id SET s.cpe = 'cpe:/a:openbsd:openssh:9.5p1' WHERE {$svcWhere}");
        App::vulnMatcher()->matchClient($id, 0);
        App::findingsEngine()->refreshClient($id);
        Assert::same('open', $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001')['status'], 'not resolved without data');
        $ctx->db->exec("UPDATE services s JOIN assets a ON a.id = s.asset_id SET s.cpe = 'cpe:/a:openbsd:openssh:8.9p1' WHERE {$svcWhere}");
        App::vulnMatcher()->matchClient($id, 0);
        App::findingsEngine()->refreshClient($id);

        // Two issues on an endpoint with a very long hostname (IPv6-style long keys) stay separate.
        $asset = (int) $ctx->db->query("SELECT id FROM assets WHERE client_id = {$id} AND ip = '203.0.113.160'")->fetchColumn();
        $long = str_repeat('a', 60) . '.' . str_repeat('b', 60) . '.' . str_repeat('c', 50) . '.example';
        $ctx->db->exec("INSERT INTO tls_endpoints (asset_id, port, sni, subject_cn, self_signed, chain_trusted, accepts_tls10, key_type, signature_alg, protocol, not_after, first_seen, last_checked)
                        VALUES ({$asset}, 443, '{$long}', 'x', 1, 0, 1, 'RSA', 'sha256', 'TLSv1.2', '2099-01-01 00:00:00', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        App::findingsEngine()->refreshClient($id);
        $keys = $ctx->db->query("SELECT finding_key FROM findings WHERE client_id = {$id} AND finding_type = 'tls' AND target LIKE '%bbbb%'")->fetchAll(PDO::FETCH_COLUMN);
        Assert::same(2, count(array_unique($keys)), 'self-signed and old-TLS findings kept apart');
        foreach ($keys as $k) {
            Assert::true(strlen($k) <= 190, 'key fits the column');
        }

        // Archived clients: findings can be read but not triaged.
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $f = $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0002');
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/archive', ['archive' => '1']);
        Assert::notContains('Save decision', $admin->get('/findings/' . (int) $f['id'])->body);
        $res = $admin->post('/findings/' . (int) $f['id'] . '/triage', ['_csrf' => $admin->get('/findings/' . (int) $f['id'])->csrf(), 'status' => 'accepted', 'note' => 'n']);
        Assert::status(422, $res);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/archive', ['archive' => '0']);
    },
    'a false positive reopens when its evidence changes' => function (TestContext $ctx) use ($clientId, $finding, $events): void {
        $id = $clientId($ctx);
        $key = 'vuln:203.0.113.160:22:CVE-2099-0002';
        $f = $finding($ctx, $id, $key);
        $tech = $ctx->login('ftech', 'Ftech-Pass-0001!');
        $tech->submit('/findings/' . (int) $f['id'], '/findings/' . (int) $f['id'] . '/triage', ['status' => 'false_positive', 'note' => 'Vendor build with the fix applied (ticket TEST-42).']);
        App::findingsEngine()->refreshClient($id);
        Assert::same('false_positive', $finding($ctx, $id, $key)['status'], 'unchanged evidence: stays a false positive');

        // The service now reports another version that NVD also lists as affected.
        $q = 'cpe:2.3:a:openbsd:openssh:9.4p1';
        $ctx->db->exec("INSERT IGNORE INTO cpe_queries (query, status, result_count, fetched_at, last_needed, created_at) VALUES ('{$q}', 'ok', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $ctx->db->exec("INSERT IGNORE INTO cpe_query_cves (query, cve_id) VALUES ('{$q}', 'CVE-2099-0002')");
        $ctx->db->exec("UPDATE services s JOIN assets a ON a.id = s.asset_id SET s.cpe = 'cpe:/a:openbsd:openssh:9.4p1', s.version = '9.4p1' WHERE a.client_id = {$id} AND a.ip = '203.0.113.160' AND s.port = 22");
        App::vulnMatcher()->matchClient($id, 0);
        App::findingsEngine()->refreshClient($id);
        $f = $finding($ctx, $id, $key);
        Assert::same('open', $f['status'], 'evidence changed: reopened');
        Assert::same('evidence_changed', array_slice($events($ctx, (int) $f['id']), -1)[0]);
        Assert::same('resolved', $finding($ctx, $id, 'vuln:203.0.113.160:22:CVE-2099-0001')['status'], 'CVE not listed for the new version: resolved');
    },
    'the all-clients list filters safely; the dashboard counts open findings' => function (TestContext $ctx) use ($clientId): void {
        $id = $clientId($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $all = $admin->get('/findings')->body;
        Assert::contains('Findings Example', $all);
        Assert::contains('Open Fail', $all);
        $fail = $admin->get('/findings?severity=fail&status=all&client=' . $id)->body;
        Assert::contains('Remote Desktop open to the internet', $fail);
        Assert::notContains('CVE-2099-0101', $fail, 'warnings filtered out');
        $fp = $admin->get('/findings?status=false_positive')->body;
        Assert::contains('No findings match', $fp, 'the false positive was reopened, so none are left');
        $resolved = $admin->get('/findings?status=resolved&client=' . $id)->body;
        Assert::contains('CVE-2099-0001', $resolved);
        $evil = $admin->get("/findings?status=open'%20OR%201=1&severity=<script>&type=../x&client=abc");
        Assert::status(200, $evil, 'invalid filter values are ignored');
        Assert::notContains('<script>', $evil->body);
        $dash = $admin->get('/')->body;
        Assert::contains('Open Fail findings', $dash);
        Assert::contains('Open Warning findings', $dash);
    },
];
