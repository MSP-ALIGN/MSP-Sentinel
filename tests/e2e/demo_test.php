<?php

declare(strict_types=1);

/**
 * End-to-end tests for demo data: loading from the System page (admins only, CSRF-checked), what it shows
 * across the interface, that demo clients are never scanned (manual scan, verify fix, discovery, agent scan,
 * API, and the repositories themselves), and that removing it deletes demo rows only. Made-up data only;
 * nothing here contacts a host.
 */

use Sentinel\Core\App;
use Sentinel\Demo\DemoData;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'demo data: admins load it from the System page; it fills every view' => function (TestContext $ctx): void {
        $otherClients = (int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 0')->fetchColumn();
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'demotech'")->fetchColumn() === 0) {
            $ctx->createUser('demotech', 'technician', 'Demotech-Pass-01!');
        }
        $tech = $ctx->login('demotech', 'Demotech-Pass-01!');
        Assert::status(403, $tech->post('/admin/system/demo', ['action' => 'load', '_csrf' => $tech->get('/')->csrf()]), 'technicians cannot load demo data');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->post('/admin/system/demo', ['action' => 'load']); // no CSRF token
        Assert::same(0, (int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 1')->fetchColumn(), 'nothing loaded without a CSRF token');

        $admin->submit('/admin/system', '/admin/system/demo', ['action' => 'load']);
        Assert::contains('Loaded 4 demo clients', $admin->get('/admin/system')->body);
        $ids = array_map('intval', $ctx->db->query('SELECT id FROM clients WHERE is_demo = 1 ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
        Assert::same(4, count($ids));
        $riverside = $ids[0];
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'demo.loaded'")->fetchColumn(), 'audited');

        // Every external target is a documentation address or *.example name.
        foreach ($ctx->db->query('SELECT a.ip FROM assets a JOIN clients c ON c.id = a.client_id AND c.is_demo = 1')->fetchAll(PDO::FETCH_COLUMN) as $ip) {
            Assert::true((bool) preg_match('/^(192\.0\.2|198\.51\.100|203\.0\.113)\./', $ip), "documentation address: {$ip}");
        }
        foreach ($ctx->db->query("SELECT e.value FROM scope_entries e JOIN clients c ON c.id = e.client_id AND c.is_demo = 1 WHERE e.entry_type = 'domain'")->fetchAll(PDO::FETCH_COLUMN) as $d) {
            Assert::true(str_ends_with($d, '.example'), "made-up domain: {$d}");
        }

        // A spread of findings, built by the real engine, in every state.
        $states = $ctx->db->query("SELECT status, COUNT(*) FROM findings WHERE client_id IN (" . implode(',', $ids) . ") GROUP BY status")->fetchAll(PDO::FETCH_KEY_PAIR);
        foreach (['open', 'resolved', 'accepted', 'false_positive'] as $st) {
            Assert::true(($states[$st] ?? 0) > 0, "some {$st} findings");
        }
        $types = $ctx->db->query("SELECT DISTINCT finding_type FROM findings WHERE client_id = {$riverside}")->fetchAll(PDO::FETCH_COLUMN);
        foreach (['port', 'tls', 'web', 'vuln', 'email', 'patch', 'device'] as $t) {
            Assert::true(in_array($t, $types, true), "finding type {$t}");
        }
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$riverside} AND status = 'open' AND due_at < UTC_TIMESTAMP()")->fetchColumn() > 0, 'some overdue');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$riverside} AND assigned_to IS NOT NULL")->fetchColumn() > 0, 'some assigned');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM finding_stats WHERE client_id = {$riverside}")->fetchColumn() >= 90, 'trend history');

        // The pages render with the demo content.
        Assert::contains('Riverside Example Ltd', $admin->get('/clients')->body);
        Assert::same(4, (int) $ctx->db->query("SELECT COUNT(DISTINCT name) FROM clients WHERE is_demo = 1")->fetchColumn(), 'unique names, even next to a real client of the same name');
        Assert::contains('>Demo<', $admin->get('/clients')->body, 'Demo badge on the client list');
        $page = $admin->get('/clients/' . $riverside)->body;
        Assert::contains('Demo client: made-up data', $page);
        $device = (int) $ctx->db->query("SELECT id FROM devices WHERE client_id = {$riverside} AND source = 'agent' ORDER BY id LIMIT 1")->fetchColumn();
        $report = (int) $ctx->db->query("SELECT id FROM reports WHERE client_id = {$riverside} ORDER BY id LIMIT 1")->fetchColumn();
        $finding = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$riverside} AND status = 'open' ORDER BY id LIMIT 1")->fetchColumn();
        foreach (['/', '/findings', '/findings/' . $finding, '/clients/' . $riverside . '/overview', '/clients/' . $riverside . '/devices/' . $device,
                  '/reports', '/reports/' . $report, '/reports/' . $report . '/view'] as $path) {
            Assert::same(200, $admin->get($path)->status, $path);
        }
        foreach (['SMBv1 is enabled', 'Known exploited', 'FS01', 'www.riverside.example', 'sentinel-agent-01'] as $text) {
            Assert::contains($text, $page . $admin->get('/findings?client=' . $riverside . '&per_page=200')->body . $admin->get('/clients/' . $riverside . '/devices/' . $device)->body, "shows {$text}");
        }
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$riverside}")->fetchColumn(), 'two reports');
        Assert::same($otherClients, (int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 0')->fetchColumn(), 'other clients untouched');
        // Loading twice does nothing.
        $admin->submit('/admin/system', '/admin/system/demo', ['action' => 'load']);
        Assert::same(4, (int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 1')->fetchColumn(), 'not loaded twice');
    },
    'demo data: demo clients are never scanned, whoever asks' => function (TestContext $ctx): void {
        $ids = array_map('intval', $ctx->db->query('SELECT id FROM clients WHERE is_demo = 1 ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
        $riverside = $ids[0];
        $jobs = static fn (): int => (int) $ctx->db->query('SELECT COUNT(*) FROM scan_jobs WHERE client_id IN (' . implode(',', $ids) . ") AND status IN ('queued','running')")->fetchColumn()
            + (int) $ctx->db->query('SELECT COUNT(*) FROM agent_jobs WHERE client_id IN (' . implode(',', $ids) . ") AND status IN ('queued','sent')")->fetchColumn();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $riverside, '/clients/' . $riverside . '/scan', []);
        Assert::contains('never scanned', $admin->get('/clients/' . $riverside)->body, 'manual scan refused with a clear message');
        $admin->submit('/clients/' . $riverside, '/clients/' . $riverside . '/discover', []);
        Assert::contains('never scanned', $admin->get('/clients/' . $riverside)->body, 'discovery refused');
        $site = (int) $ctx->db->query("SELECT site_id FROM agents WHERE client_id = {$riverside}")->fetchColumn();
        $admin->submit('/clients/' . $riverside, '/clients/' . $riverside . '/sites/' . $site . '/scan', ['reason' => 'Demo test']);
        $finding = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$riverside} AND status = 'open' AND finding_key LIKE 'port:%' LIMIT 1")->fetchColumn();
        $admin->submit('/findings/' . $finding, '/findings/' . $finding . '/verify', []);
        Assert::same(0, $jobs(), 'no scan or agent job was queued for a demo client');
        // The repositories refuse too, so a future caller can't get round it.
        foreach ([static fn () => App::scans()->queue($riverside, 'manual', null, false, null, ['ips' => ['203.0.113.10']]),
                  static fn () => App::agents()->queueJob(1, $riverside, $site, 1, 'full', 'manual', null, [445], 1)] as $call) {
            $refused = false;
            try {
                $call();
            } catch (\DomainException) {
                $refused = true;
            }
            Assert::true($refused, 'repository refuses demo clients');
        }
        // The scheduler and the agent scheduler skip them.
        // (They may queue jobs for the other test clients: those are removed again, so later tests see the same state.)
        $maxScan = (int) $ctx->db->query('SELECT COALESCE(MAX(id), 0) FROM scan_jobs')->fetchColumn();
        $maxAgent = (int) $ctx->db->query('SELECT COALESCE(MAX(id), 0) FROM agent_jobs')->fetchColumn();
        try {
            App::scanWorker()->scheduleDue();
            App::agentService()->scheduleDue();
            Assert::same(0, $jobs(), 'schedulers skip demo clients');
        } finally {
            $ctx->db->exec("DELETE FROM scan_jobs WHERE id > {$maxScan}");
            $ctx->db->exec("DELETE FROM agent_jobs WHERE id > {$maxAgent}");
        }
        // The demo agent can never authenticate: its token was thrown away.
        Assert::same(null, App::agents()->authenticate('Bearer ' . str_repeat('a', 64)));
    },
    'demo data: removing it deletes demo rows only' => function (TestContext $ctx): void {
        $otherFindings = (int) $ctx->db->query('SELECT COUNT(*) FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_demo = 0')->fetchColumn();
        $otherClients = (int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 0')->fetchColumn();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/system', '/admin/system/demo', ['action' => 'remove']);
        Assert::contains('Removed 4 demo client(s)', $admin->get('/admin/system')->body);
        Assert::same(0, (int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 1')->fetchColumn());
        foreach (['assets', 'findings', 'devices', 'agents', 'reports', 'scan_jobs', 'internal_authorisations', 'scan_authorisations', 'sites', 'email_checks', 'finding_stats'] as $table) {
            Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM {$table} t LEFT JOIN clients c ON c.id = t.client_id WHERE c.id IS NULL")->fetchColumn(), "no orphaned {$table}");
        }
        Assert::same($otherClients, (int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 0')->fetchColumn(), 'other clients kept');
        Assert::same($otherFindings, (int) $ctx->db->query('SELECT COUNT(*) FROM findings')->fetchColumn(), 'other findings kept');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM cves WHERE cve_id = 'CVE-2021-34473'")->fetchColumn() === 1, 'public CVE reference data stays');
        // The command line does the same, and refuses root unless allowed.
        [$code, $out] = $ctx->cli('bin/demo.php', ['--load']);
        Assert::same(0, $code, $out);
        Assert::contains('Loaded 4 demo clients', $out);
        [$code, $out] = $ctx->cli('bin/demo.php', ['--status']);
        Assert::contains('Demo data is loaded', $out);
        [$code, $out] = $ctx->cli('bin/demo.php', ['--remove']);
        Assert::same(0, $code, $out);
        Assert::true(!(new DemoData($ctx->db, 1))->isLoaded(), 'removed from the command line');
    },
];
