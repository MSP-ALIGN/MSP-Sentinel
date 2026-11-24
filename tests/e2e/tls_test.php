<?php

declare(strict_types=1);

/**
 * End-to-end tests: certificate and web page checks after a port scan and in
 * the daily job, against local mock TLS/HTTP servers with throwaway test
 * certificates. Documentation addresses and *.example names only.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'a port scan checks certificates and web pages on the open ports' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $now = (int) gmdate('G');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'TLS Check Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => sprintf('%02d:00', ($now + 23) % 24), 'scan_window_end' => sprintf('%02d:00', ($now + 1) % 24), 'notes' => '',
            'ports_extra' => '', 'ports_excluded' => '']);
        $id = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $id . '/authorisations/new', '/clients/' . $id . '/authorisations', [
            'approved_by_name' => 'Kim Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
            'document_ref' => '', 'notes' => '', 'confirm' => '1',
            'scope' => "203.0.113.180\n203.0.113.181\n203.0.113.182\nportal.tlscheck.example",
        ]);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $jobId = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$id}")->fetchColumn();
        [$code, $out] = $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $jobId]);
        Assert::same('done', $ctx->db->query("SELECT status FROM scan_jobs WHERE id = {$jobId}")->fetchColumn(), $out);

        $tls = [];
        foreach ($ctx->db->query("SELECT a.ip, t.* FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id WHERE a.client_id = {$id}")->fetchAll() as $row) {
            $tls[$row['ip'] . ':' . $row['port']] = $row;
        }
        $good = $tls['203.0.113.180:443'];
        Assert::same('vpn.tlscheck.example', $good['subject_cn']);
        Assert::same(1, (int) $good['chain_trusted'], 'signed by the (test) trusted CA');
        Assert::same(0, (int) $good['self_signed']);
        Assert::same(0, (int) $good['accepts_tls10'], 'modern server refuses TLS 1.0');
        Assert::same(null, $good['hostname_match'], 'scanned by IP: no name to compare');
        Assert::true(str_starts_with((string) $good['protocol'], 'TLSv1.'), 'negotiated protocol recorded');

        $weak = $tls['203.0.113.181:443'];
        Assert::same(1, (int) $weak['self_signed']);
        Assert::same(1, (int) $weak['accepts_tls10'], 'legacy server accepts TLS 1.0');
        Assert::same(1024, (int) $weak['key_bits'], 'weak 1024-bit certificate could still be read');

        $named = $tls['203.0.113.182:8443'];
        Assert::same('portal.tlscheck.example', $named['sni'], 'in-scope hostname sent as SNI');
        Assert::same(0, (int) $named['hostname_match'], 'certificate is for another name');

        $web = $ctx->db->query("SELECT CONCAT(a.ip, ':', w.port) AS k, w.category FROM web_pages w JOIN assets a ON a.id = w.asset_id WHERE a.client_id = {$id}")->fetchAll(PDO::FETCH_KEY_PAIR);
        ksort($web);
        Assert::same(['203.0.113.180:443' => 'vpn_portal', '203.0.113.180:80' => null, '203.0.113.181:443' => 'firewall_admin', '203.0.113.182:8443' => 'device_admin'], $web);

        $page = $ctx->clientPages($admin, (int) $id);
        foreach (['Self-signed certificate', 'Still accepts TLS 1.0', 'Weak key (RSA 1024 bits)', 'Certificate expires in', 'Certificate does not match the name portal.tlscheck.example',
                  'Firewall admin page reachable from the internet', 'VPN login portal exposed', 'Device management page reachable', 'Welcome to Example Co'] as $text) {
            Assert::contains($text, $page);
        }
        Assert::contains('Certs ≤ 14 days', $admin->get('/')->body);
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM scan_log WHERE job_id = {$jobId} AND result = 'checked'")->fetchColumn() === 3, 'endpoint checks logged per host');
    },
    'the daily job re-checks known endpoints and skips anything out of scope' => function (TestContext $ctx): void {
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'TLS Check Example'")->fetchColumn();
        $ctx->db->exec("UPDATE tls_endpoints SET last_checked = '2026-01-01 00:00:00' WHERE asset_id IN (SELECT id FROM assets WHERE client_id = {$id})");
        // Make the weekly port scan "recent" (so the daily TLS job is what gets scheduled) and silence other clients.
        $ctx->db->exec("UPDATE scan_jobs SET status = 'cancelled' WHERE status IN ('queued','running')");
        $ctx->db->exec("UPDATE scan_jobs SET trigger_type = 'scheduled', created_at = UTC_TIMESTAMP() - INTERVAL 2 DAY WHERE client_id = {$id}");
        $ctx->db->exec("UPDATE clients SET scanning_paused = 1 WHERE id <> {$id}");
        try {
            // Outside the window the daily job is not queued (so it can't block a manual scan for days).
            $ctx->db->exec(sprintf("UPDATE clients SET scan_window_start = '%02d:00:00', scan_window_end = '%02d:00:00' WHERE id = %d", ((int) gmdate('G') + 2) % 24, ((int) gmdate('G') + 3) % 24, $id));
            $ctx->cli('bin/worker.php');
            Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$id} AND job_type = 'tls'")->fetchColumn(), 'not queued outside the window');
            $ctx->db->exec(sprintf("UPDATE clients SET scan_window_start = '%02d:00:00', scan_window_end = '%02d:00:00' WHERE id = %d", ((int) gmdate('G') + 23) % 24, ((int) gmdate('G') + 1) % 24, $id));
            // A stale row for a name no longer used on this endpoint is removed by the next check.
            $asset = (int) $ctx->db->query("SELECT id FROM assets WHERE client_id = {$id} AND ip = '203.0.113.182'")->fetchColumn();
            $ctx->db->exec("INSERT INTO tls_endpoints (asset_id, port, sni, not_after, first_seen, last_checked) VALUES ({$asset}, 8443, '', '2020-01-01 00:00:00', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
            $ctx->cli('bin/worker.php');
            $tlsJob = $ctx->db->query("SELECT * FROM scan_jobs WHERE client_id = {$id} AND job_type = 'tls' ORDER BY id DESC LIMIT 1")->fetch();
            Assert::true($tlsJob !== false, 'daily TLS job queued');
            if ($tlsJob['status'] === 'queued') {
                $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $tlsJob['id']]);
            }
            Assert::same('done', $ctx->db->query("SELECT status FROM scan_jobs WHERE id = {$tlsJob['id']}")->fetchColumn());
            Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id WHERE a.client_id = {$id} AND t.last_checked < '2026-02-01'")->fetchColumn(), 'all re-checked');
            Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM tls_endpoints WHERE asset_id = {$asset} AND sni = ''")->fetchColumn(), 'stale name-less row pruned');

            // A manual port scan replaces a queued daily certificate job instead of being blocked by it.
            \Sentinel\Core\App::scans()->queue($id, 'scheduled', null, false, null, ['endpoints' => []], 'tls');
            $admin = $ctx->login('admin', 'Admin-Pass-0001!');
            $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
            Assert::same('ports', $ctx->db->query("SELECT job_type FROM scan_jobs WHERE client_id = {$id} AND status = 'queued'")->fetchColumn(), 'port scan queued, TLS job cancelled');
            $ctx->db->exec("UPDATE scan_jobs SET status = 'cancelled' WHERE client_id = {$id} AND status = 'queued'");

            // A TLS job naming an address outside the scope never connects to it.
            $jid = \Sentinel\Core\App::scans()->queue($id, 'manual', null, true, 'test', ['endpoints' => [['ip' => '203.0.113.199', 'port' => 443, 'service' => 'https', 'hostnames' => []]]], 'tls');
            $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $jid]);
            Assert::same('skipped_out_of_scope', $ctx->db->query("SELECT result FROM scan_log WHERE job_id = {$jid}")->fetchColumn());
            Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM assets WHERE ip = '203.0.113.199'")->fetchColumn());
        } finally {
            $ctx->db->exec("UPDATE clients SET scanning_paused = 0");
        }
    },
];
