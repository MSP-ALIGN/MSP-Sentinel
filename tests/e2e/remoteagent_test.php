<?php

declare(strict_types=1);

/**
 * End-to-end tests for agent settings managed from the web UI: scan gentleness per site (signed into jobs, used for
 * nmap's timing), the check-in interval, a diagnostics report, and a restart, with the real agent program against this
 * test server (fake nmap; nothing real is contacted). Made-up data only.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$setDir = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent-settings';
$setRun = static fn (TestContext $ctx): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $setDir($ctx) . '/agent.json']);
$setSetup = static function (TestContext $ctx) use ($setDir): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Settings Example'")->fetchColumn();
    if ($cid > 0) {
        return [$cid, (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn()];
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Settings Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
        'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-4001', 'notes' => '', 'ranges' => '10.91.0.0/24', 'confirm' => '1']);
    $page = $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body;
    preg_match('/SNE(-[A-Z2-9]{5}){4}/', $page, $m);
    @mkdir($setDir($ctx), 0700, true);
    [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $setDir($ctx) . '/agent.json']);
    if ($code !== 0) {
        throw new RuntimeException('Agent enrolment failed: ' . $out);
    }
    $app = require $ctx->configPath;
    $c = json_decode((string) file_get_contents($setDir($ctx) . '/agent.json'), true);
    $c['nmap_path'] = $app['testing']['agent_nmap_path']; // accepts the agents' other timing profiles
    $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $setDir($ctx) . '/arp'];
    file_put_contents($setDir($ctx) . '/agent.json', json_encode($c));
    file_put_contents($setDir($ctx) . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n");
    return [$cid, $site];
};

return [
    'agent settings: gentleness per site is signed into jobs and used for nmap; the check-in interval follows' => function (TestContext $ctx) use ($setSetup, $setRun, $setDir): void {
        [$cid, $site] = $setSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $ctx->clientSection($admin, $cid, 'agents');
        Assert::contains('Scan gentleness', $page);
        Assert::contains('Gentle (nmap polite timing -T2; default)', $page);
        // Only the offered values; admins only.
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/agent-settings', ['timing' => 'insane', 'poll_seconds' => '60']);
        Assert::contains('Choose one of the offered settings', $ctx->clientSection($admin, $cid, 'agents'));
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/agent-settings', ['timing' => 'normal', 'poll_seconds' => '7']);
        Assert::contains('Choose one of the offered settings', $ctx->clientSection($admin, $cid, 'agents'));
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'settech'")->fetchColumn() === 0) {
            $ctx->createUser('settech', 'technician', 'Settech-Pass-0001!');
        }
        $tech = $ctx->login('settech', 'Settech-Pass-0001!');
        Assert::status(403, $tech->post('/clients/' . $cid . '/sites/' . $site . '/agent-settings', ['_csrf' => $tech->get('/')->csrf(), 'timing' => 'normal', 'poll_seconds' => '60']));
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/sites/' . $site . '/agent-settings', ['timing' => 'very_gentle', 'poll_seconds' => '300']);
        Assert::same(['very_gentle', 300], array_values(array_map(static fn ($v) => is_numeric($v) ? (int) $v : $v,
            $ctx->db->query("SELECT agent_timing, agent_poll_seconds FROM sites WHERE id = {$site}")->fetch(PDO::FETCH_NUM))));
        Assert::contains('site.agent_settings', implode("\n", $ctx->db->query('SELECT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)));
        // The check-in answer carries the interval.
        $c = json_decode((string) file_get_contents($setDir($ctx) . '/agent.json'), true);
        $answer = (string) @file_get_contents($ctx->baseUrl . '/agent/v1/poll', false, stream_context_create(['http' => ['method' => 'POST',
            'header' => "Authorization: Bearer {$c['token']}\r\nContent-Type: application/json\r\n", 'content' => '{}', 'ignore_errors' => true]]));
        Assert::same(300, json_decode($answer, true)['poll_seconds'] ?? null);
        // A scan uses the site's timing (the signed job says very_gentle: one probe at a time, at most 10 a second).
        $before = count(@file($ctx->nmapLog) ?: []);
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'Timing test']);
        [$code, $out] = $setRun($ctx);
        Assert::same(0, $code, 'agent ran: ' . $out);
        $calls = array_slice(file($ctx->nmapLog, FILE_IGNORE_NEW_LINES) ?: [], $before);
        Assert::true($calls !== [], 'nmap ran');
        foreach ($calls as $line) {
            $args = json_decode($line, true);
            $t = array_search('--max-parallelism', $args, true);
            Assert::true($t !== false && $args[$t + 1] === '1' && $args[$t - 1] === '10' && in_array('-T2', $args, true), 'very gentle timing on every nmap call: ' . $line);
        }
    },
    'agent settings: diagnostics on request, and a restart between scans' => function (TestContext $ctx) use ($setSetup, $setRun, $setDir): void {
        [$cid, $site] = $setSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agentId . '/diagnostics', []);
        Assert::contains('diagnostics requested', $ctx->clientSection($admin, $cid, 'agents'));
        // The status command checks in too, but must not take the request meant for the running agent.
        $ctx->cli('bin/sentinel-agent.php', ['status', '--config', $setDir($ctx) . '/agent.json']);
        Assert::same(1, (int) $ctx->db->query("SELECT diagnostics_requested FROM agents WHERE id = {$agentId}")->fetchColumn(), 'still waiting');
        [$code, $out] = $setRun($ctx);
        Assert::contains('Diagnostics sent', $out);
        $d = json_decode((string) $ctx->db->query("SELECT diagnostics FROM agents WHERE id = {$agentId}")->fetchColumn(), true);
        Assert::same(PHP_VERSION, $d['php']);
        Assert::true($d['version'] !== '' && $d['key_fingerprint'] !== '' && is_int($d['disk_free_mb']) && abs((int) $d['clock_skew_seconds']) < 30, 'a full report');
        Assert::notContains('token', json_encode($d), 'no secrets in it');
        $page = $ctx->clientSection($admin, $cid, 'agents');
        Assert::contains('Diagnostics reported by the agent', $page);
        Assert::contains(PHP_VERSION, $page);
        // Restart with a scan queued: the restart goes out alone (the scan stays queued, not lost), then the scan runs.
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'Before restart']);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM agent_jobs WHERE site_id = {$site}")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agentId . '/restart', []);
        [$code, $out] = $setRun($ctx);
        Assert::same(75, $code, 'exits for a restart');
        Assert::contains('asked for a restart', $out);
        Assert::same('queued', $ctx->db->query("SELECT status FROM agent_jobs WHERE id = {$job}")->fetchColumn(), 'the scan was not handed out with the restart');
        [$code, $out] = $setRun($ctx);
        Assert::same(0, $code, 'asked once only');
        Assert::true(in_array($ctx->db->query("SELECT status FROM agent_jobs WHERE id = {$job}")->fetchColumn(), ['done', 'partial'], true), 'then the scan ran');
        Assert::status(404, $admin->post('/clients/' . $cid . '/agents/999999/restart', ['_csrf' => $admin->get('/')->csrf()]));
    },
];
