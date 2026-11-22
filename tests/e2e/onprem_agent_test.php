<?php

declare(strict_types=1);

/**
 * End-to-end tests for the on-premises agent: a signed internal
 * authorisation, a one-time enrolment code, the real agent program enrolling
 * and running jobs against this test server (fake nmap, mock services
 * through redirects: no packets to real hosts), results turned into devices,
 * services, certificate findings and CVE findings, new-device alerts after
 * the baseline, the kill switch, and the security checks: scope refusals,
 * tampered authorisations, replays, revoked agents. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$agentDir = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent';
$runAgent = static function (TestContext $ctx, array $args) use ($agentDir): array {
    return $ctx->cli('bin/sentinel-agent.php', array_merge($args, ['--config', $agentDir($ctx) . '/agent.json']));
};
$setup = static function (TestContext $ctx) use ($agentDir, $runAgent): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Harbour Example'")->fetchColumn();
    if ($cid > 0) {
        return [$cid, (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn()];
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Harbour Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
        'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-2001', 'notes' => '', 'ranges' => "10.90.0.0/24", 'confirm' => '1']);
    $page = $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body;
    preg_match('/SNE(-[A-Z2-9]{5}){4}/', $page, $m);
    @mkdir($agentDir($ctx), 0700, true);
    [$code, $out] = $runAgent($ctx, ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing']);
    if ($code !== 0) {
        throw new RuntimeException('Agent enrolment failed: ' . $out);
    }
    // Test-only agent settings: the fake nmap and the mock services (honoured only with SENTINEL_TEST_MODE=1).
    $app = require $ctx->configPath;
    $c = json_decode((string) file_get_contents($agentDir($ctx) . '/agent.json'), true);
    $c['nmap_path'] = $app['scanner']['nmap_path'];
    $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $agentDir($ctx) . '/arp'];
    file_put_contents($agentDir($ctx) . '/agent.json', json_encode($c));
    file_put_contents($agentDir($ctx) . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n10.90.0.30       0x1         0x2         02:00:00:00:00:30     *        eth0\n");
    return [$cid, $site];
};
$scanNow = static function (TestContext $ctx, int $cid, int $site): int {
    $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'Test scan']);
    return (int) $ctx->db->query("SELECT MAX(id) FROM agent_jobs WHERE site_id = {$site}")->fetchColumn();
};

return [
    'internal authorisations: private ranges only, signed, admin-only' => function (TestContext $ctx) use ($setup): void {
        [$cid, $site] = $setup($ctx);
        $a = $ctx->db->query("SELECT * FROM internal_authorisations WHERE site_id = {$site}")->fetch();
        Assert::same("10.90.0.0/24", $a['ranges']);
        Assert::true(\Sentinel\Agent\Signer::verify($a['signed_payload'], $a['signature'], App::agentSigner()->publicKey()), 'signed with the server key');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $bad = $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d'), 'valid_until' => gmdate('Y-m-d', time() + 86400),
            'document_ref' => '', 'notes' => '', 'ranges' => "203.0.113.0/24\n10.0.0.0/8", 'confirm' => '1']);
        Assert::status(422, $bad);
        Assert::contains('is not a private (internal) address', $bad->body);
        Assert::contains('is too large', $bad->body);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'agtech'")->fetchColumn() === 0) {
            $ctx->createUser('agtech', 'technician', 'Agtech-Pass-0001!');
        }
        $tech = $ctx->login('agtech', 'Agtech-Pass-0001!');
        Assert::status(403, $tech->get('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new'));
        Assert::status(403, $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', []), 'only admins create enrolment codes');
        Assert::contains('10.90.0.0/24', $admin->get('/clients/' . $cid)->body);
    },
    'enrolment: one-time code, token stored hashed, server key pinned' => function (TestContext $ctx) use ($setup, $agentDir): void {
        [$cid, $site] = $setup($ctx);
        $agent = $ctx->db->query("SELECT * FROM agents WHERE site_id = {$site}")->fetch();
        $config = json_decode((string) file_get_contents($agentDir($ctx) . '/agent.json'), true);
        Assert::same('active', $agent['status']);
        Assert::same(App::agentSigner()->publicKey(), $config['server_public_key'], 'server key pinned');
        Assert::true(!str_contains((string) $agent['token_hash'], (string) $config['token']) && strlen((string) $agent['token_hash']) === 64, 'only a hash is stored');
        Assert::same('600', substr(sprintf('%o', fileperms($agentDir($ctx) . '/agent.json')), -3), 'config readable by the agent only');
        $used = (string) $ctx->db->query("SELECT COUNT(*) FROM agent_enrolments WHERE used_at IS NOT NULL AND agent_id = {$agent['id']}")->fetchColumn();
        Assert::same('1', $used);
        $res = $ctx->api('POST', '/agent/v1/enrol', null, ['code' => 'SNE-AAAAA-BBBBB-CCCCC-DDDDD']);
        Assert::status(403, $res, 'unknown code refused');
        Assert::status(401, $ctx->api('POST', '/agent/v1/poll', null, ['running' => []]), 'no token');
        Assert::status(401, $ctx->api('POST', '/agent/v1/poll', 'sna_000000000000_' . str_repeat('A', 43), ['running' => []]), 'wrong token');
    },
    'a full scan by the real agent: devices, services, certificates, CVEs; baseline without alerts' => function (TestContext $ctx) use ($setup, $runAgent, $scanNow, $agentDir): void {
        [$cid, $site] = $setup($ctx);
        // 10.90.0.30 is off the network for the first scan (it appears later as a new device).
        file_put_contents(dirname($ctx->nmapLog) . '/nmap-down.json', json_encode(['10.90.0.30']));
        file_put_contents($ctx->nmapLog, '');
        $job = $scanNow($ctx, $cid, $site);
        [$code, $out] = $runAgent($ctx, ['run', '--once']);
        Assert::same(0, $code, 'agent ran: ' . $out);
        Assert::same('done', (string) $ctx->db->query("SELECT status FROM agent_jobs WHERE id = {$job}")->fetchColumn(), 'job done: ' . $out);
        $calls = array_map(static fn (string $l): array => json_decode($l, true), array_values(array_filter(explode("\n", (string) file_get_contents($ctx->nmapLog)))));
        Assert::same('10.90.0.0/24', end($calls[0]), 'discovery of exactly the signed range');
        Assert::true(in_array('-sn', $calls[0], true), 'discovery sweep first');
        foreach (array_slice($calls, 1) as $c) {
            Assert::true(in_array(end($c), ['10.90.0.10', '10.90.0.20'], true), 'port scans only on devices found: ' . end($c));
        }
        $devices = $ctx->db->query("SELECT source_id, name, mac FROM devices WHERE client_id = {$cid} AND source = 'agent' AND removed_at IS NULL ORDER BY source_id")->fetchAll(PDO::FETCH_UNIQUE);
        Assert::same([$site . ':10.90.0.10', $site . ':10.90.0.20'], array_keys($devices));
        Assert::same('02:00:00:00:00:10', $devices[$site . ':10.90.0.10']['mac']);
        $dev = (int) $ctx->db->query("SELECT id FROM devices WHERE source_id = '{$site}:10.90.0.10'")->fetchColumn();
        Assert::same([22, 443], array_map('intval', $ctx->db->query("SELECT port FROM device_ports WHERE device_id = {$dev} ORDER BY port")->fetchAll(PDO::FETCH_COLUMN)));
        Assert::same(1, (int) $ctx->db->query("SELECT distro FROM device_software WHERE device_id = {$dev} AND cpe LIKE 'cpe:/a:openbsd:openssh%'")->fetchColumn(), 'Ubuntu build: distro');
        // Certificate problems that matter inside a network: weak key and old TLS (self-signed is normal inside).
        $tls = $ctx->db->query("SELECT finding_key, severity FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'dport:%'")->fetchAll(PDO::FETCH_KEY_PAIR);
        Assert::same('warn', $tls["dport:agent:{$site}:10.90.0.10:443:cert_weak_key"] ?? null, 'weak key: ' . json_encode($tls));
        Assert::same('warn', $tls["dport:agent:{$site}:10.90.0.10:443:tls_old_protocol"] ?? null);
        Assert::true(!isset($tls["dport:agent:{$site}:10.90.0.10:443:cert_self_signed"]), 'self-signed is not a finding inside');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE kind = 'new_device'")->fetchColumn(), 'first scan is the baseline');
        Assert::contains('starting point', (string) $ctx->db->query("SELECT summary FROM agent_jobs WHERE id = {$job}")->fetchColumn());
        Assert::contains('Example NAS Login', (string) $ctx->db->query("SELECT web FROM device_ports WHERE device_id = {$dev} AND port = 443")->fetchColumn());
        Assert::contains("10.90.0.10", $ctx->login('admin', 'Admin-Pass-0001!')->get('/clients/' . $cid)->body);
    },
    'a light sweep finds a new device and alerts; replays and other jobs are refused' => function (TestContext $ctx) use ($setup, $runAgent, $agentDir): void {
        [$cid, $site] = $setup($ctx);
        @unlink(dirname($ctx->nmapLog) . '/nmap-down.json');
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        $auth = (int) $ctx->db->query("SELECT id FROM internal_authorisations WHERE site_id = {$site}")->fetchColumn();
        $job = App::agents()->queueJob($agentId, $cid, $site, $auth, 'light', 'scheduled', null, [], 12);
        [$code, $out] = $runAgent($ctx, ['run', '--once']);
        Assert::same('done', (string) $ctx->db->query("SELECT status FROM agent_jobs WHERE id = {$job}")->fetchColumn(), 'light job: ' . $out);
        $note = $ctx->db->query("SELECT title, body FROM notifications WHERE kind = 'new_device' ORDER BY id DESC LIMIT 1")->fetch();
        Assert::true($note !== false && str_contains($note['title'], '1 new device(s)') && str_contains($note['body'], '10.90.0.30'), 'new device alert');
        Assert::contains('02:00:00:00:00:30', (string) $note['body'], 'MAC from the agent\'s ARP table');
        // The same job handed out again (replay) is refused by the agent.
        $ctx->db->exec("UPDATE agent_jobs SET status = 'sent' WHERE id = {$job}");
        [$code, $out] = $runAgent($ctx, ['run', '--once']);
        Assert::contains('replay', $out, 'replay refused');
        $ctx->db->exec("UPDATE agent_jobs SET status = 'done' WHERE id = {$job}");
    },
    'scope is enforced by server and agent: out-of-range results, tampered authorisations, forged jobs' => function (TestContext $ctx) use ($setup, $agentDir): void {
        [$cid, $site] = $setup($ctx);
        $config = json_decode((string) file_get_contents($agentDir($ctx) . '/agent.json'), true);
        $agentId = (int) $config['agent_id'];
        $auth = (int) $ctx->db->query("SELECT id FROM internal_authorisations WHERE site_id = {$site}")->fetchColumn();
        // Results for an address outside the authorisation are dropped by the server.
        $job = App::agents()->queueJob($agentId, $cid, $site, $auth, 'light', 'manual', null, [], 12);
        $res = $ctx->api('POST', '/agent/v1/jobs/' . $job . '/results', $config['token'], ['status' => 'done', 'hosts' => [['ip' => '10.91.0.5'], ['ip' => '8.8.8.8'], ['ip' => '10.90.0.20']]]);
        Assert::status(200, $res);
        Assert::same(2, json_decode($res->body, true)['rejected'] ?? null);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE source_id LIKE '%10.91.0.5'")->fetchColumn(), 'nothing stored outside scope');
        // A tampered authorisation (ranges changed in the database, signature not) is never used.
        $ctx->db->exec("UPDATE internal_authorisations SET signed_payload = REPLACE(signed_payload, '10.90.0.0/24', '10.91.0.0/24') WHERE id = {$auth}");
        $job2 = App::agents()->queueJob($agentId, $cid, $site, $auth, 'light', 'manual', null, [], 12);
        $poll = json_decode($ctx->api('POST', '/agent/v1/poll', $config['token'], ['running' => []])->body, true);
        Assert::same([], $poll['jobs'], 'no job handed out');
        Assert::same('cancelled', (string) $ctx->db->query("SELECT status FROM agent_jobs WHERE id = {$job2}")->fetchColumn());
        $ctx->db->exec("UPDATE internal_authorisations SET signed_payload = REPLACE(signed_payload, '10.91.0.0/24', '10.90.0.0/24') WHERE id = {$auth}");
        // The agent refuses jobs signed by another key, for other agents, or with targets outside the signed ranges.
        $v = new \Sentinel\AgentClient\JobVerifier($config['server_public_key'], $agentId);
        $signer = App::agentSigner();
        $a = $ctx->db->query("SELECT signed_payload, signature FROM internal_authorisations WHERE id = {$auth}")->fetch();
        $base = ['v' => 1, 'type' => 'agent_job', 'job_id' => 999001, 'agent_id' => $agentId, 'site_id' => $site, 'kind' => 'light', 'ports' => [], 'targets' => ['10.90.0.0/24'],
                 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600), 'authorisation' => ['payload' => $a['signed_payload'], 'signature' => $a['signature']]];
        $ok = $signer->sign($base);
        Assert::true(is_array($v->verify($ok['payload'], $ok['signature'], [])), 'a correct job is accepted');
        $other = \Sentinel\Agent\Signer::fromAppKey(random_bytes(32))->sign($base);
        Assert::same('bad signature', $v->verify($other['payload'], $other['signature'], []));
        $wide = $signer->sign(['targets' => ['10.90.0.0/16']] + $base);
        Assert::same('targets outside the signed authorisation', $v->verify($wide['payload'], $wide['signature'], []));
        $forOther = $signer->sign(['agent_id' => $agentId + 1] + $base);
        Assert::same('job is for another agent', $v->verify($forOther['payload'], $forOther['signature'], []));
        $old = $signer->sign(['expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() - 60)] + $base);
        Assert::same('job expired', $v->verify($old['payload'], $old['signature'], []));
        $fakeAuth = \Sentinel\Agent\Signer::fromAppKey(random_bytes(32))->sign(json_decode($a['signed_payload'], true));
        $forged = $signer->sign(['authorisation' => $fakeAuth] + $base);
        Assert::same('authorisation not signed by the server', $v->verify($forged['payload'], $forged['signature'], []));
    },
    'kill switch and revocation stop the agent' => function (TestContext $ctx) use ($setup, $agentDir, $runAgent): void {
        [$cid, $site] = $setup($ctx);
        $config = json_decode((string) file_get_contents($agentDir($ctx) . '/agent.json'), true);
        $tech = $ctx->login('agtech', 'Agtech-Pass-0001!');
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/pause', []);
        $poll = json_decode($ctx->api('POST', '/agent/v1/poll', $config['token'], ['running' => [12345]])->body, true);
        Assert::true($poll['paused'] === true && in_array(12345, $poll['stop'], true), 'paused: running jobs told to stop');
        Assert::status(403, $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/resume', []), 'only admins resume');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/resume', []);
        $agentId = (int) $config['agent_id'];
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/agents/' . $agentId . '/revoke', []);
        Assert::status(401, $ctx->api('POST', '/agent/v1/poll', $config['token'], ['running' => []]), 'revoked token refused');
        [$code, $out] = $runAgent($ctx, ['run', '--once']);
        Assert::contains('no longer accepts this agent', $out);
        Assert::contains('agent.revoked', (string) $ctx->db->query("SELECT GROUP_CONCAT(action) FROM audit_log")->fetchColumn());
    },
];
