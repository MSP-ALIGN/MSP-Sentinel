<?php

declare(strict_types=1);

/**
 * End-to-end test for the agent's risky-protocol checks: the real agent scans
 * a made-up internal network through mock SMB, RDP, SNMP, Telnet/FTP and web
 * servers (127.0.0.1 only), and Sentinel grades a badly configured device and
 * a well configured one. No real host is contacted.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'risky protocols are found on a badly configured device and not on a good one' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Quay Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid}")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Ash Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d'), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 30),
            'document_ref' => '', 'notes' => '', 'ranges' => '10.92.0.0/24', 'confirm' => '1']);
        preg_match('/SNE(-[A-Z2-9]{5}){4}/', $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body, $m);
        $dir = dirname($ctx->configPath) . '/agent-quay';
        @mkdir($dir, 0700, true);
        [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code-stdin', '--config', $dir . '/agent.json']);
        Assert::true($code !== 0, 'without a code on stdin, enrollment is refused');
        // Code on stdin (as the installer passes it).
        $proc = proc_open([PHP_BINARY, $ctx->root . '/bin/sentinel-agent.php', 'enrol', '--server', $ctx->baseUrl, '--code-stdin', '--config', $dir . '/agent.json'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $ctx->root, ['SENTINEL_TEST_MODE' => '1', 'SENTINEL_ALLOW_ROOT' => '1', 'PATH' => (string) getenv('PATH')]);
        fwrite($pipes[0], ($m[0] ?? 'missing') . "\n");
        fclose($pipes[0]);
        $enrolOut = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        Assert::same(0, proc_close($proc), 'enrolled with the code on stdin: ' . $enrolOut);
        $app = require $ctx->configPath;
        $c = json_decode((string) file_get_contents($dir . '/agent.json'), true);
        Assert::same([$site, $cid], [$c['site_id'], $c['client_id']], 'site and client pinned');
        $c['nmap_path'] = $app['scanner']['nmap_path'];
        $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections']];
        file_put_contents($dir . '/agent.json', json_encode($c));
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'Protocol checks']);
        [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $dir . '/agent.json']);
        Assert::same('done', (string) $ctx->db->query("SELECT status FROM agent_jobs WHERE site_id = {$site} ORDER BY id DESC LIMIT 1")->fetchColumn(), 'scan done: ' . $out);

        $found = $ctx->db->query("SELECT finding_key, severity FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'proto:%'")->fetchAll(PDO::FETCH_KEY_PAIR);
        $bad = "proto:agent:{$site}:10.92.0.40:";
        $expect = ['smb1' => 'fail', 'smb_signing' => 'warn', 'rdp_no_nla' => 'warn', 'telnet' => 'fail', 'ftp' => 'warn', 'http_login' => 'warn', 'snmp_private' => 'fail'];
        foreach ($expect as $codeName => $sev) {
            Assert::same($sev, $found[$bad . $codeName] ?? null, $codeName . ': ' . json_encode($found));
        }
        Assert::true(!isset($found[$bad . 'snmp_public']), '"private" covers "public" (one finding)');
        $good = array_filter(array_keys($found), static fn (string $k): bool => str_contains($k, ':10.92.0.41:'));
        Assert::same([], array_values($good), 'well configured device: SMBv1 off, signing required, NLA required, no SNMP answer');
        $dev = (int) $ctx->db->query("SELECT id FROM devices WHERE source_id = '{$site}:10.92.0.41'")->fetchColumn();
        Assert::same('{"smb1":false,"signing_required":true,"nla_required":null}', (string) $ctx->db->query("SELECT checks FROM device_ports WHERE device_id = {$dev} AND port = 445")->fetchColumn());
        $page = $admin->get('/clients/' . $cid . '/devices/' . (int) $ctx->db->query("SELECT id FROM devices WHERE source_id = '{$site}:10.92.0.40'")->fetchColumn())->body;
        Assert::contains('SMBv1 is enabled', $page);
        // A later scan where the SMB check couldn't decide keeps the earlier answer (and the finding).
        $job = App::agents()->queueJob((int) $c['agent_id'], $cid, $site, (int) $ctx->db->query("SELECT id FROM internal_authorisations WHERE site_id = {$site}")->fetchColumn(), 'full', 'manual', null, [445], 12);
        $ctx->api('POST', '/agent/v1/poll', $c['token'], ['running' => []]);
        $ctx->api('POST', '/agent/v1/jobs/' . $job . '/results', $c['token'], ['status' => 'done', 'hosts' => [
            ['ip' => '10.92.0.40', 'scanned' => true, 'snmp' => null, 'ports' => [['port' => 445, 'service' => 'microsoft-ds', 'checks' => ['smb1' => null, 'signing_required' => null]],
             ['port' => 21, 'service' => 'ftp'], ['port' => 23, 'service' => 'telnet'], ['port' => 80, 'service' => 'http', 'web' => ['ok' => true, 'status' => 200, 'title' => 'x', 'scheme' => 'http', 'login_over_http' => true]],
             ['port' => 3389, 'service' => 'ms-wbt-server', 'checks' => ['nla_required' => false]]]]]]);
        Assert::same('open', (string) $ctx->db->query("SELECT status FROM findings WHERE client_id = {$cid} AND finding_key = '{$bad}smb1'")->fetchColumn(), 'undecided does not resolve SMBv1');
        Assert::same('open', (string) $ctx->db->query("SELECT status FROM findings WHERE client_id = {$cid} AND finding_key = '{$bad}snmp_private'")->fetchColumn(), 'skipped SNMP keeps its answer');
        $rid = App::reportService()->generate(App::clients()->find($cid), 'technical', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        Assert::contains('Turn off SMBv1', (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$rid}")->fetchColumn(), 'plain-English fix in reports');
    },
];
