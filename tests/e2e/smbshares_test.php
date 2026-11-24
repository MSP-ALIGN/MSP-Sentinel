<?php

declare(strict_types=1);

/**
 * End-to-end tests for the safe SMB share check (1.30, part of the engagement's anonymous access test): an anonymous
 * session only (no username, nothing to lock), the share list, a read-only count of each disk share's top folder, no
 * file names kept, nothing written; externally and through the agent. Fake SMB2 servers on 127.0.0.1 only; made-up
 * data and documentation ranges.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$smbSetup = static function (TestContext $ctx): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Share Check Example'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Share Check Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
            'approved_by_name' => 'Robin Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
            'document_ref' => '', 'notes' => '', 'scope' => "203.0.113.76\n", 'confirm' => '1']);
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-3001', 'notes' => '', 'ranges' => '10.88.0.0/24', 'confirm' => '1']);
        foreach (['smbtech' => 'technician', 'smbadmin2' => 'admin'] as $u => $role) {
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = '{$u}'")->fetchColumn() === 0) {
                $ctx->createUser($u, $role, ucfirst($u) . '-Pass-0001!');
            }
        }
    }
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $pdf = dirname($ctx->configPath) . '/signed-authorisation.pdf';
    file_put_contents($pdf, "%PDF-1.4\n% made-up signed authorisation for the test suite\n%%EOF\n");
    return [$cid, $site, $pdf];
};
$smbFields = static fn (int $site, array $over = []): array => $over + [
    'name' => 'Share check', 'signer_name' => 'Robin Example', 'signer_role' => 'Owner', 'signed_on' => gmdate('Y-m-d'),
    'window_start' => gmdate('Y-m-d\TH:i', time() - 3600), 'window_end' => gmdate('Y-m-d\TH:i', time() + 86400), 'intensity' => 'normal',
    'tests[0]' => 'anon_access', 'external' => '203.0.113.76', 'internal_' . $site => '', 'exclusions' => '', 'notes' => '', 'confirm' => '1',
];
$smbLast = static fn (TestContext $ctx, int $cid): int => (int) $ctx->db->query("SELECT MAX(id) FROM engagements WHERE client_id = {$cid}")->fetchColumn();
$smbLog = static fn (TestContext $ctx): array => is_file(dirname($ctx->nmapLog) . '/smb-requests.log') ? (file(dirname($ctx->nmapLog) . '/smb-requests.log', FILE_IGNORE_NEW_LINES) ?: []) : [];
$readOnly = static function (array $log): void {
    foreach ($log as $line) {
        if (str_starts_with($line, 'WRITE')) {
            Assert::true(str_starts_with($line, 'WRITE IPC$ rpc_type='), 'the only writes are the share-list request on the IPC$ pipe: ' . $line);
        }
        if (str_starts_with($line, 'CREATE') && !str_starts_with($line, 'CREATE IPC$ "srvsvc"')) {
            Assert::true((bool) preg_match('/^CREATE \S+ "" access=00100081$/', $line), 'only top folders, opened for listing (no write/delete rights): ' . $line);
        }
        Assert::true(!str_starts_with($line, 'UNEXPECTED'), 'nothing unexpected: ' . $line);
        if (str_starts_with($line, 'SESSION_SETUP authenticate')) {
            Assert::same('SESSION_SETUP authenticate user_length=0', $line, 'anonymous: no username at all');
        }
    }
};

return [
    'share check externally: anonymous session, share list, read-only counts, no file names kept' => function (TestContext $ctx) use ($smbSetup, $smbFields, $smbLast, $smbLog, $readOnly): void {
        [$cid, $site, $pdf] = $smbSetup($ctx);
        $tech = $ctx->login('smbtech', 'Smbtech-Pass-0001!');
        $admin2 = $ctx->login('smbadmin2', 'Smbadmin2-Pass-0001!');
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $smbFields($site), 'document', $pdf, 'application/pdf');
        $id = $smbLast($ctx, $cid);
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Smbadmin2-Pass-0001!']);
        $tech->post('/engagements/' . $id . '/run-external', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        $jobs = App::engagements()->externalJobs($id);
        @unlink(dirname($ctx->nmapLog) . '/smb-requests.log');
        [$code, $out] = $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . (int) $jobs[0]['id']]);
        Assert::same(0, $code, 'worker: ' . $out);
        $log = $smbLog($ctx);
        Assert::true(in_array('TREE_CONNECT Scans', $log, true), 'disk shares tested');
        $readOnly($log);
        $results = App::engagements()->results($id);
        $smb = $results[0]['checks_list']['smb_shares'] ?? [];
        Assert::same('anonymous', $smb['session'] ?? null);
        $byName = array_column((array) ($smb['shares'] ?? []), null, 'name');
        Assert::same(250, $byName['Scans']['items'] ?? null, 'counted over several answers');
        Assert::same(true, $byName['Scans']['complete'] ?? null, 'counted to the end');
        Assert::same(false, $byName['Finance']['readable'] ?? null);
        Assert::true(isset($byName['Printer']) && $byName['Printer']['readable'] === null, 'printers are not opened');
        Assert::true(!in_array('TREE_CONNECT Printer', $log, true) && !in_array('TREE_CONNECT IPC$x', $log, true), 'printer shares never connected');
        Assert::notContains('item-1.txt', (string) json_encode($results), 'no file names are kept');
        $page = $tech->get('/engagements/' . $id)->body;
        Assert::contains('File share \\\\203.0.113.76\\Public can be read without a password', $page);
        Assert::contains('File share \\\\203.0.113.76\\Scans can be read without a password', $page);
        Assert::contains('250 item(s) in its top folder', $page);
        Assert::contains('s file shares without a password', $page);
        Assert::notContains('Finance can be read', $page);
    },
    'share check internally through the agent: refused and restricted servers are fine' => function (TestContext $ctx) use ($smbSetup, $smbFields, $smbLast, $smbLog, $readOnly): void {
        [$cid, $site, $pdf] = $smbSetup($ctx);
        $tech = $ctx->login('smbtech', 'Smbtech-Pass-0001!');
        $admin2 = $ctx->login('smbadmin2', 'Smbadmin2-Pass-0001!');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $dir = dirname($ctx->configPath) . '/agent-smbshares';
        @mkdir($dir, 0700, true);
        if (!is_file($dir . '/agent.json')) {
            preg_match('/SNE(-[A-Z2-9]{5}){4}/', $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body, $m);
            [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $dir . '/agent.json']);
            Assert::same(0, $code, 'enrol: ' . $out);
            $app = require $ctx->configPath;
            $c = json_decode((string) file_get_contents($dir . '/agent.json'), true);
            $c['nmap_path'] = $app['testing']['agent_nmap_path'];
            $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $dir . '/arp'];
            file_put_contents($dir . '/agent.json', json_encode($c));
            file_put_contents($dir . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n");
        }
        $run = static fn (): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $dir . '/agent.json']);
        $run(); // reports its version
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $smbFields($site, ['name' => 'Internal share check',
            'external' => '', 'internal_' . $site => '10.88.0.0/24']), 'document', $pdf, 'application/pdf');
        $id = $smbLast($ctx, $cid);
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Smbadmin2-Pass-0001!']);
        $tech->post('/engagements/' . $id . '/run-internal', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        @unlink(dirname($ctx->nmapLog) . '/smb-requests.log');
        [$code, $out] = $run();
        Assert::same(0, $code, 'agent: ' . $out);
        $readOnly($smbLog($ctx));
        $byIp = array_column(App::engagements()->results($id), null, 'ip');
        Assert::same('refused', $byIp['10.88.0.41']['checks_list']['smb_shares']['session'] ?? null, 'anonymous logon refused');
        Assert::same(false, $byIp['10.88.0.42']['checks_list']['smb_shares']['listed'] ?? null, 'share list refused');
        Assert::same(false, $byIp['10.88.0.43']['checks_list']['smb_shares']['listed'] ?? null, 'an empty "access denied" answer is not a share list');
        $page = $tech->get('/engagements/' . $id)->body;
        Assert::contains('File share \\\\10.88.0.40\\Scans can be read without a password', $page);
        Assert::notContains('10.88.0.41\\', $page);
        Assert::notContains('10.88.0.42\\', $page);
        Assert::same(1, substr_count($page, 's file shares without a password'), 'one "anyone can list" finding (10.88.0.40), none for the server that refused the list');
    },
];
