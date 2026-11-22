<?php

declare(strict_types=1);

/**
 * End-to-end tests for internal devices from an inventory source (a test
 * stand-in for NinjaOne, read from a file): admin-only linking with a name
 * suggestion, syncs through the worker, software matched to a made-up CVE,
 * device findings (unsupported Windows, antivirus off, encryption, missing
 * and failed updates), removed devices, partial and failed syncs, and the
 * pages. No real devices or organisations; made-up names only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

/** Write the inventory file (dates relative to now). */
$write = static function (TestContext $ctx, array $over = []): void {
    $day = 86400;
    $data = [
        'organisations' => [['id' => 'org-101', 'name' => 'Riverbend Example Ltd'], ['id' => 'org-102', 'name' => 'Hilltop Example'], ['id' => 'org-fail', 'name' => 'Broken Example']],
        'fail' => ['org-fail'],
        'snapshots' => ['org-101' => ['complete' => true, 'devices' => [
            ['source_id' => '5001', 'name' => 'RB-WS-01', 'dns_name' => 'rb-ws-01.riverbend.example', 'device_class' => 'workstation', 'os_name' => 'Windows 10 Professional Edition',
             'os_build' => '19045', 'os_release' => '22H2', 'ip_addresses' => ['192.0.2.10', 'not-an-ip'], 'last_contact' => time() - 3600, 'av_product' => 'Example Defender', 'av_state' => 'on',
             'av_definitions' => 'current', 'encryption' => 'off',
             'software' => [['name' => 'Google Chrome', 'publisher' => 'Google LLC', 'version' => '120.0.6099.130'], ['name' => '7-Zip 19.00 (x64)', 'publisher' => 'Igor Pavlov', 'version' => ''],
                            ['name' => 'Example Line-of-Business App', 'publisher' => 'Example Corp', 'version' => '4.2'], ['name' => "<script>alert(1)</script>", 'publisher' => '', 'version' => '1.0']],
             'patches' => [['patch_id' => 'p-1', 'name' => '2099-01 Cumulative Update (made up)', 'kb' => 'KB5099001', 'severity' => 'critical', 'status' => 'pending', 'detected_at' => time() - 60 * $day],
                           ['patch_id' => 'p-2', 'name' => 'Example driver update', 'kb' => 'KB5099002', 'severity' => 'optional', 'status' => 'failed', 'detected_at' => time() - 2 * $day],
                           ['patch_id' => 'p-3', 'name' => 'Recent security update', 'kb' => 'KB5099003', 'severity' => 'critical', 'status' => 'pending', 'detected_at' => time() - 3 * $day]]],
            ['source_id' => '5002', 'name' => 'RB-SRV-01', 'dns_name' => '', 'device_class' => 'server', 'os_name' => 'Windows Server 2022 Standard', 'os_build' => '20348', 'os_release' => '',
             'ip_addresses' => ['192.0.2.20'], 'last_contact' => time() - 600, 'av_product' => 'Example Defender', 'av_state' => 'off', 'av_definitions' => '', 'encryption' => 'off', 'software' => [], 'patches' => []],
            ['source_id' => '5003', 'name' => 'RB-WS-02', 'dns_name' => '', 'device_class' => 'workstation', 'os_name' => 'Windows 11 Enterprise', 'os_build' => '26200', 'os_release' => '25H2',
             'ip_addresses' => [], 'last_contact' => time() - 60, 'av_product' => 'Example Defender', 'av_state' => 'on', 'av_definitions' => 'current', 'encryption' => 'on', 'software' => [], 'patches' => []],
        ]]],
    ];
    file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode(array_replace_recursive($data, $over)));
};
$setup = static function (TestContext $ctx) use ($write): int {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Riverbend Example'")->fetchColumn();
    if ($cid > 0) {
        return $cid;
    }
    $write($ctx);
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Riverbend Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
        'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    return (int) basename((string) $res->location());
};
$finding = static fn (TestContext $ctx, int $cid, string $key): ?array => $ctx->db->query("SELECT severity, status, finding_type, source, device_id, title, detail FROM findings WHERE client_id = {$cid} AND finding_key = " . $ctx->db->quote($key))->fetch() ?: null;

return [
    'admins link a client to an organisation; a name match is only suggested' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('Link to an organisation', $ctx->clientPages($admin, (int) $cid));
        $form = $admin->get('/clients/' . $cid . '/inventory/link?source=ninjaone')->body;
        Assert::true(preg_match('/<option value="org-101" selected>Riverbend Example Ltd \(suggested\)/', $form) === 1, 'suggested by name, ignoring "Ltd"');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM source_links WHERE client_id = {$cid}")->fetchColumn(), 'nothing linked automatically');
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'invtech'")->fetchColumn() === 0) {
            $ctx->createUser('invtech', 'technician', 'Invtech-Pass-0001!');
        }
        $tech = $ctx->login('invtech', 'Invtech-Pass-0001!');
        Assert::status(403, $tech->get('/clients/' . $cid . '/inventory/link'), 'technicians cannot link');
        Assert::status(403, $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/inventory/link', ['source' => 'ninjaone', 'org_id' => 'org-101']));
        // Only organisations the source lists can be linked.
        $admin->submit('/clients/' . $cid . '/inventory/link?source=ninjaone', '/clients/' . $cid . '/inventory/link', ['source' => 'ninjaone', 'org_id' => 'org-999']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM source_links WHERE client_id = {$cid}")->fetchColumn(), 'unknown organisation refused');
        Assert::status(404, $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/inventory/link', ['source' => 'other', 'org_id' => 'org-101']), 'unknown source');
        Assert::redirect('/clients/' . $cid . '/devices', $admin->submit('/clients/' . $cid . '/inventory/link?source=ninjaone', '/clients/' . $cid . '/inventory/link', ['source' => 'ninjaone', 'org_id' => 'org-101']));
        Assert::same('Riverbend Example Ltd', (string) $ctx->db->query("SELECT org_name FROM source_links WHERE client_id = {$cid}")->fetchColumn());
        Assert::contains('inventory.linked', (string) $ctx->db->query("SELECT GROUP_CONCAT(action) FROM audit_log")->fetchColumn());
        // One organisation, one client.
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Second Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $other = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $other . '/inventory/link', '/clients/' . $other . '/inventory/link', ['source' => 'ninjaone', 'org_id' => 'org-101']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM source_links WHERE client_id = {$other}")->fetchColumn(), 'already linked elsewhere');
    },
    'a sync brings devices, matches software and grades devices honestly' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        $ctx->cli('bin/worker.php', ['--no-schedule']);
        Assert::same(3, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND removed_at IS NULL")->fetchColumn(), 'three devices');
        Assert::same('ok', (string) $ctx->db->query("SELECT last_sync_status FROM source_links WHERE client_id = {$cid}")->fetchColumn());
        Assert::same('192.0.2.10', (string) $ctx->db->query("SELECT ip_addresses FROM devices WHERE source_id = '5001'")->fetchColumn(), 'invalid addresses dropped');
        $sw = $ctx->db->query("SELECT s.name, s.product, s.cpe FROM device_software s JOIN devices d ON d.id = s.device_id WHERE d.source_id = '5001' ORDER BY s.name")->fetchAll(PDO::FETCH_UNIQUE);
        Assert::same('cpe:/a:7-zip:7-zip:19.00', $sw['7-Zip 19.00 (x64)']['cpe'], 'version from the name');
        Assert::same('', $sw['Example Line-of-Business App']['cpe'], 'not in the catalogue: not matched');

        $ws = '5001';
        $os = $finding($ctx, $cid, "dev:ninjaone:{$ws}:os_unsupported");
        Assert::same(['fail', 'device', 'ninjaone'], [$os['severity'] ?? null, $os['finding_type'] ?? null, $os['source'] ?? null], 'Windows 10 22H2: unsupported (Fail)');
        Assert::contains('2025-10-14', (string) $finding($ctx, $cid, "dev:ninjaone:{$ws}:os_unsupported")['detail']);
        Assert::same('warn', $finding($ctx, $cid, "dev:ninjaone:{$ws}:encryption_off")['severity'] ?? null, 'workstation without encryption');
        $p = $finding($ctx, $cid, "dev:ninjaone:{$ws}:patches_missing");
        Assert::true($p !== null && $p['finding_type'] === 'patch' && str_contains($p['detail'], 'KB5099001') && !str_contains($p['detail'], 'KB5099003'), 'only updates missing for 30+ days');
        Assert::same('warn', $finding($ctx, $cid, "dev:ninjaone:{$ws}:patches_failed")['severity'] ?? null);
        Assert::same('fail', $finding($ctx, $cid, 'dev:ninjaone:5002:av_off')['severity'] ?? null, 'antivirus off');
        Assert::same(null, $finding($ctx, $cid, 'dev:ninjaone:5002:encryption_off_server'), 'servers: advice only');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'dev:ninjaone:5003:%'")->fetchColumn(), 'healthy device: nothing');
        // Software CVE (made-up NVD data for this Chrome version).
        $ctx->cli('bin/feeds.php');
        $v = $finding($ctx, $cid, "devvuln:ninjaone:{$ws}:Google Chrome");
        Assert::true($v !== null && $v['severity'] === 'fail' && $v['finding_type'] === 'vuln' && $v['source'] === 'ninjaone', 'critical confirmed CVE in installed software');
        Assert::contains('Google Chrome 120.0.6099.130: 1 known CVE(s)', (string) $v['title']);
        Assert::contains('CVE-2099-0301', (string) $v['detail']);
        // Chrome updates before NVD has data for the new version: the finding waits instead of resolving.
        $data = json_decode((string) file_get_contents(dirname($ctx->configPath) . '/inventory.json'), true);
        $data['snapshots']['org-101']['devices'][0]['software'][0]['version'] = '120.0.6099.199';
        file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode($data));
        App::vulns()->setNvdBlockedUntil(time() + 3600); // NVD not reachable: the new version's data stays pending
        App::inventorySync()->syncClient($cid, 'ninjaone');
        App::vulns()->setNvdBlockedUntil(0);
        Assert::same('open', $finding($ctx, $cid, "devvuln:ninjaone:{$ws}:Google Chrome")['status'] ?? null, 'not resolved while data for the new version is pending');
        $data['snapshots']['org-101']['devices'][0]['software'][0]['version'] = '120.0.6099.130';
        file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode($data));
        App::inventorySync()->syncClient($cid, 'ninjaone');
        Assert::true((int) $v['device_id'] > 0, 'linked to the device');
    },
    'pages: client card, device page, findings filter, report guidance; data is escaped' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $view = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $ctx->clientPages($view, (int) $cid);
        foreach (['Internal devices', 'RB-WS-01', 'Operating system no longer gets security updates', 'Antivirus or EDR is turned off', 'linked to Riverbend Example Ltd'] as $s) {
            Assert::contains($s, $page);
        }
        $dev = (int) $ctx->db->query("SELECT id FROM devices WHERE source_id = '5001'")->fetchColumn();
        $d = $view->get('/clients/' . $cid . '/devices/' . $dev)->body;
        Assert::contains('CVE-2099-0301', $d);
        Assert::contains('KB5099001', $d);
        Assert::contains('not matched', $d);
        Assert::notContains('<script>alert(1)</script>', $d, 'program names are escaped');
        Assert::contains('&lt;script&gt;', $d);
        $res = $view->submit('/clients/new', '/clients', ['name' => 'Elsewhere Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        Assert::status(404, $view->get('/clients/' . (int) basename((string) $res->location()) . '/devices/' . $dev), 'a device is only shown under its own client');
        $internal = $view->get('/findings?source=internal&client=' . $cid)->body;
        Assert::contains('Device security', $internal);
        Assert::contains('Missing updates', $internal);
        $id = App::reportService()->generate(App::clients()->find($cid), 'technical', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        $html = (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$id}")->fetchColumn();
        Assert::contains('Upgrade to a supported Windows version', $html, 'plain-English fix in reports');
    },
    'removed devices resolve; partial snapshots keep devices; failed syncs are shown' => function (TestContext $ctx) use ($setup, $write, $finding): void {
        $cid = $setup($ctx);
        // RB-SRV-01 is gone from a PARTIAL snapshot: kept.
        $data = json_decode((string) file_get_contents(dirname($ctx->configPath) . '/inventory.json'), true);
        $data['snapshots']['org-101']['devices'] = array_values(array_filter($data['snapshots']['org-101']['devices'], static fn (array $d): bool => $d['source_id'] !== '5002'));
        $data['snapshots']['org-101']['complete'] = false;
        file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode($data));
        App::inventorySync()->syncClient($cid, 'ninjaone');
        Assert::same(null, $ctx->db->query("SELECT removed_at FROM devices WHERE source_id = '5002'")->fetchColumn(), 'partial: not removed');
        Assert::same('partial', (string) $ctx->db->query("SELECT last_sync_status FROM source_links WHERE client_id = {$cid}")->fetchColumn());
        // Complete snapshot without it: removed, and its findings resolve.
        $data['snapshots']['org-101']['complete'] = true;
        file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode($data));
        App::inventorySync()->syncClient($cid, 'ninjaone');
        Assert::true($ctx->db->query("SELECT removed_at FROM devices WHERE source_id = '5002'")->fetchColumn() !== null, 'complete: removed');
        Assert::same('resolved', $finding($ctx, $cid, 'dev:ninjaone:5002:av_off')['status'] ?? null);
        // Updates installed: the patch findings resolve.
        $data['snapshots']['org-101']['devices'][0]['patches'] = [];
        file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode($data));
        App::inventorySync()->syncClient($cid, 'ninjaone');
        Assert::same('resolved', $finding($ctx, $cid, 'dev:ninjaone:5001:patches_missing')['status'] ?? null);
        // An empty "complete" answer (lost access) removes nothing.
        $saved = $data;
        $data['snapshots']['org-101']['devices'] = [];
        file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode($data));
        $r = App::inventorySync()->syncClient($cid, 'ninjaone');
        Assert::contains('far fewer devices', $r['message']);
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND removed_at IS NULL")->fetchColumn(), 'nothing removed');
        $data = $saved;
        file_put_contents(dirname($ctx->configPath) . '/inventory.json', json_encode($data));
        // A failing source: shown on the client, nothing changes.
        $before = (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND removed_at IS NULL")->fetchColumn();
        $ctx->db->exec("UPDATE source_links SET org_id = 'org-fail' WHERE client_id = {$cid}");
        $r = App::inventorySync()->syncClient($cid, 'ninjaone');
        Assert::same('error', $r['status']);
        Assert::same($before, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND removed_at IS NULL")->fetchColumn(), 'a failure removes nothing');
        Assert::contains('Sync failed', $ctx->clientPages($ctx->login('admin', 'Admin-Pass-0001!'), (int) $cid));
        $ctx->db->exec("UPDATE source_links SET org_id = 'org-101' WHERE client_id = {$cid}");
        // Sync now (technicians) marks the link due; unlink (admins) removes devices and resolves their findings.
        $tech = $ctx->login('invtech', 'Invtech-Pass-0001!');
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/inventory/sync', ['source' => 'ninjaone']);
        Assert::same(null, $ctx->db->query("SELECT last_sync_at FROM source_links WHERE client_id = {$cid}")->fetchColumn(), 'due now');
        Assert::status(403, $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/inventory/unlink', ['source' => 'ninjaone']), 'technicians cannot unlink');
        $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/inventory/unlink', ['source' => 'ninjaone']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND removed_at IS NULL")->fetchColumn());
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND source = 'ninjaone' AND status = 'open'")->fetchColumn(), 'findings resolved');
        Assert::contains('not a confirmed fix', (string) $ctx->db->query("SELECT note FROM finding_events e JOIN findings f ON f.id = e.finding_id WHERE f.client_id = {$cid} AND e.event = 'resolved' ORDER BY e.id DESC LIMIT 1")->fetchColumn());
        // Archived clients can't be linked.
        $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$cid}");
        $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/inventory/link', ['source' => 'ninjaone', 'org_id' => 'org-101']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM source_links WHERE client_id = {$cid}")->fetchColumn(), 'archived: not linked');
        $ctx->db->exec("UPDATE clients SET is_archived = 0 WHERE id = {$cid}");
        $write($ctx);
    },
];
