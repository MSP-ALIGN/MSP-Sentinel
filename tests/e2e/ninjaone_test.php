<?php

declare(strict_types=1);

/**
 * End-to-end tests for the NinjaOne connector and Administration > Integrations, against the mock NinjaOne
 * Public API (tests/mocks/ninjaone_mock.php on 127.0.0.1). Never contacts NinjaOne. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Inventory\InventoryException;
use Sentinel\Inventory\NinjaOneSource;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$base = static fn (TestContext $ctx): string => (string) (require $ctx->configPath)['testing']['ninjaone_base_url'];

return [
    'NinjaOne connector: signs in, pages through every list and grades honestly' => function (TestContext $ctx) use ($base): void {
        // A page size of 2 makes every list (organisations, devices, cursor reports) take several pages.
        $src = new NinjaOneSource('app.ninjarmm.com', 'test-client', 'test-secret-value', $base($ctx), 2);
        $orgs = $src->organisations();
        Assert::same(['900', '901', '902'], array_column($orgs, 'id'), 'all organisations, across pages (until an empty page)');
        Assert::same('Harbour Example Ltd', $orgs[1]['name']);

        $snap = $src->snapshot('901');
        Assert::true($snap['complete'], 'complete snapshot');
        $by = array_column($snap['devices'], null, 'source_id');
        Assert::same(['11', '12', '13', '17'], array_map('strval', array_keys($by)), 'computers only: no switch, no unapproved device');
        Assert::same('', $by['17']['av_state'], 'offline a month, no inventory: antivirus unknown, never "missing"');
        $lt1 = $by['11'];
        Assert::same(['HARBOUR-LT-01', 'workstation', 'Windows 10 Pro', '19045', '22H2', ['10.30.0.11']], [$lt1['name'], $lt1['device_class'], $lt1['os_name'], $lt1['os_build'], $lt1['os_release'], $lt1['ip_addresses']]);
        Assert::same(['off', 'outdated', 'off'], [$lt1['av_state'], $lt1['av_definitions'], $lt1['encryption']], 'antivirus off, old definitions, BitLocker off');
        Assert::same(['Google Chrome', '7-Zip 23.01 (x64)'], array_column($lt1['software'], 'name'), 'software from several cursor pages');
        Assert::same([['KB5099999', 'pending']], array_map(static fn ($p) => [$p['kb'], $p['status']], $lt1['patches']));
        Assert::true(is_int($lt1['last_contact']) && $lt1['last_contact'] > time() - 3600, 'last contact as Unix time');
        $srv = $by['12'];
        Assert::same(['server', 'on', 'current', ''], [$srv['device_class'], $srv['av_state'], $srv['av_definitions'], $srv['encryption']], 'no volume data: encryption unknown, not off');
        Assert::same('failed', $srv['patches'][0]['status'], 'a failed install in the last 30 days (os-patch-installs)');
        Assert::same('pending', $lt1['patches'][0]['status'], 'a failed attempt 40 days ago is history');
        Assert::same(null, $lt1['patches'][0]['detected_at'], 'NinjaOne\'s collection time is not a detection date');
        $lt2 = $by['13'];
        Assert::same('missing', $lt2['av_state'], 'a Windows workstation with no antivirus reported');
        Assert::same('on', $lt2['encryption'], 'C: protected (another drive does not count)');
        Assert::same([], $lt2['patches'], 'rejected patches were declined on purpose: not missing');

        // A server that keeps returning the same page is stopped, not looped or half-saved.
        $stuck = false;
        try {
            $src->snapshot('903');
        } catch (InventoryException $ex) {
            $stuck = str_contains($ex->getMessage(), 'same page twice');
        }
        Assert::true($stuck, 'repeated page detected');
        // A failed page fails the whole snapshot (never half the data as if it were everything).
        $failed = false;
        try {
            $src->snapshot('900');
        } catch (InventoryException $ex) {
            $failed = str_contains($ex->getMessage(), 'HTTP 500');
        }
        Assert::true($failed, 'failed report page throws');
        // Wrong secret: NinjaOne's reason, and never the secret itself.
        $bad = new NinjaOneSource('app.ninjarmm.com', 'test-client', 'wrong-secret-xyz', $base($ctx));
        try {
            $bad->organisations();
            Assert::true(false, 'wrong secret must fail');
        } catch (InventoryException $ex) {
            Assert::contains('The client credentials are not valid', $ex->getMessage());
            Assert::notContains('wrong-secret-xyz', $ex->getMessage());
        }
        // Production refuses anything but a *.ninjarmm.com host, so the secret only ever goes to NinjaOne.
        foreach (['evil.example', 'app.ninjarmm.com.evil.example', 'ninjarmm.com', 'APP.NINJARMM.COM/x'] as $host) {
            Assert::true(!NinjaOneSource::validHost($host), "refused host {$host}");
        }
        Assert::true(NinjaOneSource::validHost('eu.ninjarmm.com'), 'regional instance accepted');
        $refused = false;
        try {
            (new NinjaOneSource('evil.example', 'test-client', 'test-secret-value'))->organisations();
        } catch (InventoryException) {
            $refused = true;
        }
        Assert::true($refused, 'no request to a non-NinjaOne host');
        $badOrg = false;
        try {
            $src->snapshot('1 OR 1');
        } catch (InventoryException) {
            $badOrg = true;
        }
        Assert::true($badOrg, 'organisation IDs are digits only (they go into the device filter)');
    },
    'Integrations page: admins save NinjaOne settings, the secret is encrypted and never shown, test connection works' => function (TestContext $ctx): void {
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'intech'")->fetchColumn() === 0) {
            $ctx->createUser('intech', 'technician', 'Intech-Pass-001!');
        }
        Assert::status(403, $ctx->login('intech', 'Intech-Pass-001!')->get('/admin/integrations'), 'technicians cannot open it');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $admin->get('/admin/integrations');
        Assert::status(200, $page);
        Assert::contains('API Services (machine-to-machine)', $page->body, 'set-up steps shown');
        Assert::contains('href="/admin/integrations"', $admin->get('/admin')->body, 'in the Administration menu');

        $admin->submit('/admin/integrations', '/admin/integrations/ninjaone', ['host' => 'evil.example', 'client_id' => 'test-client', 'client_secret' => 'test-secret-value', 'enabled' => '1']);
        Assert::contains('must be the address you sign in at', $admin->get('/admin/integrations')->body);
        Assert::same('', App::settings()->fresh('ninjaone_host'), 'nothing saved');

        $admin->submit('/admin/integrations', '/admin/integrations/ninjaone', ['host' => 'https://app.ninjarmm.com/apidocs', 'client_id' => 'test-client', 'client_secret' => 'test-secret-value', 'enabled' => '1']);
        Assert::same('app.ninjarmm.com', App::settings()->fresh('ninjaone_host'), 'a pasted URL becomes the host');
        $raw = (string) $ctx->db->query("SELECT value FROM settings WHERE name = 'ninjaone_client_secret'")->fetchColumn();
        Assert::true($raw !== '' && !str_contains($raw, 'test-secret-value'), 'secret stored encrypted');
        $page = $admin->get('/admin/integrations')->body;
        Assert::notContains('test-secret-value', $page, 'secret never shown');
        Assert::contains('Saved (leave empty to keep)', $page);
        $audit = implode("\n", $ctx->db->query("SELECT details FROM audit_log WHERE action LIKE 'settings.ninjaone%'")->fetchAll(PDO::FETCH_COLUMN));
        Assert::contains('"ninjaone_client_secret":"changed"', $audit);
        Assert::notContains('test-secret-value', $audit, 'secret never audited');

        $admin->submit('/admin/integrations', '/admin/integrations/ninjaone/test', []);
        Assert::contains('Connected: the API app can see 3 organisation(s)', $admin->get('/admin/integrations')->body);
        // Saving again with the secret field empty keeps the saved secret.
        $admin->submit('/admin/integrations', '/admin/integrations/ninjaone', ['host' => 'app.ninjarmm.com', 'client_id' => 'test-client', 'client_secret' => '', 'enabled' => '1']);
        Assert::same('test-secret-value', App::settings()->getSecret('ninjaone_client_secret'));
        // A wrong secret: the test says why.
        $admin->submit('/admin/integrations', '/admin/integrations/ninjaone', ['host' => 'app.ninjarmm.com', 'client_id' => 'test-client', 'client_secret' => 'wrong-secret-xyz', 'enabled' => '1']);
        $admin->submit('/admin/integrations', '/admin/integrations/ninjaone/test', []);
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('NinjaOne sign-in failed', $page);
        Assert::notContains('wrong-secret-xyz', $page);
        // Clear it again so later tests keep using the fixture source.
        $admin->submit('/admin/integrations', '/admin/integrations/ninjaone', ['host' => '', 'client_id' => '', 'clear_secret' => '1', 'enabled' => '0']);
        Assert::same('', App::settings()->getSecret('ninjaone_client_secret'), 'secret removed');
    },
    'NinjaOne sync: a linked client gets its devices, software vulnerabilities and device findings' => function (TestContext $ctx) use ($base): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Harbour Ninja Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $ctx->db->prepare("INSERT INTO source_links (client_id, source, org_id, org_name, linked_by, linked_at) VALUES (:c, 'ninjaone', '901', 'Harbour Example Ltd', 1, UTC_TIMESTAMP())")->execute(['c' => $cid]);
        $sync = new \Sentinel\Inventory\InventorySync(App::db(), App::inventory(), ['ninjaone' => new NinjaOneSource('app.ninjarmm.com', 'test-client', 'test-secret-value', $base($ctx), 2)],
            App::vulnMatcher(15), App::findingsEngine(), null);
        $r = $sync->syncClient($cid, 'ninjaone');
        Assert::same('ok', $r['status'], $r['message']);
        Assert::same(4, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND removed_at IS NULL")->fetchColumn());
        Assert::same('00:1b:21:3a:4f:11,00:1b:21:3a:4f:13', (string) $ctx->db->query("SELECT mac_addresses FROM devices WHERE client_id = {$cid} AND source_id = '11'")->fetchColumn(), 'MAC addresses normalised, junk, multicast and labels dropped, dotted form read (1.50.1)');
        // Missing updates count from when Sentinel first saw them: 40 days later they are late.
        $ctx->db->exec("UPDATE device_patches p JOIN devices d ON d.id = p.device_id SET p.first_seen = UTC_TIMESTAMP() - INTERVAL 40 DAY WHERE d.client_id = {$cid}");
        $r = $sync->syncClient($cid, 'ninjaone');
        Assert::same('ok', $r['status'], $r['message']);
        $keys = $ctx->db->query("SELECT finding_key FROM findings WHERE client_id = {$cid} AND status = 'open'")->fetchAll(PDO::FETCH_COLUMN);
        foreach (['dev:ninjaone:11:os_unsupported', 'dev:ninjaone:11:av_off', 'dev:ninjaone:11:encryption_off', 'dev:ninjaone:11:patches_missing', 'dev:ninjaone:12:patches_failed', 'dev:ninjaone:13:av_missing'] as $k) {
            Assert::true(in_array($k, $keys, true), "finding {$k}: " . implode(', ', $keys));
        }
        Assert::true(!in_array('dev:ninjaone:12:encryption_off_server', $keys, true) && !in_array('dev:ninjaone:12:encryption_off', $keys, true), 'unknown encryption is not a finding');
        $devices = $ctx->clientSection($admin, $cid, 'devices');
        Assert::contains('HARBOUR-LT-01', $devices);
        Assert::notContains('<script>alert(1)', $ctx->clientSection($admin, $cid, 'devices') . $admin->get('/clients/' . $cid . '/devices/' . (int) $ctx->db->query("SELECT id FROM devices WHERE client_id = {$cid} AND source_id = '13'")->fetchColumn())->body, 'escaped');
        // 1.49: an organisation whose antivirus report is empty: its online workstation is unknown, not "no antivirus".
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Quay Ninja Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $quay = (int) basename((string) $res->location());
        $ctx->db->prepare("INSERT INTO source_links (client_id, source, org_id, org_name, linked_by, linked_at) VALUES (:c, 'ninjaone', '902', 'Quay Example Inc', 1, UTC_TIMESTAMP())")->execute(['c' => $quay]);
        Assert::same('ok', $sync->syncClient($quay, 'ninjaone')['status']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$quay} AND finding_key LIKE '%av_missing'")->fetchColumn(), 'empty antivirus report: no "no antivirus" findings');
        // A failing organisation keeps the devices it had (nothing is removed on a failed sync).
        $ctx->db->prepare("UPDATE source_links SET org_id = '900' WHERE client_id = :c")->execute(['c' => $cid]);
        $r = $sync->syncClient($cid, 'ninjaone');
        Assert::true($r['status'] !== 'ok', 'failed sync reported');
        Assert::same(4, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND removed_at IS NULL")->fetchColumn(), 'devices kept');
    },
];
