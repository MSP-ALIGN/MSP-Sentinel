<?php

declare(strict_types=1);

/**
 * End-to-end tests (1.38): the Windows version read over SMB from the mock server (no login), and one device for a
 * machine the agent and the inventory source both report (matching rules, combined page, admin merge and split).
 * Made-up names and documentation/private test addresses only; nothing real is scanned.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'NTLM over SMB: the mock answers with its Windows version and names, without any login' => function (TestContext $ctx): void {
        $app = require $ctx->configPath;
        $smb = new \Sentinel\Scanning\SmbShares(\Sentinel\Scanning\Connector::fromTesting($app['testing']));
        $log = dirname($ctx->nmapLog) . '/smb-requests.log';
        $before = is_file($log) ? count(file($log) ?: []) : 0;
        $info = $smb->ntlmInfo('203.0.113.76');
        Assert::same(['major' => 10, 'minor' => 0, 'build' => 20348], array_intersect_key((array) $info, ['major' => 1, 'minor' => 1, 'build' => 1]));
        Assert::same(['FILESRV01', 'filesrv01.corp.example'], [$info['netbios_name'], $info['dns_name']]);
        $new = array_slice(is_file($log) ? (file($log, FILE_IGNORE_NEW_LINES) ?: []) : [], $before);
        Assert::true(!in_array(true, array_map(static fn (string $l): bool => str_contains($l, 'authenticate'), $new), true), 'never logs in: ' . implode(' | ', $new));
        Assert::same('Windows Server 2022', \Sentinel\Inventory\OsGuess::guess($info, [['port' => 445]])['os_name']);
    },
    'merged devices: matched by address and name, one row, combined page; admins split and merge by hand' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Merge Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00',
            'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $add = static function (string $source, string $sid, string $name, string $dns, string $ip) use ($ctx, $cid, $site): int {
            $ctx->db->prepare("INSERT INTO devices (client_id, site_id, source, source_id, name, dns_name, device_class, os_name, ip_addresses, first_seen, last_seen)
                               VALUES (:c, :s, :src, :sid, :n, :d, 'server', '', :ip, UTC_TIMESTAMP(), UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 's' => $site, 'src' => $source, 'sid' => $sid, 'n' => $name, 'd' => $dns, 'ip' => $ip]);
            return (int) $ctx->db->lastInsertId();
        };
        $ninja = $add('ninjaone', 'merge-1', 'SRV-FILES', 'srv-files.corp.example', '10.93.0.10');
        $ninja2 = $add('ninjaone', 'merge-2', 'SRV-APPS', 'srv-apps.corp.example', '10.93.0.20');
        $sameName = $add('agent', 'agent-a', '', 'srv-files.corp.example', '10.93.0.10');   // same address and name: merged
        $noName = $add('agent', 'agent-b', '10.93.0.20', '', '10.93.0.20');                // same address, no name (the agent stores the address): merged
        $otherName = $add('agent', 'agent-c', 'PRINTER-2', '', '10.93.0.10');                // same address, another name: not merged
        $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at, device_id)
                           VALUES (:c, 'device:merge-test', 'device', 'fail', 'SMBv1 is enabled (merge test)', '', 'srv-files', 'x', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), :d)")
            ->execute(['c' => $cid, 'd' => $sameName]);
        Assert::same(2, App::inventory()->refreshMerges($cid));
        $m = static function (int $id) use ($ctx): array {
            $r = $ctx->db->query("SELECT merged_into, merge_state FROM devices WHERE id = {$id}")->fetch();
            return [$r['merged_into'] === null ? null : (string) $r['merged_into'], $r['merge_state']];
        };
        Assert::same([(string) $ninja, 'auto'], array_values($m($sameName)));
        Assert::same([(string) $ninja2, 'auto'], array_values($m($noName)));
        Assert::same([null, null], array_values($m($otherName)), 'a different name on the same address is not merged');
        // One row each; the inventory row carries the agent's findings and a badge.
        $list = $ctx->clientSection($admin, $cid, 'devices');
        Assert::notContains('/devices/' . $sameName . '"', $list, 'the merged agent row is not listed');
        Assert::contains('also found by agent', $list);
        Assert::contains('PRINTER-2', $list);
        $page = $admin->get('/clients/' . $cid . '/devices/' . $ninja)->body;
        Assert::contains('SMBv1 is enabled (merge test)', $page, "the agent's finding shows on the combined page");
        Assert::contains('matched by address and name', $page);
        Assert::redirect('/clients/' . $cid . '/devices/' . $ninja, $admin->get('/clients/' . $cid . '/devices/' . $sameName), 'the agent row opens the combined page');
        // Split: stays separate, even when the rules run again.
        $admin->submit('/clients/' . $cid . '/devices/' . $ninja, '/clients/' . $cid . '/devices/' . $sameName . '/merge', ['target' => '']);
        App::inventory()->refreshMerges($cid);
        Assert::same([null, 'split'], array_values($m($sameName)));
        // Manual merge of the differently named one; other clients' devices and agent devices are refused as targets.
        $page = $admin->get('/clients/' . $cid . '/devices/' . $otherName)->body;
        Assert::contains('Same machine as an inventory device?', $page);
        $admin->submit('/clients/' . $cid . '/devices/' . $otherName, '/clients/' . $cid . '/devices/' . $otherName . '/merge', ['target' => (string) $ninja]);
        Assert::same([(string) $ninja, 'manual'], array_values($m($otherName)));
        $admin->submit('/clients/' . $cid . '/devices/' . $ninja, '/clients/' . $cid . '/devices/' . $otherName . '/merge', ['target' => (string) $noName]);
        Assert::same([(string) $ninja, 'manual'], array_values($m($otherName)), 'an agent device is not a target');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action IN ('device.merged', 'device.split')")->fetchColumn() >= 2, 'audited');
        // The inventory device goes away: the merge is released, the agent device shows again.
        $ctx->db->exec("UPDATE devices SET removed_at = UTC_TIMESTAMP() WHERE id = {$ninja}");
        App::inventory()->refreshMerges($cid);
        Assert::same([null, null], array_values($m($otherName)));
        // Technicians can't merge.
        $ctx->createUser('mergetech', 'technician', 'Mergetech-Pass-0001!');
        $tech = $ctx->login('mergetech', 'Mergetech-Pass-0001!');
        Assert::status(403, $tech->post('/clients/' . $cid . '/devices/' . $otherName . '/merge', ['_csrf' => $tech->get('/clients/' . $cid . '/devices/' . $ninja2)->csrf(), 'target' => (string) $ninja2]));
        $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$cid}");
    },

    'merged devices (1.39 fixes): unlinking or moving the target shows the agent device again; OS guesses stay cautious' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $mk = static function (string $name) use ($admin): int {
            $res = $admin->submit('/clients/new', '/clients', ['name' => $name, 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00',
                'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
            return (int) basename((string) $res->location());
        };
        $cid = $mk('Merge Fix Example');
        $other = $mk('Merge Fix Other Example');
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $add = static function (string $source, string $sid, string $name, string $ip, string $os = '', string $build = '') use ($ctx, $cid, $site): int {
            $ctx->db->prepare("INSERT INTO devices (client_id, site_id, source, source_id, name, dns_name, device_class, os_name, os_build, ip_addresses, first_seen, last_seen)
                               VALUES (:c, :s, :src, :sid, :n, '', 'server', :os, :b, :ip, UTC_TIMESTAMP(), UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 's' => $site, 'src' => $source, 'sid' => $sid, 'n' => $name, 'os' => $os, 'b' => $build, 'ip' => $ip]);
            return (int) $ctx->db->lastInsertId();
        };
        $ctx->db->prepare("INSERT INTO source_links (client_id, source, org_id, org_name, linked_by, linked_at) VALUES (:c, 'ninjaone', 'org-fix', 'Fix Org', 1, UTC_TIMESTAMP())")
            ->execute(['c' => $cid]);
        $inv = $add('ninjaone', 'fix-1', 'SRV-FIX', '10.94.0.10');
        $inv2 = $add('ninjaone', 'fix-2', 'SRV-MOVE', '10.94.0.20');
        $agent = $add('agent', 'fix-a', 'SRV-FIX', '10.94.0.10');
        $agent2 = $add('agent', 'fix-b', 'SRV-MOVE', '10.94.0.20');
        App::inventory()->refreshMerges($cid);
        $merged = static fn (int $id): ?string => ($v = $ctx->db->query("SELECT merged_into FROM devices WHERE id = {$id}")->fetchColumn()) === null ? null : (string) $v;
        Assert::same((string) $inv, $merged($agent));
        Assert::same((string) $inv2, $merged($agent2));
        $list = static fn (): string => $ctx->clientSection($admin, $cid, 'devices');
        Assert::notContains('/devices/' . $agent2 . '"', $list());
        // The source's devices move to another client (its organisation linked there): the agent device shows again at
        // once, its page no longer redirects, and the next refresh releases the merge.
        $ctx->db->exec("UPDATE devices SET client_id = {$other} WHERE id = {$inv2}");
        Assert::contains('/devices/' . $agent2 . '"', $list(), 'a target in another client never hides it');
        Assert::status(200, $admin->get('/clients/' . $cid . '/devices/' . $agent2), 'no redirect into another client');
        App::inventory()->refreshMerges($cid);
        Assert::same(null, $merged($agent2), 'released');
        // Unlinking the source shows the merged agent device again straight away.
        App::inventory()->unlink($cid, 'ninjaone');
        Assert::same(null, $merged($agent), 'released on unlink');
        Assert::contains('/devices/' . $agent . '"', $list());

        // Samba answers NTLM with build 0: not Windows; a NAS banner wins.
        Assert::same('Linux or Unix (Samba)', \Sentinel\Inventory\OsGuess::guess(['major' => 6, 'minor' => 1, 'build' => 0], [['port' => 445]])['os_name']);
        Assert::same('Synology DSM (NAS)', \Sentinel\Inventory\OsGuess::guess(['major' => 6, 'minor' => 1, 'build' => 0], [['port' => 5001, 'product' => 'Synology DiskStation']])['os_name']);
        Assert::same('Windows Server 2022', \Sentinel\Inventory\OsGuess::guess(['major' => 10, 'minor' => 0, 'build' => 20348], [['port' => 445]])['os_name']);

        // An OS guessed from the network: an expired release is a Warning worded as a guess; a build that is also a
        // long-term (LTSC) edition is not judged; the inventory source's own OS still raises the Fail.
        $rule = static fn (string $source, string $os, string $build): array => array_values(array_filter(\Sentinel\Inventory\DeviceRules::issues(
            ['source' => $source, 'os_name' => $os, 'os_build' => $build, 'av_state' => '', 'av_product' => '', 'av_definitions' => '', 'encryption' => '', 'device_class' => 'workstation',
             'last_contact' => gmdate('Y-m-d H:i:s')], []), static fn (array $i): bool => $i['code'] === 'os_unsupported'));
        Assert::same('warn', $rule('agent', 'Windows 10 21H1', '19043')[0]['severity'] ?? null, 'guessed: a warning');
        Assert::same([], $rule('agent', 'Windows 10 21H2', '19044'), 'an LTSC build is not judged from the network');
        Assert::same('fail', $rule('ninjaone', 'Windows 10 21H2', '19044')[0]['severity'] ?? null, 'the installed OS (from the source) still fails');

        // A banner-only guess never replaces one with a build; the NTLM name fills a name that is only the address.
        $nameless = $add('agent', 'fix-c', '10.94.0.30', '10.94.0.30', 'Windows Server 2022', '20348');
        $ctx->db->exec("INSERT INTO device_ports (device_id, port, first_seen, last_seen) VALUES ({$nameless}, 22, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $ctx->db->exec("UPDATE device_ports SET product = 'OpenSSH' WHERE device_id = {$nameless}");
        $save = new \ReflectionMethod(App::agentService(), 'saveOsGuess');
        $save->invoke(App::agentService(), $nameless, null);
        Assert::same('Windows Server 2022', (string) $ctx->db->query("SELECT os_name FROM devices WHERE id = {$nameless}")->fetchColumn(), 'the weaker guess is ignored');
        $save->invoke(App::agentService(), $nameless, ['major' => 10, 'minor' => 0, 'build' => 20348, 'netbios_name' => 'SRV-NB', 'dns_name' => '']);
        Assert::same('SRV-NB', (string) $ctx->db->query("SELECT name FROM devices WHERE id = {$nameless}")->fetchColumn(), 'the NetBIOS name replaces the bare address');
        $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id IN ({$cid}, {$other})");
    },

    'merged devices (1.50): MAC first; stale addresses, ranges two sites share and other names prove nothing; a unique name does' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Merge Rules Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00',
            'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $siteA = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $ctx->db->exec("INSERT INTO sites (client_id, name, is_default, created_at, updated_at) VALUES ({$cid}, 'Second office', 0, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $siteB = (int) $ctx->db->lastInsertId();
        $auth = static function (int $site, string $ranges) use ($ctx, $cid): void {
            $ctx->db->prepare("INSERT INTO internal_authorisations (client_id, site_id, approved_by_name, approved_by_role, approved_on, valid_from, valid_until, ranges, signed_payload, signature, recorded_by, created_at)
                               VALUES (:c, :s, 'Robin Example', 'Owner', UTC_DATE(), UTC_DATE(), UTC_DATE() + INTERVAL 300 DAY, :r, '', '', 1, UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 's' => $site, 'r' => $ranges]);
        };
        $auth($siteA, "10.94.0.0/24\n10.95.0.0/24");
        $auth($siteB, '10.95.0.0/24'); // both offices use 10.95.0.0/24
        $add = static function (string $source, string $sid, string $name, string $ip, string $mac = '', string $macs = '', ?string $contact = 'now') use ($ctx, $cid, $siteA): int {
            $ctx->db->prepare("INSERT INTO devices (client_id, site_id, source, source_id, name, dns_name, device_class, os_name, ip_addresses, mac, mac_addresses, last_contact, first_seen, last_seen)
                               VALUES (:c, :s, :src, :sid, :n, '', 'workstation', '', :ip, :mac, :macs, :lc, UTC_TIMESTAMP(), UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 's' => $siteA, 'src' => $source, 'sid' => $sid, 'n' => $name, 'ip' => $ip, 'mac' => $mac, 'macs' => $macs,
                           'lc' => $contact === 'now' ? gmdate('Y-m-d H:i:s') : $contact]);
            return (int) $ctx->db->lastInsertId();
        };
        $into = static fn (int $id): ?int => ($v = $ctx->db->query("SELECT merged_into FROM devices WHERE id = {$id}")->fetchColumn()) === null ? null : (int) $v;
        // 1. MAC: same machine at another address under another name.
        $byMacN = $add('ninjaone', 'rules-1', 'LAPTOP-KIM', '10.94.0.11', '', '00:1b:21:aa:00:01,00:1b:21:aa:00:02');
        $byMacA = $add('agent', 'rules-a1', '10.94.0.99', '10.94.0.99', '00:1b:21:aa:00:02');
        // 2a. Stale: NinjaOne's last address for a PC offline for three days.
        $staleN = $add('ninjaone', 'rules-2', 'OLD-PC', '10.94.0.30', '', '', gmdate('Y-m-d H:i:s', time() - 3 * 86400));
        $staleA = $add('agent', 'rules-a2', '10.94.0.30', '10.94.0.30');
        // 2b. An address in a range both offices use: the address alone can't tell the offices apart.
        $sharedN = $add('ninjaone', 'rules-3', 'BRANCH-PC', '10.95.0.40');
        $sharedA = $add('agent', 'rules-a3', '10.95.0.40', '10.95.0.40');
        // 3. Name: exactly one inventory device is called SRV-DB; the agent sees it at another address.
        $nameN = $add('ninjaone', 'rules-4', 'SRV-DB', '10.94.0.50');
        $nameA = $add('agent', 'rules-a4', 'srv-db.corp.example', '10.94.0.51');
        App::inventory()->refreshMerges($cid);
        Assert::same($byMacN, $into($byMacA), 'matched by MAC');
        Assert::same(null, $into($staleA), 'a stale address is not matched');
        Assert::same(null, $into($sharedA), 'an address two sites share is not matched on its own');
        Assert::same($nameN, $into($nameA), 'a unique name is matched');
        // A private MAC proves nothing.
        $privA = $add('agent', 'rules-a5', '10.94.0.98', '10.94.0.98', '02:1b:21:aa:00:01');
        $ctx->db->exec("UPDATE devices SET mac_addresses = '02:1b:21:aa:00:01' WHERE id = {$nameN}");
        App::inventory()->refreshMerges($cid);
        Assert::same(null, $into($privA), 'a private MAC is not matched');
        Assert::true($staleN > 0 && $sharedN > 0, 'fixtures made');
        // 1.50.1: a MAC two agent devices carry (a router or VPN server answering for others) identifies neither.
        $routerN = $add('ninjaone', 'rules-6', 'RAS-01', '10.94.0.70', '', '00:1b:21:cc:00:01');
        $behind1 = $add('agent', 'rules-a6', '10.94.0.71', '10.94.0.71', '00:1b:21:cc:00:01');
        $behind2 = $add('agent', 'rules-a7', '10.94.0.72', '10.94.0.72', '00:1b:21:cc:00:01');
        // A real MAC the inventory device doesn't list (while listing others) rules it out, even at the same address.
        $otherN = $add('ninjaone', 'rules-7', 'DESK-07', '10.94.0.60', '', '00:1b:21:bb:00:01');
        $otherA = $add('agent', 'rules-a8', '10.94.0.60', '10.94.0.60', '00:1b:21:bb:00:09');
        // A unique name only counts for a device seen lately (default names come back on other machines).
        $oldNameN = $add('ninjaone', 'rules-8', 'MACBOOK-PRO', '10.94.0.80', '', '', gmdate('Y-m-d H:i:s', time() - 5 * 86400));
        $oldNameA = $add('agent', 'rules-a9', 'MacBook-Pro.local', '10.94.0.81');
        // A lapsed authorisation still counts as that site's range.
        $ctx->db->exec("UPDATE internal_authorisations SET valid_until = UTC_DATE() - INTERVAL 1 DAY WHERE client_id = {$cid} AND site_id = {$siteB}");
        // An admin's merge is kept even without evidence.
        App::inventory()->setMerge($cid, $staleA, $staleN);
        App::inventory()->refreshMerges($cid);
        Assert::same([null, null], [$into($behind1), $into($behind2)], 'a shared MAC matches nothing');
        Assert::same(null, $into($otherA), 'a contradicting MAC blocks the address match');
        Assert::same(null, $into($oldNameA), 'a name of a device not seen lately is not matched');
        Assert::same(null, $into($sharedA), 'lapsed authorization: the range is still shared');
        Assert::same($staleN, $into($staleA), 'manual merge kept');
        Assert::true($routerN > 0 && $otherN > 0 && $oldNameN > 0, 'fixtures made');
    },
];
