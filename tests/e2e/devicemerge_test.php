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
        $noName = $add('agent', 'agent-b', '', '', '10.93.0.20');                          // same address, no name: merged
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
];
