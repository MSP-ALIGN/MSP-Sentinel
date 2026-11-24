<?php

declare(strict_types=1);

/**
 * End-to-end tests for MSP Align compliance (read-only): Administration > Integrations, linking a client, and the
 * client's Compliance page, against the mock MSP Align API (tests/mocks/align_mock.php on 127.0.0.1). Never
 * contacts a real MSP Align. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Compliance\AlignCompliance;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$alignBase = static fn (TestContext $ctx): string => str_replace('/ninja', '/align', (string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
$goodKey = 'msa_TESTKEY1_' . str_repeat('a', 32);

return [
    'MSP Align: findings map to crosswalk tags' => function (TestContext $ctx): void {
        Assert::same(['cfg_ports_services', 'net_firewall', 'net_remote_access'], AlignCompliance::tagsFor('port:203.0.113.5:3389'), 'RDP exposed');
        Assert::same(['cfg_ports_services', 'net_firewall'], AlignCompliance::tagsFor('port:203.0.113.5:445'));
        Assert::same(['email_auth'], AlignCompliance::tagsFor('email:harbour.example:dmarc_missing'));
        Assert::same(['ep_malware', 'ep_edr'], AlignCompliance::tagsFor('dev:ninjaone:11:av_off'));
        Assert::same(['ep_encryption', 'data_encrypt_rest'], AlignCompliance::tagsFor('dev:ninjaone:11:encryption_off'));
        Assert::same(['ep_lifecycle'], AlignCompliance::tagsFor('dev:ninjaone:11:os_unsupported'));
        Assert::same(['vuln_patch_os', 'vuln_remediation'], AlignCompliance::tagsFor('dev:ninjaone:11:patches_missing'));
        Assert::same(['net_remote_access', 'iam_mfa_remote'], AlignCompliance::tagsFor('web:203.0.113.11:443:vpn_portal'));
        Assert::same(['net_encrypt_transit'], AlignCompliance::tagsFor('tls:203.0.113.10:443:www.example:cert_expired'));
        Assert::same([], AlignCompliance::tagsFor('dev:ninjaone:11:stale'), 'no tag: not mapped');
        Assert::same([], AlignCompliance::tagsFor('nonsense'));
    },
    'MSP Align: admins connect it; the key is encrypted, never shown, and its permissions are checked' => function (TestContext $ctx) use ($alignBase, $goodKey): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('id="mspalign"', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => 'ftp://align.example', 'api_key' => $goodKey, 'enabled' => '1']);
        Assert::contains('must be an https:// address', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => $alignBase($ctx), 'api_key' => 'not-a-key', 'enabled' => '1']);
        Assert::contains('That is not an MSP Align API key', $admin->get('/admin/integrations')->body);
        // A key with only clients:read: the test says what's missing.
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => $alignBase($ctx) . '/api/v1', 'api_key' => 'msa_NOSCOPE1_' . str_repeat('b', 32), 'enabled' => '1']);
        Assert::same($alignBase($ctx), App::settings()->fresh('mspalign_url'), 'a pasted API address becomes the app address');
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign/test', []);
        Assert::contains('missing compliance:read', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => $alignBase($ctx), 'api_key' => $goodKey, 'enabled' => '1']);
        $raw = (string) $ctx->db->query("SELECT value FROM settings WHERE name = 'mspalign_api_key'")->fetchColumn();
        Assert::true($raw !== '' && !str_contains($raw, $goodKey), 'key stored encrypted');
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign/test', []);
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('Connected to MSP Align 2.41.0 as &quot;MSP Sentinel&quot;; the key can see 5 client(s)', $page);
        Assert::notContains($goodKey, $page, 'key never shown');
        Assert::notContains($goodKey, implode("\n", $ctx->db->query('SELECT details FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)), 'key never audited');
    },
    'MSP Align: a linked client shows its frameworks with Sentinel evidence per control, honestly' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Harbour Align Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        // A finished external scan with Remote Desktop open (a Fail finding).
        $ctx->db->prepare("INSERT INTO scan_jobs (client_id, job_type, trigger_type, status, payload, created_at, finished_at) VALUES (:c, 'ports', 'manual', 'done', '{}', UTC_TIMESTAMP(), UTC_TIMESTAMP())")->execute(['c' => $cid]);
        $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, target, status, first_seen, last_seen, opened_at)
                           VALUES (:c, 'port:203.0.113.5:3389', 'port', 'fail', 'Remote Desktop open to the internet', '203.0.113.5:3389', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())")->execute(['c' => $cid]);
        $page = $ctx->clientSection($admin, $cid, 'compliance');
        Assert::contains('Harbour Align Example — same name', $page, 'the exact-name match is suggested first');
        // Technicians can't link; an ID the key can't see is refused.
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'comptech'")->fetchColumn() === 0) {
            $ctx->createUser('comptech', 'technician', 'Comptech-Pass-01!');
        }
        $tech = $ctx->login('comptech', 'Comptech-Pass-01!');
        Assert::status(403, $tech->post('/clients/' . $cid . '/compliance/link', ['_csrf' => $tech->get('/')->csrf(), 'align_client_id' => '501']));
        $admin->submit('/clients/' . $cid . '/compliance', '/clients/' . $cid . '/compliance/link', ['align_client_id' => '999']);
        Assert::contains('not visible to the API key', $ctx->clientSection($admin, $cid, 'compliance'));

        $admin->submit('/clients/' . $cid . '/compliance', '/clients/' . $cid . '/compliance/link', ['align_client_id' => '501']);
        $page = $ctx->clientSection($admin, $cid, 'compliance');
        Assert::contains('Linked to Harbour Align Example in MSP Align', $page);
        Assert::contains('CIS Controls v8 IG1 (example)', $page);
        Assert::contains('MSP Align score 42%', $page);
        // 4.4 firewall: the open RDP finding. 3.11 transit encryption: checked by the scan, nothing open. 9.5 DMARC and
        // 10.1 anti-malware: in Sentinel's areas but not checked for this client (no email checks, no devices).
        $row = static function (string $page, string $ref): string {
            $i = strpos($page, '>' . $ref . '</span>');
            return $i === false ? '' : substr($page, $i, (int) strpos($page, '</tr>', $i) - $i);
        };
        Assert::contains('1 open problem(s)', $row($page, '4.4'));
        Assert::contains('Remote Desktop open to the internet', $row($page, '4.4'));
        Assert::contains('No problems found', $row($page, '3.11'));
        Assert::contains('Checked: external scan', $row($page, '3.11'));
        Assert::contains('Not checked yet', $row($page, '9.5'));
        Assert::contains('Not checked yet', $row($page, '10.1'));
        Assert::contains('Not met', $row($page, '3.11'), 'MSP Align\'s own status is shown as it is');
        Assert::contains('1 other control(s) are about things Sentinel doesn', $page, 'awareness training counted, not listed');
        Assert::notContains('<script>x', $page, 'escaped');
        Assert::contains('/align/clients/501/compliance/7"', $page, 'link into the configured MSP Align');
        Assert::contains('Not checked yet', $row($page, '6.4'), 'an external scan never vouches for MFA');

        // Read once an hour: a second view doesn't ask MSP Align again; "Read again" does.
        $count = static fn (): int => substr_count(str_replace('\\/', '/', (string) @file_get_contents($ctx->feedsLog)), '/align/api/v1/clients/501/compliance/7/controls');
        $before = $count();
        $ctx->clientSection($admin, $cid, 'compliance');
        Assert::same($before, $count(), 'cached');
        $tech->submit('/clients/' . $cid . '/compliance', '/clients/' . $cid . '/compliance/refresh', []);
        Assert::same($before, $count(), 'at most once a minute');
        Assert::contains('less than a minute ago', $ctx->clientSection($tech, $cid, 'compliance'));
        $ctx->db->exec("UPDATE align_cache SET fetched_at = UTC_TIMESTAMP() - INTERVAL 5 MINUTE, attempted_at = UTC_TIMESTAMP() - INTERVAL 5 MINUTE WHERE client_id = {$cid}");
        $tech->submit('/clients/' . $cid . '/compliance', '/clients/' . $cid . '/compliance/refresh', []);
        Assert::same($before + 1, $count(), 'read again on request (technicians may)');
        // Nothing was ever written to MSP Align.
        Assert::notContains('PATCH', (string) @file_get_contents($ctx->feedsLog));

        $admin->submit('/clients/' . $cid . '/compliance', '/clients/' . $cid . '/compliance/unlink', []);
        Assert::contains('Unlinked from MSP Align', $ctx->clientSection($admin, $cid, 'compliance'));
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM align_cache WHERE client_id = {$cid}")->fetchColumn(), 'cache cleared');
        // Turn it off again for the other tests.
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => '', 'clear_key' => '1', 'enabled' => '0']);
    },
];
