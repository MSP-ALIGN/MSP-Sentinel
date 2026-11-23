<?php

declare(strict_types=1);

/**
 * End-to-end tests for agent updates from Sentinel: an admin clicks Update; the real agent fetches the made-up release
 * (9.9.9, signed with a key made for this test run) from this server, checks it against its pinned release key and
 * stages it; the real root update helper (bin/agent-update-runner.php, in test mode on test folders) checks everything
 * again and installs it. Refusals: a release signed with another key, a staged file changed after staging, a
 * downgrade, test options outside the test suite. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$upDir = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent-update';
$upRun = static fn (TestContext $ctx): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $upDir($ctx) . '/agent.json']);
$releaseRoot = static fn (TestContext $ctx): string => (string) (require $ctx->configPath)['testing']['release_root'];
$upSetup = static function (TestContext $ctx) use ($upDir, $releaseRoot): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Update Example'")->fetchColumn();
    if ($cid > 0) {
        return [$cid, (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn()];
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Update Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
        'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-5001', 'notes' => '', 'ranges' => '10.93.0.0/24', 'confirm' => '1']);
    $page = $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body;
    preg_match('/SNE(-[A-Z2-9]{5}){4}/', $page, $m);
    @mkdir($upDir($ctx), 0700, true);
    [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $upDir($ctx) . '/agent.json']);
    if ($code !== 0) {
        throw new RuntimeException('Agent enrolment failed: ' . $out);
    }
    $app = require $ctx->configPath;
    $c = json_decode((string) file_get_contents($upDir($ctx) . '/agent.json'), true);
    $c['nmap_path'] = $app['scanner']['nmap_path'];
    // The agent pins the release key as the installer would (here: the made-up release's public key).
    $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $upDir($ctx) . '/arp',
        'release_key' => $upDir($ctx) . '/release-key.pub'];
    file_put_contents($upDir($ctx) . '/agent.json', json_encode($c));
    file_put_contents($upDir($ctx) . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n");
    copy($releaseRoot($ctx) . '/install/release-key.pub', $upDir($ctx) . '/release-key.pub');
    return [$cid, $site];
};
/** A pretend installed agent (the folder the helper replaces), at $version. */
$fakeApp = static function (TestContext $ctx, string $name, string $version): string {
    $dir = dirname($ctx->configPath) . '/' . $name;
    @mkdir($dir . '/bin', 0700, true);
    file_put_contents($dir . '/VERSION', $version . "\n");
    file_put_contents($dir . '/bin/sentinel-agent.php', "<?php // installed {$version}\n");
    return $dir;
};
$helper = static fn (TestContext $ctx, string $app, string $keyFile, array $env = []): array => $ctx->cli('bin/agent-update-runner.php',
    ['--app', $app, '--state', $upDir($ctx), '--key', $keyFile, '--no-systemd'], $env);

return [
    'agent updates: admins hand out the signed release; the agent stages it, the root helper checks it again and installs it' => function (TestContext $ctx) use ($upSetup, $upRun, $upDir, $fakeApp, $helper): void {
        [$cid, $site] = $upSetup($ctx);
        $upRun($ctx); // first check-in: the agent reports its version
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('can hand agents version 9.9.9', $admin->get('/admin/system')->body);
        $page = $ctx->clientSection($admin, $cid, 'agents');
        Assert::contains('Update to 9.9.9', $page);
        Assert::contains('Update all agents to 9.9.9', $page);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'uptech'")->fetchColumn() === 0) {
            $ctx->createUser('uptech', 'technician', 'Uptech-Pass-0001!');
        }
        $tech = $ctx->login('uptech', 'Uptech-Pass-0001!');
        Assert::status(403, $tech->post('/clients/' . $cid . '/agents/' . $agentId . '/update', ['_csrf' => $tech->get('/')->csrf()]), 'admins only');
        // Nothing is served to an agent nobody asked to update.
        $c = json_decode((string) file_get_contents($upDir($ctx) . '/agent.json'), true);
        $api = static fn (string $path, array $body): array => [(int) substr((string) (($h = @get_headers($ctx->baseUrl . $path, false, stream_context_create(['http' => ['method' => 'POST',
            'header' => "Authorization: Bearer {$c['token']}\r\nContent-Type: application/json\r\n", 'content' => json_encode($body), 'ignore_errors' => true]])))[0] ?? ''), 9, 3)];
        Assert::same([404], $api('/agent/v1/update/manifest', ['version' => '9.9.9']), 'not asked: nothing served');

        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agentId . '/update', []);
        Assert::same('9.9.9', $ctx->db->query("SELECT update_to FROM agents WHERE id = {$agentId}")->fetchColumn());
        Assert::same([404], $api('/agent/v1/update/file', ['version' => '9.9.9', 'path' => '../../config/config.php']), 'only release files');
        Assert::same([404], $api('/agent/v1/update/file', ['version' => '9.9.9', 'path' => 'tests/run.php']), 'never anything outside the signed list');
        [$code, $out] = $upRun($ctx);
        Assert::contains('Update to 9.9.9 staged', $out);
        Assert::true(is_file($upDir($ctx) . '/update-request') && is_file($upDir($ctx) . '/update/files/src/marker.txt'), 'staged for the helper');
        // The root helper installs it (test mode: a pretend installed agent folder, no systemd).
        $app = $fakeApp($ctx, 'installed-agent', '1.22.0');
        [$code, $out] = $helper($ctx, $app, $upDir($ctx) . '/release-key.pub');
        Assert::same(0, $code, 'helper: ' . $out);
        Assert::same("9.9.9\n", file_get_contents($app . '/VERSION'), 'installed');
        Assert::same("release 9.9.9\n", file_get_contents($app . '/src/marker.txt'));
        Assert::same("1.22.0\n", file_get_contents($app . '.old/VERSION'), 'previous version kept aside');
        Assert::true(!is_file($upDir($ctx) . '/update-request') && !is_dir($upDir($ctx) . '/update'), 'request and staging cleaned up');
        // The agent reports the helper's result.
        $upRun($ctx);
        $r = json_decode((string) $ctx->db->query("SELECT update_result FROM agents WHERE id = {$agentId}")->fetchColumn(), true);
        Assert::same(['9.9.9', true], [$r['version'], $r['ok']]);
        Assert::contains('Updated to 9.9.9', $ctx->clientSection($admin, $cid, 'agents'));
        Assert::contains('agent.update_requested', implode("\n", $ctx->db->query('SELECT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)));
    },
    'agent updates: other keys, changed files, downgrades and test options are all refused' => function (TestContext $ctx) use ($upSetup, $upRun, $upDir, $fakeApp, $helper): void {
        [$cid, $site] = $upSetup($ctx);
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        // A fresh request each time, as the Update button makes (each has its own identifier).
        $n = 0;
        $ask = static function () use ($ctx, $agentId, &$n): void {
            $n++;
            $ctx->db->exec("UPDATE agents SET update_to = '9.9.9', update_requested_at = UTC_TIMESTAMP() + INTERVAL {$n} MINUTE WHERE id = {$agentId}");
        };
        $ctx->db->exec("UPDATE agents SET update_result = NULL WHERE id = {$agentId}");
        $ask();
        // A file changed after staging (the agent's own user could): the helper's own check of its copy refuses it.
        [$code, $out] = $upRun($ctx);
        Assert::contains('staged', $out);
        file_put_contents($upDir($ctx) . '/update/files/src/marker.txt', "tampered\n");
        $app = $fakeApp($ctx, 'installed-agent-2', '1.22.0');
        [$code, $out] = $helper($ctx, $app, $upDir($ctx) . '/release-key.pub');
        Assert::same(1, $code);
        Assert::contains('does not match the signed release', $out);
        Assert::same("1.22.0\n", file_get_contents($app . '/VERSION'), 'nothing installed');
        // A downgrade (the installed agent is newer) is refused.
        $ask();
        @unlink($upDir($ctx) . '/update-result.json');
        $upRun($ctx);
        $newer = $fakeApp($ctx, 'installed-agent-3', '10.0.0');
        [$code, $out] = $helper($ctx, $newer, $upDir($ctx) . '/release-key.pub');
        Assert::same(1, $code);
        Assert::contains('not newer', $out);
        Assert::same("10.0.0\n", file_get_contents($newer . '/VERSION'));
        // Test options are refused outside the test suite.
        [$code, $out] = $helper($ctx, $app, $upDir($ctx) . '/release-key.pub', ['SENTINEL_TEST_MODE' => '0']);
        Assert::same(2, $code);
        Assert::contains('only allowed in the test suite', $out);
        // An agent that pins another release key refuses the release before staging anything, and says so.
        $other = sodium_crypto_sign_keypair();
        file_put_contents($upDir($ctx) . '/release-key.pub', base64_encode(sodium_crypto_sign_publickey($other)));
        @unlink($upDir($ctx) . '/update-request');
        $ask(); // the downgrade's result is still waiting to be reported: it must not end this newer request
        [$code, $out] = $upRun($ctx);
        Assert::contains('not signed with the release key', $out);
        Assert::true(!is_file($upDir($ctx) . '/update-request'), 'nothing staged');
        $r = json_decode((string) $ctx->db->query("SELECT update_result FROM agents WHERE id = {$agentId}")->fetchColumn(), true);
        Assert::same(false, $r['ok']);
        Assert::same('', $ctx->db->query("SELECT update_to FROM agents WHERE id = {$agentId}")->fetchColumn(), 'a refusal ends the request (no retry loop)');
        Assert::contains('Update to 9.9.9 refused', $ctx->clientSection($ctx->login('admin', 'Admin-Pass-0001!'), $cid, 'agents'));
    },
];
