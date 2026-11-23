<?php

declare(strict_types=1);

/**
 * End-to-end tests for agent updates from Sentinel: an admin clicks Update; the real agent fetches the made-up release
 * (9.9.9, signed with a key made for this test run) from this server, checks it against its pinned release key and
 * stages it; the real root update helper (bin/agent-update-runner.php, in test mode on test folders) checks everything
 * again and installs it. Refusals: a release signed with another key, a staged file changed after staging, a
 * downgrade, test options outside the test suite. On Linux the helper starts through a launcher outside the code
 * folder (install/linux/agent-update-launcher.php), which repairs an update stopped half-way (code folder missing,
 * .old there) first. Made-up data only.
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
        'release_key' => $upDir($ctx) . '/release-key.pub', 'update_result_dir' => $upDir($ctx) . '-results'];
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
// The root helper in test mode: test folders, no systemd; its results go to a separate folder (root-owned in production).
$helper = static fn (TestContext $ctx, string $app, string $keyFile, array $env = []): array => $ctx->cli('bin/agent-update-runner.php',
    ['--app', $app, '--state', $upDir($ctx), '--key', $keyFile, '--result', $upDir($ctx) . '-results', '--no-systemd'], $env);

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
        Assert::true(!is_file($upDir($ctx) . '/update-request'), 'the request was taken (by the collector, as the agent\'s user)');
        Assert::true(is_file($upDir($ctx) . '-results/result.json') && !is_file($upDir($ctx) . '/update-result.json'), 'the result is outside the agent\'s folder');
        // The agent reports the helper's result, then cleans up its own staging folder (root never deletes there).
        $upRun($ctx);
        Assert::true(!is_dir($upDir($ctx) . '/update'), 'staging cleaned up by the agent');
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
            $ctx->db->exec("UPDATE agents SET update_to = '9.9.9', update_requested_at = UTC_TIMESTAMP() + INTERVAL {$n} MINUTE, update_handouts = 0, update_handed_at = NULL WHERE id = {$agentId}");
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
        Assert::contains('not matching the signed release', $out);
        Assert::same("1.22.0\n", file_get_contents($app . '/VERSION'), 'nothing installed');
        // A downgrade (the installed agent is newer) is refused.
        $ask();
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
    'agent updates: root never follows the agent\'s symlinks; a failing self-check, a planted folder and a stuck helper' => function (TestContext $ctx) use ($upSetup, $upRun, $upDir, $fakeApp, $helper, $releaseRoot): void {
        [$cid, $site] = $upSetup($ctx);
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        $state = $upDir($ctx);
        copy($releaseRoot($ctx) . '/install/release-key.pub', $state . '/release-key.pub'); // the right key again
        // The agent's user plants symlinks where the old helper wrote: nothing is written through them.
        $victim = dirname($ctx->configPath) . '/victim.sh';
        file_put_contents($victim, "# untouched\n");
        @unlink($state . '/update-result.json');
        symlink($victim, $state . '/update-result.json');
        file_put_contents($state . '/update-request', json_encode(['version' => '$(touch${IFS}pwned)', 'request' => 'x']));
        [$code, $out] = $helper($ctx, $fakeApp($ctx, 'installed-agent-4', '1.22.0'), $state . '/release-key.pub');
        Assert::same(1, $code);
        Assert::contains('No valid update request', $out, 'a version that is not x.y.z is never used');
        Assert::same("# untouched\n", file_get_contents($victim), 'nothing written through the symlink');
        Assert::true(!str_contains((string) file_get_contents($upDir($ctx) . '-results/result.json'), 'pwned'), 'the bad version is not echoed');
        unlink($state . '/update-result.json');
        // A request planted as a folder is removed (no loop).
        @mkdir($state . '/update-request');
        $helper($ctx, $fakeApp($ctx, 'installed-agent-5', '1.22.0'), $state . '/release-key.pub');
        Assert::true(!file_exists($state . '/update-request'), 'a folder request is removed');
        // A release whose self-check fails on this appliance (signed: 9.9.10) is not installed.
        $bad = dirname($ctx->configPath) . '/release-bad';
        @mkdir($bad . '/files/bin', 0700, true);
        @mkdir($bad . '/files/install', 0700, true);
        file_put_contents($bad . '/files/VERSION', "9.9.10\n");
        file_put_contents($bad . '/files/bin/sentinel-agent.php', "<?php echo \"selfcheck failed: needs the made-up extension\\n\"; exit(1);\n");
        file_put_contents($bad . '/files/install/agent-install.sh', "#!/bin/sh\n");
        $m = \Sentinel\System\ReleaseManifest::canonical(\Sentinel\System\ReleaseManifest::build($bad . '/files', '9.9.10', ['VERSION', 'bin/sentinel-agent.php', 'install/agent-install.sh']));
        $secret = (string) file_get_contents(dirname($ctx->feedsLog) . '/test-release.key');
        \Sentinel\AgentClient\Updater::removeTree($state . '/update');
        mkdir($state . '/update/files', 0700, true);
        foreach (['VERSION', 'bin/sentinel-agent.php', 'install/agent-install.sh'] as $f) {
            @mkdir(dirname($state . '/update/files/' . $f), 0700, true);
            copy($bad . '/files/' . $f, $state . '/update/files/' . $f);
        }
        file_put_contents($state . '/update/agent-manifest.json', $m);
        file_put_contents($state . '/update/agent-manifest.sig', \Sentinel\System\ReleaseManifest::sign($m, $secret));
        file_put_contents($state . '/update-request', json_encode(['version' => '9.9.10', 'request' => '2026-01-01 00:00:00']));
        $app = $fakeApp($ctx, 'installed-agent-6', '1.22.0');
        [$code, $out] = $helper($ctx, $app, $state . '/release-key.pub');
        Assert::same(1, $code);
        Assert::contains('did not pass its self-check', $out);
        Assert::same("1.22.0\n", file_get_contents($app . '/VERSION'), 'not installed');
        Assert::true(!is_dir($app . '.new'), 'the new folder was removed');
        // A request the helper already answered but couldn't remove is cleaned up by the agent (it never blocks later updates).
        $answered = json_decode((string) file_get_contents($upDir($ctx) . '-results/result.json'), true);
        file_put_contents($state . '/update-request', json_encode(['version' => $answered['version'], 'request' => $answered['request']]));
        $upd = new \Sentinel\AgentClient\Updater(new \Sentinel\AgentClient\Http($ctx->baseUrl, null, null, true), $state . '/release-key.pub', $state, static fn () => null,
            '', 0, 0, 0, $upDir($ctx) . '-results');
        Assert::same(false, $upd->pending(), 'an answered request is not pending');
        Assert::true(!is_file($state . '/update-request'), 'and the agent removed it');
        // A helper that never answers: after 3 hand-outs the request ends, and scans flow in between.
        $ctx->db->exec("UPDATE agents SET update_to = '9.9.9', update_requested_at = UTC_TIMESTAMP(), update_handouts = 3, update_handed_at = UTC_TIMESTAMP() - INTERVAL 31 MINUTE WHERE id = {$agentId}");
        $upRun($ctx);
        Assert::same('', $ctx->db->query("SELECT update_to FROM agents WHERE id = {$agentId}")->fetchColumn(), 'ended');
        Assert::contains('No result from the agent', (string) $ctx->db->query("SELECT update_result FROM agents WHERE id = {$agentId}")->fetchColumn());
        $ctx->db->exec("UPDATE agents SET update_to = '9.9.9', update_requested_at = UTC_TIMESTAMP(), update_handouts = 1, update_handed_at = UTC_TIMESTAMP() - INTERVAL 5 MINUTE WHERE id = {$agentId}");
        $ctx->login('admin', 'Admin-Pass-0001!')->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/scan', ['reason' => 'While an update waits']);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM agent_jobs WHERE site_id = {$site}")->fetchColumn();
        $upRun($ctx);
        Assert::true(in_array($ctx->db->query("SELECT status FROM agent_jobs WHERE id = {$job}")->fetchColumn(), ['done', 'partial'], true), 'a scan runs while the update waits for its next attempt');
    },
    'agent updates (Linux): the launcher outside the code folder repairs an update stopped half-way, then runs the helper' => function (TestContext $ctx) use ($upSetup, $upRun, $upDir, $fakeApp, $releaseRoot): void {
        [, $site] = $upSetup($ctx);
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        $state = $upDir($ctx);
        $results = $state . '-results';
        $root = dirname(__DIR__, 2);
        copy($releaseRoot($ctx) . '/install/release-key.pub', $state . '/release-key.pub');
        $launch = static fn (array $args, array $env = []): array => $ctx->cli('install/linux/agent-update-launcher.php', $args, $env);
        // A pretend installed agent with the helper in it, as /opt/sentinel-agent has.
        $app = $fakeApp($ctx, 'installed-agent-8', '1.22.0');
        foreach (['bin/agent-update-runner.php', 'src/System/ReleaseManifest.php', 'src/Agent/Signer.php', 'src/System/ReleaseKeyOffer.php'] as $f) {
            @mkdir(dirname($app . '/' . $f), 0700, true);
            copy($root . '/' . $f, $app . '/' . $f);
        }

        // A power cut between the helper's two renames: the code folder is gone, the previous one is .old.
        rename($app, $app . '.old');
        Assert::true(!is_file($app . '/bin/agent-update-runner.php'), 'the helper itself is in the missing folder');
        // The agent's start (ExecStartPre --repair-only) puts it back; no update request is needed (it was taken already).
        [$code, $out] = $launch(['--repair-only', '--app', $app, '--result', $results]);
        Assert::same(0, $code, $out);
        Assert::contains('Restored ' . $app, $out);
        Assert::same("1.22.0\n", file_get_contents($app . '/VERSION'), 'repaired');
        Assert::true(!is_dir($app . '.old'), 'moved back, not copied');
        [$code, $out] = $launch(['--repair-only', '--app', $app, '--result', $results]);
        Assert::same(0, $code, $out);
        Assert::notContains('Restored', $out, 'nothing to repair: nothing changed');
        // While the helper runs (it holds the update lock), the agent's start leaves the folders to it.
        rename($app, $app . '.old');
        $lock = fopen($results . '/update.lock', 'c');
        flock($lock, LOCK_EX);
        [$code, $out] = $launch(['--repair-only', '--app', $app, '--result', $results]);
        flock($lock, LOCK_UN);
        fclose($lock);
        Assert::same(0, $code, $out);
        Assert::true(!is_dir($app) && is_dir($app . '.old'), 'no repair in the middle of an update');

        // The update service: the launcher repairs first, then runs the helper from the restored folder, which installs
        // the staged release.
        $ctx->db->exec("UPDATE agents SET update_to = '9.9.9', update_requested_at = UTC_TIMESTAMP() + INTERVAL 30 MINUTE, update_handouts = 0, update_handed_at = NULL, update_result = NULL WHERE id = {$agentId}");
        [, $out] = $upRun($ctx);
        Assert::contains('staged', $out);
        [$code, $out] = $launch(['--app', $app, '--state', $state, '--key', $state . '/release-key.pub', '--result', $results, '--no-systemd']);
        Assert::same(0, $code, $out);
        Assert::contains('Restored ' . $app, $out);
        Assert::same("9.9.9\n", file_get_contents($app . '/VERSION'), 'installed by the helper the launcher started');
        Assert::same("1.22.0\n", file_get_contents($app . '.old/VERSION'), 'the restored version was kept aside as usual');
        $r = json_decode((string) file_get_contents($results . '/result.json'), true);
        Assert::same(['9.9.9', true], [$r['version'], $r['ok']]);
        Assert::true(!is_file($state . '/update-request'), 'the request was taken');

        // Test options are refused outside the test suite.
        [$code, $out] = $launch(['--repair-only', '--app', $app], ['SENTINEL_TEST_MODE' => '0']);
        Assert::same(2, $code);
        Assert::contains('only allowed in the test suite', $out);

        // The units start it from its fixed place; the update service keeps its hardening; the installer writes it.
        $unit = (string) file_get_contents($root . '/install/templates/sentinel-agent-update.service');
        Assert::contains("\nExecStart=__PHP__ /usr/local/lib/sentinel-agent/update-launcher.php\n", $unit);
        Assert::contains("\nExecStartPre=-+/usr/bin/install -D -o root -g root -m 0644 __ROOT__/install/linux/agent-update-launcher.php /usr/local/lib/sentinel-agent/update-launcher.php\n", $unit);
        Assert::notContains('agent-update-runner.php', implode("\n", array_filter(explode("\n", $unit), static fn (string $l): bool => !str_starts_with($l, '#'))));
        foreach (["\nProtectSystem=strict\n", "\nReadWritePaths=/opt /etc/systemd/system /etc/sentinel-agent /var/lib/sentinel-agent-update /var/lib/sentinel-agent\n", "\nUMask=0027\n"] as $line) {
            Assert::contains($line, $unit);
        }
        Assert::contains("\nExecStartPre=-+__PHP__ /usr/local/lib/sentinel-agent/update-launcher.php --repair-only\n", (string) file_get_contents($root . '/install/templates/sentinel-agent.service'));
        exec('bash ' . escapeshellarg($root . '/install/agent-install.sh') . ' --dry-run --skip-os-check --upgrade 2>&1', $lines, $rc);
        $dry = implode("\n", $lines);
        Assert::same(0, $rc, $dry);
        Assert::contains('install -o root -g root -m 0644 ' . $root . '/install/linux/agent-update-launcher.php /usr/local/lib/sentinel-agent/update-launcher.php', $dry, '--upgrade refreshes the launcher');
        Assert::true(\Sentinel\System\ReleaseManifest::releaseFile('install/linux/agent-update-launcher.php'), 'remote updates carry it too');
    },
];
