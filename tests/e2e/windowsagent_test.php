<?php

declare(strict_types=1);

/**
 * End-to-end tests for the Windows agent's update path, run in the Linux test suite: the real agent in Windows mode
 * (testing.platform) writes only an update request, and the real Windows update task (bin/agent-update-task.php, in
 * test mode: test folders, no service) downloads the made-up release 9.9.9 from this server itself, checks it with the
 * pinned release key and installs it. Also: an answered request is never handled twice, a linked request file is
 * ignored, a forged key offer is refused, and test options are refused outside the test suite. Made-up data only.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$wDir = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent-windows';
$wRun = static fn (TestContext $ctx): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $wDir($ctx) . '/config/agent.json']);
$wSetup = static function (TestContext $ctx) use ($wDir): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Windows Example'")->fetchColumn();
    if ($cid > 0) {
        return [$cid, (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn()];
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Windows Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
        'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-8001', 'notes' => '', 'ranges' => '10.96.0.0/24', 'confirm' => '1']);
    $page = $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body;
    preg_match('/SNE(-[A-Z2-9]{5}){4}/', $page, $m);
    // As install-agent.ps1 lays it out: config, state and update folders apart; enrolment names the state folder.
    foreach (['config', 'state', 'update'] as $d) {
        @mkdir($wDir($ctx) . '/' . $d, 0700, true);
    }
    [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $wDir($ctx) . '/config/agent.json',
        '--state-dir', $wDir($ctx) . '/state'], ['SENTINEL_TEST_PLATFORM' => 'windows']);
    if ($code !== 0) {
        throw new RuntimeException('Agent enrolment failed: ' . $out);
    }
    $app = require $ctx->configPath;
    $c = json_decode((string) file_get_contents($wDir($ctx) . '/config/agent.json'), true);
    $c['nmap_path'] = $app['scanner']['nmap_path'];
    $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'platform' => 'windows',
        'arp_file' => $wDir($ctx) . '/arp', 'release_key' => $wDir($ctx) . '/config/release-key.pub', 'update_result_dir' => $wDir($ctx) . '/update'];
    file_put_contents($wDir($ctx) . '/config/agent.json', json_encode($c));
    file_put_contents($wDir($ctx) . '/arp', '');
    copy((string) $app['testing']['release_root'] . '/install/release-key.pub', $wDir($ctx) . '/config/release-key.pub');
    return [$cid, $site];
};
/** The Windows update task in test mode on the test folders. */
$task = static fn (TestContext $ctx, string $appDir, array $env = []): array => $ctx->cli('bin/agent-update-task.php', ['--config', $wDir($ctx) . '/config/agent.json',
    '--state', $wDir($ctx) . '/state', '--app', $appDir, '--result', $wDir($ctx) . '/update', '--key', $wDir($ctx) . '/config/release-key.pub', '--php', PHP_BINARY, '--no-service'], $env);
$fakeApp = static function (TestContext $ctx, string $name, string $version): string {
    $dir = dirname($ctx->configPath) . '/' . $name;
    @mkdir($dir . '/bin', 0700, true);
    file_put_contents($dir . '/VERSION', $version . "\n");
    file_put_contents($dir . '/bin/sentinel-agent.php', "<?php // installed {$version}\n");
    return $dir;
};

return [
    'Windows agent: the agent only asks; the SYSTEM update task downloads, checks and installs the signed release' => function (TestContext $ctx) use ($wSetup, $wRun, $wDir, $task, $fakeApp): void {
        [$cid, $site] = $wSetup($ctx);
        $c = json_decode((string) file_get_contents($wDir($ctx) . '/config/agent.json'), true);
        Assert::same($wDir($ctx) . '/state/state.json', $c['state_file'], 'state folder named at enrolment');
        $wRun($ctx); // reports its version
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $cid . '/agents', '/clients/' . $cid . '/agents/' . $agentId . '/update', []);
        [$code, $out] = $wRun($ctx);
        Assert::contains('Update to 9.9.9 requested', $out);
        Assert::true(is_file($wDir($ctx) . '/state/update-request') && !is_dir($wDir($ctx) . '/state/update'), 'only the request, no staged files');

        $app = $fakeApp($ctx, 'win-installed-agent', '1.25.0');
        [$code, $out] = $task($ctx, $app);
        Assert::same(0, $code, 'task: ' . $out);
        Assert::same("9.9.9\n", file_get_contents($app . '/VERSION'), 'installed');
        Assert::same("release 9.9.9\n", file_get_contents($app . '/src/marker.txt'));
        Assert::same("1.25.0\n", file_get_contents($app . '.old/VERSION'), 'previous version kept aside');
        Assert::true(is_file($wDir($ctx) . '/state/update-request'), 'the task never deletes in the agent\'s folder');
        // Run again: the request is answered, nothing happens.
        [$code, $out] = $task($ctx, $app);
        Assert::same([0, ''], [$code, trim($out)], 'an answered request is not handled twice');
        // The agent reports the result and removes its own request.
        $wRun($ctx);
        clearstatcache();
        Assert::true(!is_file($wDir($ctx) . '/state/update-request'), 'the agent removed its answered request');
        $r = json_decode((string) $ctx->db->query("SELECT update_result FROM agents WHERE id = {$agentId}")->fetchColumn(), true);
        Assert::same(['9.9.9', true], [$r['version'] ?? null, $r['ok'] ?? null]);
    },
    'Windows agent: linked requests ignored, forged key offers refused, test options refused outside the test suite' => function (TestContext $ctx) use ($wSetup, $wDir, $task, $fakeApp): void {
        $wSetup($ctx);
        $app = $fakeApp($ctx, 'win-installed-agent-2', '1.25.0');
        // A request file that is a link (to anything) is not read.
        file_put_contents($wDir($ctx) . '/elsewhere.json', json_encode(['version' => '9.9.9', 'request' => '2026-01-01 00:00:00']));
        @unlink($wDir($ctx) . '/state/update-request');
        symlink($wDir($ctx) . '/elsewhere.json', $wDir($ctx) . '/state/update-request');
        [$code, $out] = $task($ctx, $app);
        Assert::same(0, $code);
        Assert::same("1.25.0\n", file_get_contents($app . '/VERSION'), 'nothing installed through a link');
        unlink($wDir($ctx) . '/state/update-request');
        // A state folder redirected elsewhere (a junction on Windows; a symlink here) is not read at all.
        @mkdir($wDir($ctx) . '/elsewhere', 0700);
        file_put_contents($wDir($ctx) . '/elsewhere/update-request', json_encode(['version' => '9.9.9', 'request' => '2026-01-02 00:00:00']));
        @symlink($wDir($ctx) . '/elsewhere', $wDir($ctx) . '/state-link');
        [$code, $out] = $ctx->cli('bin/agent-update-task.php', ['--config', $wDir($ctx) . '/config/agent.json', '--state', $wDir($ctx) . '/state-link', '--app', $app,
            '--result', $wDir($ctx) . '/update', '--key', $wDir($ctx) . '/config/release-key.pub', '--php', PHP_BINARY, '--no-service']);
        Assert::same(0, $code);
        Assert::same("1.25.0\n", file_get_contents($app . '/VERSION'), 'nothing read through a redirected state folder');
        // A key offer not signed by this agent's Sentinel is refused; the pinned key stays.
        $before = file_get_contents($wDir($ctx) . '/config/release-key.pub');
        file_put_contents($wDir($ctx) . '/state/release-key-offer.json', json_encode(['payload' => json_encode(['type' => 'agent_release_key', 'agent_id' => 1,
            'key' => base64_encode(str_repeat('k', 32)), 'issued_at' => gmdate('Y-m-d\TH:i:s\Z')]), 'signature' => base64_encode(str_repeat('z', 64))]));
        file_put_contents($wDir($ctx) . '/state/update-request', json_encode(['kind' => 'pin', 'request' => gmdate('Y-m-d\TH:i:s\Z')]));
        [$code, $out] = $task($ctx, $app);
        Assert::same(1, $code);
        Assert::contains('not signed by this agent', $out);
        Assert::same($before, file_get_contents($wDir($ctx) . '/config/release-key.pub'));
        unlink($wDir($ctx) . '/state/update-request');
        // Outside the test suite, the test options are refused.
        [$code, $out] = $task($ctx, $app, ['SENTINEL_TEST_MODE' => '0']);
        Assert::same(2, $code);
        Assert::contains('test suite only', $out);
    },
];
