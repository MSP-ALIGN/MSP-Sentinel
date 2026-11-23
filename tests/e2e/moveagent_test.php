<?php

declare(strict_types=1);

/**
 * End-to-end tests for moving agents to a new Sentinel address: the same test installation is served on a second port
 * (the "new address"); the real agent proves the new address holds Sentinel's key before switching, keeps the move
 * in its state folder, refuses an address that can't prove it (a mock service), and goes back to its configured
 * address when the new one keeps failing. Nothing real is contacted. Made-up data only.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$mvDir = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent-move';
$mvRun = static fn (TestContext $ctx): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $mvDir($ctx) . '/agent.json']);
$mvSetup = static function (TestContext $ctx) use ($mvDir): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Move Example'")->fetchColumn();
    if ($cid > 0) {
        return [$cid, (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn()];
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Move Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
        'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-6001', 'notes' => '', 'ranges' => '10.94.0.0/24', 'confirm' => '1']);
    $page = $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body;
    preg_match('/SNE(-[A-Z2-9]{5}){4}/', $page, $m);
    @mkdir($mvDir($ctx), 0700, true);
    [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $mvDir($ctx) . '/agent.json']);
    if ($code !== 0) {
        throw new RuntimeException('Agent enrolment failed: ' . $out);
    }
    $app = require $ctx->configPath;
    $c = json_decode((string) file_get_contents($mvDir($ctx) . '/agent.json'), true);
    $c['nmap_path'] = $app['scanner']['nmap_path'];
    $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $mvDir($ctx) . '/arp'];
    file_put_contents($mvDir($ctx) . '/agent.json', json_encode($c));
    file_put_contents($mvDir($ctx) . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n");
    return [$cid, $site];
};
$freePort = static function (): int {
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) substr(strrchr(stream_socket_get_name($sock, false), ':'), 1);
    fclose($sock);
    return $port;
};

return [
    'agent moves: proved by the new address, kept in the state folder; impostors refused; a dead address falls back' => function (TestContext $ctx) use ($mvSetup, $mvRun, $mvDir, $freePort): void {
        [$cid, $site] = $mvSetup($ctx);
        $mvRun($ctx);
        $agentId = (int) $ctx->db->query("SELECT id FROM agents WHERE site_id = {$site} AND status = 'active'")->fetchColumn();
        Assert::same($ctx->baseUrl, $ctx->db->query("SELECT server_url FROM agents WHERE id = {$agentId}")->fetchColumn(), 'the agent reports its address');
        // The same installation on a second port: the "new address".
        $port = $freePort();
        $second = proc_open([PHP_BINARY, '-S', "127.0.0.1:{$port}", '-t', $ctx->root . '/public', $ctx->root . '/public/index.php'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, $ctx->root,
            ['SENTINEL_CONFIG' => $ctx->configPath, 'PATH' => (string) getenv('PATH'), 'SENTINEL_TEST_MODE' => '1']);
        for ($i = 0; $i < 50 && @fsockopen('127.0.0.1', $port) === false; $i++) {
            usleep(100000);
        }
        $newUrl = "http://127.0.0.1:{$port}";
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        try {
            // Validation; admins only.
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => 'ftp://sentinel.example', 'ca' => '']);
            Assert::contains('Enter the new address as https://host', $admin->get('/admin/system')->body);
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => $newUrl, 'ca' => 'not a certificate']);
            Assert::contains('The CA must be one or more PEM certificates', $admin->get('/admin/system')->body);
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'mvtech'")->fetchColumn() === 0) {
                $ctx->createUser('mvtech', 'technician', 'Mvtech-Pass-0001!');
            }
            $tech = $ctx->login('mvtech', 'Mvtech-Pass-0001!');
            Assert::status(403, $tech->post('/admin/system/agents-move', ['_csrf' => $tech->get('/')->csrf(), 'url' => $newUrl, 'ca' => '']));

            // The move: the new address proves itself, the agent switches and restarts onto it.
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => $newUrl, 'ca' => '']);
            [$code, $out] = $mvRun($ctx);
            Assert::same(75, $code, 'restarts to use the new address: ' . $out);
            Assert::contains('proved it holds this Sentinel', $out);
            $override = json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true);
            Assert::same($newUrl, $override['server']);
            Assert::same($ctx->baseUrl, json_decode((string) file_get_contents($mvDir($ctx) . '/agent.json'), true)['server'], 'the config is never changed');
            [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['status', '--config', $mvDir($ctx) . '/agent.json']);
            Assert::contains('→ ' . $newUrl . ' (moved from ' . $ctx->baseUrl . '): connected', $out);
            $mvRun($ctx);
            Assert::same($newUrl, $ctx->db->query("SELECT server_url FROM agents WHERE id = {$agentId}")->fetchColumn(), 'checks in at the new address');
            Assert::contains('moved', $admin->get('/admin/system')->body);
            // No move instruction once there.
            [$code, $out] = $mvRun($ctx);
            Assert::same(0, $code);

            // An impostor (a service that can't sign with Sentinel's key) gets nothing; the agent stays where it is.
            $feeds = parse_url((string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
            $impostor = 'http://127.0.0.1:' . $feeds['port'];
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => $impostor, 'ca' => '']);
            [$code, $out] = $mvRun($ctx);
            Assert::same(0, $code);
            Assert::contains('did not prove it is this Sentinel', $out);
            Assert::same($newUrl, json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true)['server'], 'still on the proven address');
            Assert::contains('not moved:', $admin->get('/admin/system')->body);
            [$code, $out] = $mvRun($ctx);
            Assert::notContains('did not prove', $out, 'not asked again after it failed');

            // A new address that keeps failing: after 10 failed check-ins the agent goes back to its configured address.
            $admin->submit('/admin/system', '/admin/system/agents-move', ['cancel' => '1']);
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode(['server' => 'http://127.0.0.1:' . $freePort(), 'ca_file' => null, 'failures' => 9]));
            [$code, $out] = $mvRun($ctx);
            Assert::same(75, $code, 'restarts on the configured address: ' . $out);
            Assert::contains('going back to the configured address', $out);
            Assert::true(!is_file($mvDir($ctx) . '/server-override.json'), 'override removed');
            [$code, $out] = $mvRun($ctx);
            Assert::same(0, $code);
            Assert::same($ctx->baseUrl, $ctx->db->query("SELECT server_url FROM agents WHERE id = {$agentId}")->fetchColumn(), 'back on the configured address');
            Assert::contains('agent.move_requested', implode("\n", $ctx->db->query('SELECT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)));
        } finally {
            // Never leave a move set for the other tests' agents.
            \Sentinel\Core\App::settings()->set('agent_move_url', '');
            proc_terminate($second);
            proc_close($second);
        }
    },
];
