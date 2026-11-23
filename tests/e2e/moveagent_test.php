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
            $pw = 'Admin-Pass-0001!';
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => $newUrl, 'ca' => '', 'password' => 'wrong-password']);
            Assert::contains('Enter your password to confirm', $admin->get('/admin/system')->body, 'a move needs the admin\'s password');
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => 'ftp://sentinel.example', 'ca' => '', 'password' => $pw]);
            Assert::contains('Enter the new address as https://host', $admin->get('/admin/system')->body);
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => $newUrl, 'ca' => 'not a certificate', 'password' => $pw]);
            Assert::contains('The CA must be one or more PEM certificates', $admin->get('/admin/system')->body);
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'mvtech'")->fetchColumn() === 0) {
                $ctx->createUser('mvtech', 'technician', 'Mvtech-Pass-0001!');
            }
            $tech = $ctx->login('mvtech', 'Mvtech-Pass-0001!');
            Assert::status(403, $tech->post('/admin/system/agents-move', ['_csrf' => $tech->get('/')->csrf(), 'url' => $newUrl, 'ca' => '', 'password' => 'Mvtech-Pass-0001!']));
            // A move written straight into the database (no app key) is ignored.
            $ctx->db->prepare("REPLACE INTO settings (name, value) VALUES ('agent_move', :v)")->execute(['v' => json_encode(['url' => $newUrl, 'ca' => '', 'requested_at' => '2026-01-01 00:00:00', 'id' => 'forged'])]);
            [$code, $out] = $mvRun($ctx);
            Assert::same(0, $code, 'no move from a forged setting');
            Assert::true(!is_file($mvDir($ctx) . '/server-override.json'), 'not moved');

            // The move: the new address proves itself, the agent switches and restarts onto it.
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => $newUrl, 'ca' => '', 'password' => $pw]);
            // Sentinel signs proofs only for the configured address: a relay from another address gets nothing.
            $prove = static function (string $server) use ($ctx, $agentId): array {
                $raw = (string) @file_get_contents($ctx->baseUrl . '/agent/v1/prove', false, stream_context_create(['http' => ['method' => 'POST',
                    'header' => "Content-Type: application/json\r\n", 'content' => json_encode(['agent_id' => $agentId, 'nonce' => str_repeat('ab', 16), 'server' => $server]), 'ignore_errors' => true]]));
                return (array) json_decode($raw, true);
            };
            Assert::true(!isset($prove('https://relay.example')['signature']), 'no proof for another address');
            $signed = $prove($newUrl);
            Assert::same($newUrl, json_decode((string) ($signed['payload'] ?? ''), true)['server'] ?? null, 'the proof names the address, and needs no token');
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
            // Agents older than 1.23.1 are never sent a move (they would send their token before any proof).
            $cfg = json_decode((string) file_get_contents($mvDir($ctx) . '/agent.json'), true);
            $answer = json_decode((string) @file_get_contents($ctx->baseUrl . '/agent/v1/poll', false, stream_context_create(['http' => ['method' => 'POST',
                'header' => "Authorization: Bearer {$cfg['token']}\r\nContent-Type: application/json\r\n",
                'content' => json_encode(['idle' => true, 'version' => '1.23.0', 'server' => $ctx->baseUrl, 'running' => []]), 'ignore_errors' => true]])), true);
            Assert::true(is_array($answer) && !isset($answer['move']), 'no move for a 1.23.0 agent');
            $ctx->db->exec("UPDATE agents SET server_url = " . $ctx->db->quote($newUrl) . " WHERE id = {$agentId}"); // that test poll changed it
            // "Move complete": no more instructions, and recall keeps moved agents where they are.
            $admin->submit('/admin/system', '/admin/system/agents-move', ['complete' => '1', 'password' => $pw]);
            Assert::contains('complete', $admin->get('/admin/system')->body);
            $o = json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true);
            $o['recall_checked_at'] = gmdate('Y-m-d\TH:i:s\Z', time() - 7 * 3600);
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode($o));
            [$code, $out] = $mvRun($ctx);
            Assert::same(0, $code, 'still moved after recall check: ' . $out);
            Assert::same($newUrl, json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true)['server']);
            // A move file left by a 1.23.0 agent (no enrolment binding) is adopted, not dropped.
            $legacy = json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true);
            unset($legacy['agent_id'], $legacy['key']);
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode($legacy));
            [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['status', '--config', $mvDir($ctx) . '/agent.json']);
            Assert::contains('→ ' . $newUrl . ' (moved from', $out, 'legacy move kept');
            Assert::same($agentId, json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true)['agent_id'] ?? null, 'and bound now');

            // An impostor (a service that can't sign with Sentinel's key) gets nothing; the agent stays where it is.
            $feeds = parse_url((string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
            $impostor = 'http://127.0.0.1:' . $feeds['port'];
            $admin->submit('/admin/system', '/admin/system/agents-move', ['url' => $impostor, 'ca' => '', 'password' => $pw]);
            [$code, $out] = $mvRun($ctx);
            Assert::same(0, $code);
            Assert::same($newUrl, json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true)['server'], 'still on the proven address');
            Assert::contains('not moved:', $admin->get('/admin/system')->body);
            [$code, $out] = $mvRun($ctx);
            Assert::notContains('did not prove', $out, 'not asked again after it failed');

            // Recall: cancelling the move brings moved agents back (they ask their configured address every few hours).
            $admin->submit('/admin/system', '/admin/system/agents-move', ['cancel' => '1', 'password' => $pw]);
            $o = json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true);
            $o['recall_checked_at'] = gmdate('Y-m-d\TH:i:s\Z', time() - 7 * 3600);
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode($o));
            [$code, $out] = $mvRun($ctx);
            Assert::same(75, $code, 'recalled: ' . $out);
            Assert::contains('no longer wants this agent at ' . $newUrl, $out);
            Assert::true(!is_file($mvDir($ctx) . '/server-override.json'), 'override removed');
            $base = ['agent_id' => $agentId, 'key' => substr(hash('sha256', (string) json_decode((string) file_get_contents($mvDir($ctx) . '/agent.json'), true)['server_public_key']), 0, 16)];
            // Right after a move (probation), a dead new address sends the agent back, and Sentinel is told.
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode($base + ['server' => 'http://127.0.0.1:' . $freePort(), 'ca_file' => null, 'failures' => 9,
                'moved_at' => gmdate('Y-m-d\TH:i:s\Z'), 'recall_checked_at' => gmdate('Y-m-d\TH:i:s\Z')]));
            [$code, $out] = $mvRun($ctx);
            Assert::same(75, $code, 'restarts on the configured address: ' . $out);
            Assert::contains('Going back to the configured address', $out);
            Assert::true(!is_file($mvDir($ctx) . '/server-override.json'), 'override removed');
            Assert::contains('went back to its configured address', (string) $ctx->db->query("SELECT move_result FROM agents WHERE id = {$agentId}")->fetchColumn(), 'reported (no loop)');
            // A 200 that isn't Sentinel's answer (a web page) is a failed check-in, never a good one.
            $page = 'http://127.0.0.1:' . (require $ctx->configPath)['testing']['redirect_connections']['10.90.0.20:80'];
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode($base + ['server' => $page, 'ca_file' => null, 'failures' => 0, 'good' => 0,
                'moved_at' => gmdate('Y-m-d\TH:i:s\Z'), 'recall_checked_at' => gmdate('Y-m-d\TH:i:s\Z')]));
            $mvRun($ctx);
            $o = json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true);
            Assert::same([1, 0], [(int) $o['failures'], (int) $o['good']], 'counted as a failure only');
            // After probation the move is permanent: an outage at the new address doesn't send it back.
            $dead = 'http://127.0.0.1:' . $freePort();
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode($base + ['server' => $dead, 'ca_file' => null, 'failures' => 9, 'good' => 50,
                'moved_at' => gmdate('Y-m-d\TH:i:s\Z', time() - 3 * 86400), 'recall_checked_at' => gmdate('Y-m-d\TH:i:s\Z')]));
            [$code, $out] = $mvRun($ctx);
            Assert::true($code !== 75, 'no fallback after probation');
            Assert::same($dead, json_decode((string) file_get_contents($mvDir($ctx) . '/server-override.json'), true)['server']);
            // An override written for another enrolment is ignored.
            file_put_contents($mvDir($ctx) . '/server-override.json', json_encode(['agent_id' => $agentId + 1000] + $base + ['server' => $dead, 'moved_at' => gmdate('Y-m-d\TH:i:s\Z')]));
            [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['status', '--config', $mvDir($ctx) . '/agent.json']);
            Assert::contains('→ ' . $ctx->baseUrl . ': connected', $out, 'other enrolment\'s override ignored');
            @unlink($mvDir($ctx) . '/server-override.json');
            [$code, $out] = $mvRun($ctx);
            Assert::same(0, $code);
            Assert::same($ctx->baseUrl, $ctx->db->query("SELECT server_url FROM agents WHERE id = {$agentId}")->fetchColumn(), 'back on the configured address');
            Assert::contains('agent.move_requested', implode("\n", $ctx->db->query('SELECT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)));
        } finally {
            // Never leave a move set for the other tests' agents.
            \Sentinel\Core\App::settings()->setSecret('agent_move', '');
            proc_terminate($second);
            proc_close($second);
        }
    },
];
