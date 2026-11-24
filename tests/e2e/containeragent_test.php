<?php

declare(strict_types=1);

/**
 * End-to-end tests for agents in containers (1.36): an agent in the Docker image (SENTINEL_AGENT_CONTAINER=docker)
 * reports it at check-in; Sentinel never hands it an in-place update (it is updated by pulling a new image) and says
 * so; the image files are unprivileged, read-only and host-networked. With SENTINEL_TEST_DOCKER_IMAGE set (an image
 * built from docker/agent/Dockerfile and a reachable Docker daemon), the real image enrols and checks in too.
 * Made-up names and documentation addresses only; nothing real is scanned.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$ctDir = static fn (TestContext $ctx): string => dirname($ctx->configPath) . '/agent-container';
$ctSetup = static function (TestContext $ctx) use ($ctDir): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Container Example'")->fetchColumn();
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    if ($cid === 0) {
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Container Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00',
            'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Kim Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-3601', 'notes' => '', 'ranges' => '10.91.0.0/24', 'confirm' => '1']);
    }
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    return [$cid, $site, $admin];
};
$enrolCode = static function ($admin, int $cid, int $site): string {
    preg_match('/SNE(-[A-Z2-9]{5}){4}/', $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body, $m);
    return $m[0] ?? 'missing';
};

return [
    'container agents: a Docker agent says so, gets no in-place update, and the page says to pull the image' => function (TestContext $ctx) use ($ctDir, $ctSetup, $enrolCode): void {
        [$cid, $site, $admin] = $ctSetup($ctx);
        @mkdir($ctDir($ctx), 0700, true);
        $cfg = $ctDir($ctx) . '/agent.json';
        @unlink($cfg);
        [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $enrolCode($admin, $cid, $site), '--config', $cfg]);
        Assert::same(0, $code, 'enrolled: ' . $out);
        $agentId = (int) json_decode((string) file_get_contents($cfg), true)['agent_id'];
        // An update was asked for before (e.g. from an older install): a Docker agent ends it at check-in.
        App::agents()->requestUpdate($agentId, '99.0.0', 1);
        [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $cfg], ['SENTINEL_AGENT_CONTAINER' => 'docker']);
        Assert::same(0, $code, 'checked in: ' . $out);
        $row = $ctx->db->query("SELECT install_type, update_to, release_key_fp FROM agents WHERE id = {$agentId}")->fetch();
        Assert::same(['docker', ''], [$row['install_type'], $row['update_to']], 'reported as Docker; the update request ended');
        Assert::same('', (string) $row['release_key_fp'], 'no update helper, so no release key is offered or pinned');
        // "Update all" skips it and says why; the per-agent update is refused.
        $n = App::agents()->requestUpdates($cid, '99.0.0', 1);
        Assert::same(1, $n['image'], 'counted as an image update');
        Assert::same('', (string) $ctx->db->query("SELECT update_to FROM agents WHERE id = {$agentId}")->fetchColumn(), 'never handed out');
        $page = $ctx->clientSection($admin, $cid, 'agents');
        Assert::contains('Docker', $page);
        Assert::notContains('/agents/' . $agentId . '/update"', $page, 'no Update button for a Docker agent');
        // Only known values are stored; a normal check-in clears it.
        $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $cfg], ['SENTINEL_AGENT_CONTAINER' => 'something-else']);
        Assert::same('', (string) $ctx->db->query("SELECT install_type FROM agents WHERE id = {$agentId}")->fetchColumn(), 'unknown value: a normal install');
        $ctx->db->exec("UPDATE agents SET status = 'revoked' WHERE id = {$agentId}");
    },
    'container agents: the image is unprivileged, read-only and host-networked, with no update helper inside' => function (TestContext $ctx): void {
        $df = (string) file_get_contents($ctx->root . '/docker/agent/Dockerfile');
        Assert::contains('USER sentinel-agent', $df);
        Assert::contains('ENV SENTINEL_AGENT_CONTAINER=docker', $df);
        Assert::notContains('agent-update-runner', $df, 'no root update helper in the image');
        Assert::notContains("\nADD ", $df, 'nothing fetched from a URL at build time');
        Assert::true(preg_match('/^FROM php:8\.\d+-cli-\w+$/m', $df) === 1, 'a pinned official PHP base image');
        $compose = (string) file_get_contents($ctx->root . '/docker/agent/docker-compose.yml');
        foreach (['network_mode: host', 'read_only: true', 'cap_drop: [ALL]', 'no-new-privileges:true', 'config:/etc/sentinel-agent:ro'] as $needle) {
            Assert::contains($needle, $compose);
        }
        Assert::notContains('privileged: true', $compose);
        $ignore = (string) file_get_contents($ctx->root . '/.dockerignore');
        foreach (['config', 'storage', 'tests', '.git'] as $p) {
            Assert::true(preg_match('/^' . preg_quote($p, '/') . '$/m', $ignore) === 1, 'not in the image: ' . $p);
        }
    },
    'container agents: the real Docker image enrols and checks in (when SENTINEL_TEST_DOCKER_IMAGE is set)' => function (TestContext $ctx) use ($ctDir, $ctSetup, $enrolCode): void {
        $image = (string) getenv('SENTINEL_TEST_DOCKER_IMAGE');
        if ($image === '' || preg_match('/^[a-z0-9._\/:-]{1,200}$/', $image) !== 1) {
            return; // optional: needs a built image and a Docker daemon
        }
        [$cid, $site, $admin] = $ctSetup($ctx);
        $vol = $ctDir($ctx) . '-docker';
        exec('rm -rf ' . escapeshellarg($vol));
        mkdir($vol . '/config', 0700, true);
        mkdir($vol . '/state', 0700, true);
        chown($vol . '/config', 10001);
        chown($vol . '/state', 10001);
        $docker = static function (array $args, string $configMode = 'ro', string $stdin = '') use ($vol, $image): array {
            $cmd = array_merge(['docker', 'run', '--rm', '-i', '--network', 'host', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--tmpfs', '/tmp', '-e', 'SENTINEL_TEST_MODE=1', '-v', $vol . '/config:/etc/sentinel-agent:' . $configMode, '-v', $vol . '/state:/var/lib/sentinel-agent', $image], $args);
            $p = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            fwrite($pipes[0], $stdin);
            fclose($pipes[0]);
            $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            return [proc_close($p), $out];
        };
        [$code, $out] = $docker(['selfcheck']);
        Assert::contains('selfcheck ok', $out, 'the image can run the agent: ' . $out);
        [$code, $out] = $docker(['enrol', '--server', $ctx->baseUrl, '--code-stdin', '--config', '/etc/sentinel-agent/agent.json', '--state-dir', '/var/lib/sentinel-agent'], 'rw', $enrolCode($admin, $cid, $site) . "\n");
        Assert::same(0, $code, 'enrolled in the container: ' . $out);
        [$code, $out] = $docker(['run', '--once', '--config', '/etc/sentinel-agent/agent.json']);
        Assert::same(0, $code, 'checked in from the container: ' . $out);
        $agentId = (int) json_decode((string) file_get_contents($vol . '/config/agent.json'), true)['agent_id'];
        Assert::same('docker', (string) $ctx->db->query("SELECT install_type FROM agents WHERE id = {$agentId}")->fetchColumn());
        $ctx->db->exec("UPDATE agents SET status = 'revoked' WHERE id = {$agentId}");
    },
];
