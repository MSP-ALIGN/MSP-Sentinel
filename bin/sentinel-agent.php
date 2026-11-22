<?php

declare(strict_types=1);

/**
 * MSP Sentinel on-premises agent (runs on a small Linux appliance at the client's site).
 *
 *   sentinel-agent.php enrol --server https://sentinel.example --code SNE-XXXXX-... [--config FILE] [--ca FILE]
 *   sentinel-agent.php run [--config FILE] [--once]
 *   sentinel-agent.php status [--config FILE]
 *
 * The agent only connects out to Sentinel (HTTPS). It runs jobs only when
 * they are signed by the server key it pinned at enrolment and every target
 * is inside a signed internal authorisation (JobVerifier). Scans are gentle
 * and unprivileged (TCP connect, no raw packets), so it runs as its own
 * unprivileged user, never as root.
 *
 * Security assumptions: the config file holds the agent token and is
 * readable only by the agent's user (0600); the token is never printed.
 * Test settings in the config are honoured only with SENTINEL_TEST_MODE=1.
 */

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\AgentClient\Http;
use Sentinel\AgentClient\JobVerifier;
use Sentinel\AgentClient\Runner;
use Sentinel\AgentClient\State;
use Sentinel\Scanning\Connector;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Scanning\NmapRunner;
use Sentinel\Scanning\TlsChecker;

$argv = $_SERVER['argv'] ?? [];
$command = $argv[1] ?? 'help';
$opts = [];
for ($i = 2; $i < count($argv); $i++) {
    if (str_starts_with($argv[$i], '--')) {
        $name = substr($argv[$i], 2);
        $opts[$name] = isset($argv[$i + 1]) && !str_starts_with($argv[$i + 1], '--') ? $argv[++$i] : true;
    }
}
$configFile = is_string($opts['config'] ?? null) ? $opts['config'] : '/etc/sentinel-agent/agent.json';
$testMode = getenv('SENTINEL_TEST_MODE') === '1';
$say = static function (string $line): void {
    fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . '] ' . $line . "\n");
};

if (function_exists('posix_geteuid') && posix_geteuid() === 0 && getenv('SENTINEL_ALLOW_ROOT') !== '1') {
    fwrite(STDERR, "The agent must not run as root. Run it as its own user (the installer creates 'sentinel-agent').\n");
    exit(1);
}

/** Load the agent config (or exit). */
$load = static function () use ($configFile): array {
    $data = is_readable($configFile) ? json_decode((string) file_get_contents($configFile), true) : null;
    if (!is_array($data) || !is_string($data['server'] ?? null) || !is_string($data['token'] ?? null) || !is_int($data['agent_id'] ?? null) || !is_string($data['server_public_key'] ?? null)) {
        fwrite(STDERR, "No valid agent config at {$configFile}. Enrol first: sentinel-agent.php enrol --server URL --code CODE\n");
        exit(1);
    }
    return $data;
};

switch ($command) {
    case 'enrol':
        $server = is_string($opts['server'] ?? null) ? rtrim($opts['server'], '/') : '';
        $code = is_string($opts['code'] ?? null) ? $opts['code'] : '';
        if ($server === '' || $code === '') {
            fwrite(STDERR, "Usage: sentinel-agent.php enrol --server https://sentinel.example --code SNE-XXXXX-XXXXX-XXXXX-XXXXX\n");
            exit(2);
        }
        if (is_file($configFile)) {
            fwrite(STDERR, "{$configFile} already exists: this agent is enrolled. Remove the file first to enrol again.\n");
            exit(1);
        }
        $ca = is_string($opts['ca'] ?? null) ? $opts['ca'] : null;
        try {
            $res = (new Http($server, null, $ca, $testMode))->post('/agent/v1/enrol', ['code' => $code, 'hostname' => (string) gethostname(), 'version' => Runner::VERSION]);
        } catch (\Throwable $ex) {
            fwrite(STDERR, $ex->getMessage() . "\n");
            exit(1);
        }
        if ($res['status'] !== 201 || !is_string($res['data']['token'] ?? null)) {
            fwrite(STDERR, 'Enrolment refused: ' . (string) ($res['data']['error']['message'] ?? 'HTTP ' . $res['status']) . "\n");
            exit(1);
        }
        $config = ['server' => $server, 'agent_id' => (int) $res['data']['agent_id'], 'token' => (string) $res['data']['token'],
                   'server_public_key' => (string) $res['data']['server_public_key'], 'ca_file' => $ca, 'nmap_path' => '/usr/bin/nmap',
                   'state_file' => dirname($configFile) . '/state.json'];
        if (!is_dir(dirname($configFile))) {
            mkdir(dirname($configFile), 0700, true);
        }
        $old = umask(0077);
        file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        umask($old);
        chmod($configFile, 0600);
        $say('Enrolled as agent #' . $config['agent_id'] . '. Server key pinned. Config written to ' . $configFile . '.');
        exit(0);

    case 'run':
    case 'status':
        $c = $load();
        // Test settings (fake nmap, mock services) only with SENTINEL_TEST_MODE=1; otherwise a direct connector.
        $connector = $testMode && is_array($c['testing'] ?? null) ? Connector::fromTesting($c['testing']) : Connector::direct();
        $http = new Http((string) $c['server'], (string) $c['token'], is_string($c['ca_file'] ?? null) ? $c['ca_file'] : null, $testMode);
        if ($command === 'status') {
            $res = $http->post('/agent/v1/poll', ['hostname' => (string) gethostname(), 'version' => Runner::VERSION, 'running' => []]);
            $say('Agent #' . $c['agent_id'] . ' → ' . $c['server'] . ': ' . ($res['status'] === 200 ? 'connected' . (($res['data']['paused'] ?? false) ? ' (scanning paused)' : '') : 'HTTP ' . $res['status']));
            exit($res['status'] === 200 ? 0 : 1);
        }
        $runner = new Runner($http, new JobVerifier((string) $c['server_public_key'], (int) $c['agent_id']), new State((string) ($c['state_file'] ?? dirname($configFile) . '/state.json')),
            new NmapRunner((string) ($c['nmap_path'] ?? '/usr/bin/nmap')), new TlsChecker($connector), new HttpProbe($connector), $say,
            $testMode && is_string($c['testing']['arp_file'] ?? null) ? $c['testing']['arp_file'] : '/proc/net/arp');
        $say('Agent #' . $c['agent_id'] . ' started (version ' . Runner::VERSION . ').');
        do {
            try {
                $wait = $runner->pollOnce();
            } catch (\Throwable $ex) {
                $say('Error: ' . mb_substr($ex->getMessage(), 0, 300));
                $wait = 60;
            }
            if ($wait < 0) {
                exit(3);
            }
            if (isset($opts['once'])) {
                break;
            }
            sleep($wait);
        } while (true);
        exit(0);

    default:
        fwrite(STDOUT, "MSP Sentinel agent\n  enrol --server URL --code CODE [--config FILE] [--ca FILE]\n  run [--config FILE] [--once]\n  status [--config FILE]\n");
        exit($command === 'help' ? 0 : 2);
}
