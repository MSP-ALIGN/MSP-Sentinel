<?php

declare(strict_types=1);

/**
 * MSP Sentinel on-premises agent (runs on a small Linux appliance at the client's site).
 *
 *   sentinel-agent.php enrol --server https://sentinel.example --code SNE-XXXXX-... [--config FILE] [--ca FILE]
 *   sentinel-agent.php enrol --server https://sentinel.example --code-stdin ...   (the code is read from stdin, so it
 *       never appears in the process list)
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

use Sentinel\AgentClient\AgentKey;
use Sentinel\AgentClient\Credentials;
use Sentinel\AgentClient\Http;
use Sentinel\AgentClient\JobVerifier;
use Sentinel\AgentClient\Mover;
use Sentinel\AgentClient\Runner;
use Sentinel\AgentClient\State;
use Sentinel\AgentClient\Updater;
use Sentinel\Directory\DirectoryChecks;
use Sentinel\Directory\NameListener;
use Sentinel\Scanning\Connector;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Scanning\NmapRunner;
use Sentinel\AgentClient\Platform;
use Sentinel\Scanning\ProtocolProbes;
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
$testMode = getenv('SENTINEL_TEST_MODE') === '1';
// Linux or Windows: default paths, nmap, the ARP table (test mode may force Windows: SENTINEL_TEST_PLATFORM, or the
// config's testing.platform below).
$platform = Platform::detect($testMode && getenv('SENTINEL_TEST_PLATFORM') !== false ? (string) getenv('SENTINEL_TEST_PLATFORM') : null);
$configFile = is_string($opts['config'] ?? null) ? $opts['config'] : $platform->configFile();
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
    if (!is_array($data) || !is_string($data['server'] ?? null) || !is_string($data['token'] ?? null) || !is_int($data['agent_id'] ?? null) || !is_string($data['server_public_key'] ?? null)
        || !is_int($data['site_id'] ?? null) || !is_int($data['client_id'] ?? null)) {
        fwrite(STDERR, "No valid agent config at {$configFile}. Enrol first: sentinel-agent.php enrol --server URL --code CODE\n");
        exit(1);
    }
    return $data;
};

switch ($command) {
    case 'selfcheck':
        // Used by the update helper before switching to a new release (run as the agent's user): can this release run
        // on this appliance? Prints "selfcheck ok <version>" and exits 0, or says what is missing.
        $missing = array_values(array_filter(['curl', 'json', 'openssl', 'sodium', 'mbstring'], static fn (string $e): bool => !extension_loaded($e)));
        if (PHP_VERSION_ID < 80300 || $missing !== []) {
            fwrite(STDOUT, 'selfcheck failed: ' . (PHP_VERSION_ID < 80300 ? 'PHP 8.3 or later needed. ' : '') . ($missing !== [] ? 'Missing PHP extensions: ' . implode(', ', $missing) . '.' : '') . "\n");
            exit(1);
        }
        foreach ([Runner::class, JobVerifier::class, Updater::class, State::class] as $class) {
            if (!class_exists($class)) {
                fwrite(STDOUT, "selfcheck failed: {$class} is missing.\n");
                exit(1);
            }
        }
        fwrite(STDOUT, 'selfcheck ok ' . Runner::version() . "\n");
        exit(0);
    case 'enrol':
        $server = is_string($opts['server'] ?? null) ? rtrim($opts['server'], '/') : '';
        $code = is_string($opts['code'] ?? null) ? $opts['code'] : (isset($opts['code-stdin']) ? trim((string) fgets(STDIN, 200)) : '');
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
            $res = (new Http($server, null, $ca, $testMode))->post('/agent/v1/enrol', ['code' => $code, 'hostname' => (string) gethostname(), 'version' => Runner::version()]);
        } catch (\Throwable $ex) {
            fwrite(STDERR, $ex->getMessage() . "\n");
            exit(1);
        }
        if ($res['status'] !== 201 || !is_string($res['data']['token'] ?? null) || !is_int($res['data']['site_id'] ?? null) || !is_int($res['data']['client_id'] ?? null)) {
            fwrite(STDERR, 'Enrolment refused: ' . (string) ($res['data']['error']['message'] ?? 'HTTP ' . $res['status']) . "\n");
            exit(1);
        }
        $config = ['server' => $server, 'agent_id' => (int) $res['data']['agent_id'], 'site_id' => $res['data']['site_id'], 'client_id' => $res['data']['client_id'],
                   'token' => (string) $res['data']['token'],
                   'server_public_key' => (string) $res['data']['server_public_key'], 'ca_file' => $ca,
                   // --nmap: where the installer put nmap (Windows); else the platform's default.
                   'nmap_path' => is_string($opts['nmap'] ?? null) && $opts['nmap'] !== '' ? $opts['nmap'] : $platform->nmapPath(),
                   // The agent release key (public), pinned at enrolment: updates need no site visit.
                   'release_public_key' => is_string($res['data']['release_public_key'] ?? null) && \Sentinel\System\ReleaseManifest::validPublicKey($res['data']['release_public_key']) ? $res['data']['release_public_key'] : '',
                   // Linux enrols into the state folder (the installer then moves the config); Windows names it (--state-dir).
                   'state_file' => (is_string($opts['state-dir'] ?? null) ? rtrim($opts['state-dir'], '\\/') : dirname($configFile)) . '/state.json'];
        if (!is_dir(dirname($configFile))) {
            mkdir(dirname($configFile), 0700, true);
        }
        $old = umask(0077);
        file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        umask($old);
        chmod($configFile, 0600);
        $say('Enrolled as agent #' . $config['agent_id'] . ' (site #' . $config['site_id'] . '). Server key, site and client pinned. Config written to ' . $configFile . '.');
        // Compare with the fingerprint on Sentinel's System page: this key decides which code the appliance installs.
        $say($config['release_public_key'] !== '' ? 'Release key pinned from Sentinel: ' . \Sentinel\System\ReleaseManifest::keyFingerprint($config['release_public_key']) . ' (compare it with Administration, System).'
            : 'No release key yet: Sentinel offers it once one is created on Administration, System.');
        exit(0);

    case 'run':
    case 'status':
        $c = $load();
        // Test settings (fake nmap, mock services) only with SENTINEL_TEST_MODE=1; otherwise a direct connector.
        $connector = $testMode && is_array($c['testing'] ?? null) ? Connector::fromTesting($c['testing']) : Connector::direct();
        $stateDir = dirname((string) ($c['state_file'] ?? dirname($configFile) . '/state.json'));
        // Moved to a new Sentinel address (Administration, System)? It is kept in the state folder; the config is read-only.
        $mover = new Mover($stateDir, (string) $c['server_public_key'], (int) $c['agent_id'], (int) $c['site_id'], (int) $c['client_id'], (string) $c['token'], $testMode, $say,
            (string) $c['server'], is_string($c['ca_file'] ?? null) ? $c['ca_file'] : null);
        $moved = $mover->override();
        $http = new Http($moved['server'] ?? (string) $c['server'], (string) $c['token'], $moved !== null ? $moved['ca_file'] : (is_string($c['ca_file'] ?? null) ? $c['ca_file'] : null), $testMode);
        // The agent's own key pair (sealed passwords) and the directory password it holds, in the state folder (the only
        // writable one: /var/lib/sentinel-agent; the config folder is read-only for the service). A key that can't be
        // read or created only turns those off: scans go on.
        $key = null;
        $credentials = null;
        try {
            $key = new AgentKey($stateDir . '/agent-key.pem');
            $credentials = new Credentials($stateDir . '/directory-credential.json', $key, (string) $c['server_public_key'], (int) $c['agent_id'], (int) $c['site_id'], (int) $c['client_id']);
        } catch (\Throwable $ex) {
            $say('The agent key is unusable (' . mb_substr($ex->getMessage(), 0, 200) . '): Active Directory checks are off until it is fixed (delete the file to create a new one, then set the password again).');
        }
        if ($command === 'status') {
            // Not idle: a status check must never take jobs or requests meant for the running agent.
            $res = $http->post('/agent/v1/poll', ['hostname' => (string) gethostname(), 'version' => Runner::version(), 'running' => [], 'idle' => false]);
            $say('Agent #' . $c['agent_id'] . ' → ' . $http->server() . ($moved !== null ? ' (moved from ' . $c['server'] . ')' : '') . ': ' . ($res['status'] === 200 ? 'connected' . (($res['data']['paused'] ?? false) ? ' (scanning paused)' : '') : 'HTTP ' . $res['status']));
            // Compare with the fingerprint on the client's Agents page before typing a directory password.
            $say('Agent key fingerprint: ' . ($key !== null ? AgentKey::fingerprint($key->publicKey()) : 'none (key unusable)'));
            exit($res['status'] === 200 ? 0 : 1);
        }
        if ($testMode && is_array($c['testing'] ?? null)) {
            $platform = Platform::detect(is_string($c['testing']['platform'] ?? null) ? $c['testing']['platform'] : $platform->os,
                is_string($c['testing']['arp_file'] ?? null) ? $c['testing']['arp_file'] : null);
        }
        $runner = new Runner($http, new JobVerifier((string) $c['server_public_key'], (int) $c['agent_id'], (int) $c['site_id'], (int) $c['client_id']), new State((string) ($c['state_file'] ?? dirname($configFile) . '/state.json')),
            new NmapRunner((string) ($c['nmap_path'] ?? $platform->nmapPath())), new TlsChecker($connector), new HttpProbe($connector), $say,
            $platform, new ProtocolProbes($connector), $key, $credentials,
            new DirectoryChecks(static fn (string $ip, int $port): array => $connector->endpoint($ip, $port)),
            // Test mode: listen on 127.0.0.1 and high ports, without joining the multicast group (no ports given: don't listen).
            // Windows: no listener (the system owns UDP 137 and 5355).
            !$platform->namesListener() ? null : ($testMode ? (is_array($c['testing']['names'] ?? null)
                ? new NameListener('127.0.0.1', (int) $c['testing']['names']['llmnr_port'], (int) $c['testing']['names']['nbns_port'], false, (string) ($c['testing']['names']['loopback_as'] ?? '')) : null)
                : new NameListener()),
            // Updates: only code signed with the release key pinned at install (test suite: testing.release_key).
            new Updater($http, $testMode && is_string($c['testing']['release_key'] ?? null) ? $c['testing']['release_key'] : $platform->releaseKeyFile(),
                $stateDir, $say, (string) $c['server_public_key'], (int) $c['agent_id'], (int) $c['site_id'], (int) $c['client_id'],
                // The helper's results: a root-owned folder the agent can read but not change.
                $testMode && is_string($c['testing']['update_result_dir'] ?? null) ? $c['testing']['update_result_dir'] : $platform->updateResultDir(),
                is_string($c['release_public_key'] ?? null) ? $c['release_public_key'] : '', $platform->isWindows()),
            $mover,
            // Vendor default passwords (signed engagement test only): 5 seconds between attempts (test suite: shorter).
            new \Sentinel\Scanning\DefaultCredentials($connector, $testMode && ($c['testing']['allow_documentation_ranges'] ?? false) === true
                && is_numeric($c['testing']['creds_spacing'] ?? null) ? (float) $c['testing']['creds_spacing'] : 5.0));
        $say('Agent #' . $c['agent_id'] . ' started (version ' . Runner::version() . ').');
        do {
            try {
                $wait = $runner->pollOnce();
            } catch (\Throwable $ex) {
                $say('Error: ' . mb_substr($ex->getMessage(), 0, 300));
                $wait = 60;
            }
            if ($wait === -2) {
                exit(75); // a restart Sentinel asked for: systemd (Restart=on-failure) starts the agent again
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
