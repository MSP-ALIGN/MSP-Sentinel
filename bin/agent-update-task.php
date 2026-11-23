<?php

declare(strict_types=1);

/**
 * MSP Sentinel agent: the Windows update task (the twin of bin/agent-update-runner.php, the Linux root helper). Task
 * Scheduler runs it as SYSTEM every 5 minutes (install-agent.ps1 registers it). It installs a new agent release, or
 * pins a release key, when the agent asked for it, and only what is signed with the pinned release key.
 *
 * Rule: SYSTEM NEVER WRITES, DELETES OR READS STAGED FILES IN THE AGENT'S FOLDER. The agent's service account could
 * create junctions or hard links there to redirect SYSTEM. So the agent writes only a small request (update-request:
 * version and request id; for a key, release-key-offer.json: the offer Sentinel signed). This task:
 * 1. reads the request (plain files only, size-capped, strictly parsed; never echoed back);
 * 2. release key offer: checked like on Linux (ReleaseKeyOffer: Sentinel's signature with the server key from the
 *    protected config, pinned only when nothing is pinned or with a rotation chain the pinned key signed);
 * 3. update: downloads the manifest and every file from Sentinel ITSELF (the address and token from the protected
 *    config, not from the agent's folder), checks the signature with the pinned release key, the version (newer than
 *    the installed one) and every SHA-256, writes them into a new folder next to the installed code, runs the new
 *    release's self-check, stops the service, swaps the folders, starts it, and puts the old folder back if the service
 *    does not stay running (20 and 50 seconds, same process);
 * 4. writes its result into its own folder (SYSTEM writes, the agent reads), naming the request, so the same request is
 *    never handled twice; the agent removes its own request when it sees the result.
 *
 * The service definition (WinSW) and the task itself are not changed by an update: install-agent.ps1 -Upgrade does that.
 *
 * Protected (by install-agent.ps1's permissions): C:\Program Files\MSP Sentinel Agent (code, PHP, WinSW: Administrators
 * and SYSTEM write) and C:\ProgramData\MSP Sentinel Agent\config and \update (Administrators and SYSTEM write; the
 * agent reads). The agent writes only \state and \logs.
 *
 * TEST SUITE ONLY (SENTINEL_TEST_MODE=1): --config, --state, --app, --result, --key, --php and --no-service point it at
 * test folders and skip the service; refused otherwise.
 */

const REQUEST_BYTES = 4096;
const OFFER_BYTES = 16384;
const SERVICE = 'SentinelAgent';

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\AgentClient\Http;
use Sentinel\AgentClient\Platform;
use Sentinel\System\ReleaseKeyOffer;
use Sentinel\System\ReleaseManifest;

$argv = $_SERVER['argv'] ?? [];
$test = getenv('SENTINEL_TEST_MODE') === '1';
$opt = static function (string $name) use ($argv): ?string {
    $i = array_search('--' . $name, $argv, true);
    return $i !== false && isset($argv[$i + 1]) ? (string) $argv[$i + 1] : null;
};
foreach (['config', 'state', 'app', 'result', 'key', 'php'] as $o) {
    if (!$test && $opt($o) !== null) {
        fwrite(STDERR, "--{$o} is for the test suite only.\n");
        exit(2);
    }
}
if (!$test && in_array('--no-service', $argv, true)) {
    fwrite(STDERR, "--no-service is for the test suite only.\n");
    exit(2);
}
$win = Platform::detect(Platform::WINDOWS);
$data = dirname(dirname($win->configFile())); // C:\ProgramData\MSP Sentinel Agent
$configFile = $opt('config') ?? $win->configFile();
$state = rtrim($opt('state') ?? $data . '\\state', '\\/');
$resultDir = rtrim($opt('result') ?? $win->updateResultDir(), '\\/');
$keyFile = $opt('key') ?? $win->releaseKeyFile();
// C:\Program Files\MSP Sentinel Agent\app: named by the launcher (agent-update-launcher.php, outside app\, so app\ can be
// swapped while this runs).
$app = rtrim($opt('app') ?? (defined('SENTINEL_UPDATE_APP') ? (string) SENTINEL_UPDATE_APP : dirname(__DIR__)), '\\/');
$php = $opt('php') ?? PHP_BINARY;
$phpIni = dirname($php) . DIRECTORY_SEPARATOR . 'php.ini';
$service = !($test && in_array('--no-service', $argv, true));
$system32 = (getenv('SystemRoot') ?: 'C:\\Windows') . '\\System32';

/** Progress: to stdout and to update\task.log (Task Scheduler keeps no output), the log capped at 1 MB. */
$say = static function (string $line) use ($resultDir): void {
    $line = '[' . gmdate('Y-m-d H:i:s') . '] ' . $line . "\n";
    fwrite(STDOUT, $line);
    $log = $resultDir . '/task.log';
    if ((int) @filesize($log) > 1048576) {
        @rename($log, $log . '.1');
    }
    @file_put_contents($log, $line, FILE_APPEND);
};
$requestId = '';
/** Write the result (own folder, atomically) and stop. */
$result = static function (string $version, bool $ok, string $message) use ($resultDir, $say, &$requestId): never {
    if (!is_dir($resultDir)) {
        mkdir($resultDir, 0755, true);
    }
    $written = file_put_contents($resultDir . '/result.json.tmp', json_encode(['version' => mb_substr($version, 0, 20), 'ok' => $ok, 'message' => mb_substr($message, 0, 500),
        'request' => $requestId, 'at' => gmdate('Y-m-d\TH:i:s\Z')], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
    // The agent may have result.json open for a moment (Windows then refuses the rename): try for up to 10 seconds.
    $moved = false;
    for ($i = 0; $i < 20 && $written !== false && !($moved = @rename($resultDir . '/result.json.tmp', $resultDir . '/result.json')); $i++) {
        usleep(500000);
    }
    if (!$moved) {
        $say('The result could not be written to ' . $resultDir . '\\result.json.');
    }
    $say(($ok ? 'OK: ' : 'Refused: ') . $message);
    exit($ok ? 0 : 1);
};
/**
 * A small plain file in the agent's state folder (no link, no folder, no redirection), at most $max bytes, or ''.
 * The state folder itself must resolve to itself: the agent's account could replace it with a junction (to a named
 * pipe, say, to catch SYSTEM connecting): then nothing is read.
 */
$norm = static fn (string $p): string => strtolower(rtrim(str_replace('\\', '/', $p), '/'));
$readPlain = static function (string $file, int $max) use ($state, $norm, $say): string {
    clearstatcache(true); // no cached answer from an earlier check (the agent could change things in between)
    $parent = realpath(dirname($state));
    $real = realpath($state);
    $realFile = realpath($file);
    // The state folder must resolve to where it sits (compared after resolving its parent, so a legitimate path
    // spelled differently isn't refused), not be a link or junction, and hold the file directly.
    $expected = $parent === false ? '' : $norm($parent . '/' . basename($state));
    if ($real === false || $norm($real) !== $expected || is_link($state) || ($realFile !== false && $norm(dirname($realFile)) !== $expected)) {
        $say('The agent\'s state folder is redirected (a link or junction): nothing read from it. Inspect this machine.');
        return '';
    }
    if ($realFile === false || is_link($file) || !is_file($file) || (int) @filesize($file) > $max) {
        return '';
    }
    return (string) @file_get_contents($file, false, null, 0, $max);
};
/** Run a program (array form, no shell); returns [exit code, output]. */
$run = static function (array $cmd, int $seconds = 120): array {
    $p = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, null, ['bypass_shell' => true]);
    if (!is_resource($p)) {
        return [127, ''];
    }
    stream_set_blocking($pipes[1], false);
    $out = '';
    $end = microtime(true) + $seconds;
    while (true) {
        $out .= (string) fread($pipes[1], 65536);
        $st = proc_get_status($p);
        if (!$st['running']) {
            $out .= (string) stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($p);
            return [$st['exitcode'], $out];
        }
        if (microtime(true) > $end) {
            proc_terminate($p);
            proc_close($p);
            return [124, $out];
        }
        usleep(50000);
    }
};
/** Remove a folder this task made (no links followed: a junction is removed, never entered). */
$rm = static function (string $dir): void {
    if (!is_dir($dir) || is_link($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) {
        $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($dir);
};
/** The service's process id (0 when not running), from sc.exe queryex. */
$servicePid = static function () use ($run, $system32): int {
    [, $out] = $run([$system32 . '\\sc.exe', 'queryex', SERVICE], 30);
    return preg_match('/STATE\s+:\s+4\s+RUNNING/', $out) === 1 && preg_match('/PID\s+:\s+(\d+)/', $out, $m) === 1 ? (int) $m[1] : 0;
};
$serviceCtl = static function (string $verb) use ($run, $system32, $servicePid): bool {
    $run([$system32 . '\\sc.exe', $verb, SERVICE], 30);
    for ($i = 0; $i < 60; $i++) { // up to 60 seconds for the service to reach the state
        $pid = $servicePid();
        if (($verb === 'stop' && $pid === 0) || ($verb === 'start' && $pid > 0)) {
            return true;
        }
        sleep(1);
    }
    return false;
};

// One run at a time.
if (!is_dir($resultDir)) {
    mkdir($resultDir, 0755, true);
}
$lock = fopen($resultDir . '/task.lock', 'c');
if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0);
}

$startMode = static function (string $mode) use ($run, $system32, $service, $say): bool {
    if (!$service) {
        return true;
    }
    [$code] = $run([$system32 . '\\sc.exe', 'config', SERVICE, 'start=', $mode], 30);
    if ($code !== 0) {
        $say('Could not set the agent service to start ' . $mode . ' (sc.exe exit ' . $code . ').');
    }
    return $code === 0;
};
/** Rename with a few retries (antivirus or the search indexer may hold a file for a moment). */
$renameRetry = static function (string $from, string $to): bool {
    for ($i = 0; $i < 10; $i++) {
        if (@rename($from, $to)) {
            return true;
        }
        sleep(1);
    }
    return false;
};
// While folders are swapped the service is disabled; this marker (in this task's own folder) says so, so that a run
// after a crash or reboot in the middle sets it back to start and starts it.
$swapMarker = $resultDir . '/swap-in-progress';

// 0. An update stopped half-way (power cut): never leave the appliance without its agent. The launcher may already
// have put app.old back (SENTINEL_UPDATE_REPAIRED); the service is started here, under the lock.
$repaired = defined('SENTINEL_UPDATE_REPAIRED');
if (!is_dir($app) && is_dir($app . '.old')) {
    $repaired = $renameRetry($app . '.old', $app);
}
if ($repaired || is_file($swapMarker)) {
    $say('An earlier update stopped half-way: ' . $app . ' restored, the service set to start again.');
    $startMode('delayed-auto');
    if ($service) {
        $serviceCtl('start');
    }
    @unlink($swapMarker);
}

// 1. The request (nothing asked: nothing to do; this runs every 5 minutes).
$req = json_decode($readPlain($state . '/update-request', REQUEST_BYTES), true);
if (!is_array($req)) {
    exit(0);
}
$requestId = is_string($req['request'] ?? null) && preg_match('/^[0-9TZ:. -]{1,30}$/', $req['request']) === 1 ? $req['request'] : '';
$last = json_decode((string) @file_get_contents($resultDir . '/result.json', false, null, 0, 8192), true);
$asked = ($req['kind'] ?? '') === 'pin' ? 'release-key' : (is_string($req['version'] ?? null) ? $req['version'] : '');
if (is_array($last) && ($last['request'] ?? null) === $requestId && ($last['version'] ?? null) === $asked) {
    exit(0); // answered already; the agent removes its request when it sees the result
}
$cfg = json_decode((string) @file_get_contents($configFile), true);
if (!is_array($cfg) || !is_string($cfg['server'] ?? null) || !is_string($cfg['token'] ?? null)) {
    $result($asked, false, 'The agent config can\'t be read: ' . $configFile);
}

/** The pinned release key as [state, key]: the key file, else (none, or empty) the key pinned at enrolment. */
$pinnedKey = static function () use ($keyFile, $cfg): array {
    if (is_link($keyFile)) {
        return ['bad', ''];
    }
    $k = is_file($keyFile) ? trim((string) @file_get_contents($keyFile, false, null, 0, 1024)) : '';
    if ($k !== '') {
        return ReleaseManifest::validPublicKey($k) ? ['ok', $k] : ['bad', ''];
    }
    $k = is_string($cfg['release_public_key'] ?? null) ? trim($cfg['release_public_key']) : '';
    return $k === '' ? ['absent', ''] : (ReleaseManifest::validPublicKey($k) ? ['ok', $k] : ['bad', '']);
};

// 2. A release key offered by Sentinel.
if (($req['kind'] ?? null) === 'pin') {
    [$pinState, $pinned] = $pinnedKey();
    $d = ReleaseKeyOffer::decide($readPlain($state . '/release-key-offer.json', OFFER_BYTES), $cfg, $pinState, $pinned, 'install-agent.ps1 -Upgrade -ReleaseKey');
    if (!$d['ok'] || $d['pin'] === null) {
        $result('release-key', $d['ok'], $d['message']);
    }
    if (file_put_contents($keyFile . '.tmp', $d['pin'] . "\n") === false || !rename($keyFile . '.tmp', $keyFile)) {
        $result('release-key', false, 'Could not write ' . $keyFile . '.');
    }
    $result('release-key', true, $d['message']);
}

// 3. An update: download it ourselves and check everything.
$wanted = is_string($req['version'] ?? null) && preg_match('/^\d{1,4}\.\d{1,4}\.\d{1,4}$/', $req['version']) === 1 ? $req['version'] : '';
if ($wanted === '') {
    $result('', false, 'No valid update request.');
}
[$pinState, $pinned] = $pinnedKey();
if ($pinState !== 'ok') {
    $result($wanted, false, $pinState === 'absent' ? 'No release key is pinned on this machine yet.' : 'The pinned release key is damaged; fix it by hand (install-agent.ps1 -Upgrade -ReleaseKey).');
}
$installed = trim((string) @file_get_contents($app . '/VERSION'));
if (preg_match('/^\d+\.\d+\.\d+$/', $installed) !== 1) {
    $result($wanted, false, 'The installed version can\'t be read; upgrade by hand (install-agent.ps1 -Upgrade).');
}
// Sentinel's address from the protected config (a move the agent recorded in its own folder is not followed here:
// keep the old address working until agents are reinstalled or upgraded by hand).
$http = new Http((string) $cfg['server'], (string) $cfg['token'], is_string($cfg['ca_file'] ?? null) ? $cfg['ca_file'] : null, $test);
try {
    $res = $http->post('/agent/v1/update/manifest', ['version' => $wanted], 60);
} catch (\Throwable $ex) {
    $result($wanted, false, 'Sentinel could not be reached: ' . mb_substr($ex->getMessage(), 0, 200));
}
$m = ReleaseManifest::verify(is_string($res['data']['manifest'] ?? null) ? $res['data']['manifest'] : '', is_string($res['data']['signature'] ?? null) ? $res['data']['signature'] : '', $pinned);
if (is_string($m)) {
    $result($wanted, false, 'Release refused: ' . $m . '.');
}
if ($m['version'] !== $wanted || !ReleaseManifest::newer($m['version'], $installed)) {
    $result($wanted, false, 'Release ' . $m['version'] . ' is not the one requested or not newer than ' . $installed . '.');
}
$new = $app . '.new';
$rm($new);
mkdir($new, 0755, true);
foreach ($m['files'] as $path => $hash) {
    try {
        $r = $http->post('/agent/v1/update/file', ['version' => $wanted, 'path' => $path], 120);
    } catch (\Throwable) {
        $r = ['status' => 0, 'data' => []];
    }
    $content = is_string($r['data']['content'] ?? null) ? base64_decode($r['data']['content'], true) : false;
    if ($r['status'] !== 200 || $content === false || strlen($content) > ReleaseManifest::MAX_FILE_BYTES || !hash_equals($hash, hash('sha256', $content))) {
        $rm($new);
        $result($wanted, false, 'Release refused: ' . $path . ' does not match the signed release.');
    }
    $dest = $new . '/' . $path;
    if (!is_dir(dirname($dest))) {
        mkdir(dirname($dest), 0755, true);
    }
    file_put_contents($dest, $content);
}

// Pre-flight: the new release checks itself (PHP version and extensions) with this machine's PHP.
[$code, $check] = $run(array_merge([$php], is_file($phpIni) ? ['-c', $phpIni] : [], [$new . '/bin/sentinel-agent.php', 'selfcheck']), 60);
if ($code !== 0 || trim($check) !== 'selfcheck ok ' . $m['version']) {
    $rm($new);
    $result($wanted, false, 'The new release did not pass its self-check on this machine (' . mb_substr(trim($check), 0, 150) . '); upgrade by hand if it needs a newer PHP.');
}

// 4. Swap with the service stopped and disabled (so the service manager's restart-on-failure can't start it while the
// folders move); roll back if it doesn't stay running. Every step is checked.
$restore = static function (string $why) use ($app, $new, $rm, $result, $wanted, $installed, $startMode, $serviceCtl, $service, $renameRetry, $swapMarker): never {
    // Put the previous version back: the new folder aside first, then the old one in place.
    $ok = true;
    if (is_dir($app)) {
        $rm($app . '.failed');
        $ok = $renameRetry($app, $app . '.failed');
    }
    $ok = $ok && $renameRetry($app . '.old', $app);
    $startMode('delayed-auto');
    if ($service) {
        $serviceCtl('start');
    }
    @unlink($swapMarker);
    $rm($new);
    if ($ok) {
        $rm($app . '.failed'); // kept when the rollback failed: it may be the only copy left
    }
    $result($wanted, false, $ok ? $why . ' The previous version ' . $installed . ' was put back.'
        : $why . ' Putting the previous version back FAILED: reinstall with install-agent.ps1 -Upgrade.');
};
if ($service) {
    file_put_contents($swapMarker, gmdate('c'));
    $startMode('disabled');
    if (!$serviceCtl('stop')) {
        $startMode('delayed-auto');
        $serviceCtl('start');
        @unlink($swapMarker);
        $rm($new);
        $result($wanted, false, 'The agent service did not stop; nothing was changed.');
    }
}
$rm($app . '.old');
if (!$renameRetry($app, $app . '.old')) {
    $rm($new);
    $startMode('delayed-auto');
    if ($service) {
        $serviceCtl('start');
    }
    @unlink($swapMarker);
    $result($wanted, false, 'Could not move the current version aside (a file in use?); the previous one was kept.');
}
if (!$renameRetry($new, $app)) {
    $restore('Could not put the new version in place.');
}
$startMode('delayed-auto');
if ($service) {
    $serviceCtl('start');
    sleep(20);
    $pid = $servicePid();
    sleep(30);
    if ($pid === 0 || $servicePid() !== $pid) {
        // It stopped or was restarted (failure actions): put the previous version back.
        $startMode('disabled');
        $serviceCtl('stop');
        $restore('Version ' . $wanted . ' did not keep running.');
    }
}
@unlink($swapMarker);
$result($wanted, true, 'Updated from ' . $installed . ' to ' . $wanted . '.');
