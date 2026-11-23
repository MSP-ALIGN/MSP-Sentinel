<?php

declare(strict_types=1);

/**
 * MSP Sentinel agent update helper. Started as ROOT by the systemd path unit sentinel-agent-update.path when the agent
 * writes /var/lib/sentinel-agent/update-request. The agent is unprivileged and can't change its code; it stages a
 * release in its own state folder (src/AgentClient/Updater.php).
 *
 * Rule: ROOT NEVER OPENS, WRITES OR DELETES ANYTHING IN THE AGENT'S FOLDER. That folder belongs to the agent's user,
 * who could plant symlinks, hard links, FIFOs or swap paths while root works there. So:
 * 1. Collect (as the agent's user, via runuser): this same script with --collect reads the request, the staged
 *    manifest, signature and files, removes the request, and writes them all to stdout as one JSON document (size
 *    capped). Whatever it reads, it could read anyway.
 * 2. Check (root, in memory only): the manifest is signed with the pinned release key (/etc/sentinel-agent/
 *    release-key.pub, else the key pinned at enrolment in agent.json; both root-owned; never changed by an update,
 *    only by a pin this helper checks: see $pinnedKey), is the version requested and newer
 *    than the installed one (an unreadable installed version is refused), and every file matches its SHA-256. Exactly
 *    the manifest's files are written into a new root-owned folder.
 * 3. Pre-flight (as the agent's user): the new release's own `sentinel-agent.php selfcheck` must pass (PHP version and
 *    extensions) before anything is swapped.
 * 4. Swap /opt/sentinel-agent for the new folder (the previous one is kept as /opt/sentinel-agent.old), write the
 *    systemd units from the new release, restart the agent, and check it stays running; if not, the previous version
 *    is put back and restarted (rollback).
 * The result goes to /var/lib/sentinel-agent-update/result.json: a root-owned folder the agent can read but not
 * change. Cleaning up the staged files is the agent's job.
 *
 * TEST SUITE ONLY: with SENTINEL_TEST_MODE=1, --app, --state, --key, --result and --no-systemd point it at test
 * folders, and the collector and pre-flight run as the current user (no runuser). Without it those options are
 * refused and it must run as root.
 */

require dirname(__DIR__) . '/src/System/ReleaseManifest.php';
require dirname(__DIR__) . '/src/Agent/Signer.php';
require dirname(__DIR__) . '/src/System/ReleaseKeyOffer.php';

use Sentinel\System\ReleaseManifest;

const MAX_COLLECTED = 100663296; // 96 MB: the whole staged release as JSON (files are base64)
const COLLECT_SECONDS = 180;

$argv = $_SERVER['argv'] ?? [];
$opt = static function (string $name) use ($argv): ?string {
    $i = array_search('--' . $name, $argv, true);
    return $i !== false ? (string) ($argv[$i + 1] ?? '') : null;
};
$test = getenv('SENTINEL_TEST_MODE') === '1';
foreach (['app', 'state', 'key', 'result', 'config'] as $o) {
    if (!$test && $opt($o) !== null) {
        fwrite(STDERR, "Test options are only allowed in the test suite.\n");
        exit(2);
    }
}
if (!$test && in_array('--no-systemd', $argv, true)) {
    fwrite(STDERR, "Test options are only allowed in the test suite.\n");
    exit(2);
}
$state = $test && $opt('state') ? rtrim((string) $opt('state'), '/') : '/var/lib/sentinel-agent';

// ---------------------------------------------------------------- collector (runs as the agent's user)
if (in_array('--collect', $argv, true)) {
    if (!$test && function_exists('posix_geteuid') && posix_geteuid() === 0) {
        fwrite(STDERR, "The collector must not run as root.\n");
        exit(2);
    }
    $out = ['request' => null, 'manifest' => '', 'signature' => '', 'files' => []];
    $raw = is_file($state . '/update-request') && !is_link($state . '/update-request') ? (string) file_get_contents($state . '/update-request', false, null, 0, 4096) : '';
    // Remove the request (a folder too: it must never keep the path unit firing).
    if (is_dir($state . '/update-request') && !is_link($state . '/update-request')) {
        @rmdir($state . '/update-request');
    }
    @unlink($state . '/update-request');
    $out['request'] = json_decode($raw, true);
    $out['offer'] = (string) @file_get_contents($state . '/release-key-offer.json', false, null, 0, 16384);
    @unlink($state . '/release-key-offer.json');
    $out['manifest'] = (string) @file_get_contents($state . '/update/agent-manifest.json', false, null, 0, 1048576);
    $out['signature'] = (string) @file_get_contents($state . '/update/agent-manifest.sig', false, null, 0, 4096);
    $listed = json_decode($out['manifest'], true);
    $total = 0;
    foreach (is_array($listed['files'] ?? null) ? array_keys($listed['files']) : [] as $path) {
        if (!is_string($path) || !ReleaseManifest::validPath($path)) {
            continue; // root refuses the manifest anyway
        }
        $f = $state . '/update/files/' . $path;
        $content = is_file($f) ? @file_get_contents($f, false, null, 0, ReleaseManifest::MAX_FILE_BYTES + 1) : false;
        if (!is_string($content)) {
            continue;
        }
        $total += strlen($content);
        if ($total > MAX_COLLECTED / 2) {
            break;
        }
        $out['files'][$path] = base64_encode($content);
    }
    fwrite(STDOUT, json_encode($out, JSON_UNESCAPED_SLASHES));
    exit(0);
}

// ---------------------------------------------------------------- installer (root)
if (!$test && (!function_exists('posix_geteuid') || posix_geteuid() !== 0)) {
    fwrite(STDERR, "The agent update helper must run as root (it is started by systemd).\n");
    exit(2);
}
$app = $test && $opt('app') ? rtrim((string) $opt('app'), '/') : '/opt/sentinel-agent';
$keyFile = $test && $opt('key') ? (string) $opt('key') : '/etc/sentinel-agent/release-key.pub';
$configFile = $test && $opt('config') ? (string) $opt('config') : '/etc/sentinel-agent/agent.json';
$resultDir = $test && $opt('result') ? rtrim((string) $opt('result'), '/') : '/var/lib/sentinel-agent-update';
$systemd = !($test && in_array('--no-systemd', $argv, true));
$php = PHP_BINARY;
// As the agent's user: setpriv changes uid, gid and groups and then execs (no fork), so a timeout kill reaches the
// command itself.
$asAgent = static fn (array $cmd): array => $test ? $cmd : array_merge(['/usr/bin/setpriv', '--reuid=sentinel-agent', '--regid=sentinel-agent', '--init-groups', '--reset-env', '--'], $cmd);
$say = static fn (string $m) => fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . '] ' . $m . "\n");
$requestId = '';
/** Write the result into the root-owned result folder (never the agent's), atomically. */
$result = static function (string $version, bool $ok, string $message) use ($resultDir, $say, $test, &$requestId): never {
    $say(($ok ? 'Updated: ' : 'Update refused: ') . $message);
    $gid = !$test && function_exists('posix_getgrnam') && ($g = posix_getgrnam('sentinel-agent')) !== false ? $g['gid'] : null;
    if (!is_dir($resultDir)) {
        mkdir($resultDir, 0750, true);
        if ($gid !== null) {
            chgrp($resultDir, $gid); // the agent must be able to read its results
        }
    }
    $tmp = $resultDir . '/result.json.' . bin2hex(random_bytes(6));
    file_put_contents($tmp, json_encode(['version' => mb_substr($version, 0, 20), 'ok' => $ok, 'message' => mb_substr($message, 0, 300), 'request' => $requestId,
        'at' => gmdate('Y-m-d\TH:i:s\Z')], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
    chmod($tmp, 0640);
    if ($gid !== null) {
        chgrp($tmp, $gid); // a file root just created in its own folder: safe
    }
    rename($tmp, $resultDir . '/result.json');
    exit($ok ? 0 : 1);
};
/** Run a command, return [exit code, stdout (capped)]. The command gets no stdin and at most $seconds. */
$run = static function (array $cmd, int $seconds, int $max = 65536): array {
    $p = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    if (!is_resource($p)) {
        return [127, ''];
    }
    stream_set_blocking($pipes[1], false);
    $out = '';
    $end = microtime(true) + $seconds;
    while (true) {
        $chunk = fread($pipes[1], 1048576);
        if (is_string($chunk) && $chunk !== '') {
            $out .= $chunk;
            if (strlen($out) > $max) {
                proc_terminate($p, 9);
                proc_close($p);
                return [125, ''];
            }
            continue;
        }
        $status = proc_get_status($p);
        if (!$status['running']) {
            $out .= (string) stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            proc_close($p);
            return [$status['exitcode'], $out];
        }
        if (microtime(true) > $end) {
            proc_terminate($p, 9);
            proc_close($p);
            return [124, ''];
        }
        usleep(20000);
    }
};
$rm = static function (string $dir): void { // only for root-owned folders under /opt (never the agent's)
    if (!is_dir($dir) || is_link($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) {
        $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($dir);
};

/**
 * The pinned release key, as [state, key]: /etc/sentinel-agent/release-key.pub, else (no file, or an empty one, as the
 * agent reads it too) the key pinned at enrolment in agent.json. Files must be root-owned, not writable by others and
 * not symlinks. States: 'ok' (a trusted key), 'absent' (truly nothing pinned: only then may a key be pinned without the
 * pinned key's signature), 'bad' (something is there but can't be trusted or isn't a key: refuse updates AND pins, so
 * a damaged pin never turns into "nothing pinned").
 *
 * @return array{0:'ok'|'absent'|'bad', 1:string}
 */
$pinnedKey = static function () use ($keyFile, $configFile, $test): array {
    $trusted = static function (string $f) use ($test): bool {
        $st = @lstat($f);
        return $st !== false && ($test || ($st['uid'] === 0 && ($st['mode'] & 0022) === 0 && !is_link($f) && is_file($f)));
    };
    if (file_exists($keyFile) || is_link($keyFile)) {
        if (!$trusted($keyFile)) {
            return ['bad', ''];
        }
        $k = trim((string) @file_get_contents($keyFile, false, null, 0, 1024));
        if ($k !== '') {
            return ReleaseManifest::validPublicKey($k) ? ['ok', $k] : ['bad', ''];
        }
    }
    if (!$trusted($configFile)) {
        return ['bad', '']; // the config also holds the server key: without it nothing can be checked
    }
    $cfg = json_decode((string) @file_get_contents($configFile), true);
    if (!is_array($cfg)) {
        return ['bad', ''];
    }
    $k = is_string($cfg['release_public_key'] ?? null) ? trim($cfg['release_public_key']) : '';
    return $k === '' ? ['absent', ''] : (ReleaseManifest::validPublicKey($k) ? ['ok', $k] : ['bad', '']);
};

// 0. A crash in the middle of a swap must never leave the appliance without its agent.
if (!is_dir($app) && is_dir($app . '.old')) {
    rename($app . '.old', $app);
    $say('Restored ' . $app . ' from ' . $app . '.old (an earlier update stopped half-way).');
}

// 1. Collect, as the agent's user.
[$code, $raw] = $run($asAgent(array_merge([$php, __FILE__, '--collect'], $test ? ['--state', $state] : [])), COLLECT_SECONDS, MAX_COLLECTED);
$c = $code === 0 ? json_decode($raw, true) : null;
$req = is_array($c) && is_array($c['request'] ?? null) ? $c['request'] : [];

// A release key offered by Sentinel: pin it (none pinned yet), or rotate to it (with a statement the pinned key signed).
if (($req['kind'] ?? null) === 'pin' && is_array($c)) {
    $requestId = is_string($req['request'] ?? null) && preg_match('/^[0-9TZ:. -]{1,30}$/', $req['request']) === 1 ? $req['request'] : '';
    $cfg = json_decode((string) @file_get_contents($configFile), true); // root-owned: the pinned server key and identity
    [$pinState, $pinned] = $pinnedKey();
    $decision = \Sentinel\System\ReleaseKeyOffer::decide((string) ($c['offer'] ?? ''), is_array($cfg) ? $cfg : [], $pinState, $pinned, 'agent-install.sh --upgrade --release-key');
    if (!$decision['ok'] || $decision['pin'] === null) {
        $result('release-key', $decision['ok'], $decision['message']);
    }
    $d = ['key' => $decision['pin']];
    $tmp = $keyFile . '.tmp';
    if (file_put_contents($tmp, $d['key'] . "\n") === false || !chmod($tmp, 0644) || !rename($tmp, $keyFile)) {
        $result('release-key', false, 'Could not write ' . $keyFile . '.');
    }
    $result('release-key', true, $decision['message']);
}
$wanted = is_string($req['version'] ?? null) && preg_match('/^\d{1,4}\.\d{1,4}\.\d{1,4}$/', $req['version']) === 1 ? $req['version'] : '';
$requestId = is_string($req['request'] ?? null) && preg_match('/^[0-9: -]{1,30}$/', $req['request']) === 1 ? $req['request'] : '';
if (!is_array($c) || $wanted === '') {
    $result('', false, 'No valid update request.');
}

// 2. Check, in memory, with the pinned release key (the key file, else the key pinned at enrolment in the config).
[$pinState, $pinned] = $pinnedKey();
if ($pinState !== 'ok') {
    $result($wanted, false, $pinState === 'absent' ? 'No release key is pinned on this appliance yet.'
        : 'The pinned release key (' . $keyFile . ' or agent.json) is damaged or not root-owned; fix it by hand (agent-install.sh --upgrade --release-key).');
}
$m = ReleaseManifest::verify((string) ($c['manifest'] ?? ''), (string) ($c['signature'] ?? ''), $pinned);
if (is_string($m)) {
    $result($wanted, false, 'Release refused: ' . $m . '.');
}
$installed = trim((string) @file_get_contents($app . '/VERSION'));
if (preg_match('/^\d+\.\d+\.\d+$/', $installed) !== 1) {
    $result($wanted, false, 'The installed version can\'t be read; upgrade by hand.');
}
if ($m['version'] !== $wanted || !ReleaseManifest::newer($m['version'], $installed)) {
    $result($wanted, false, 'Release ' . $m['version'] . ' is not the one requested or not newer than ' . $installed . '.');
}
$new = $app . '.new';
$rm($new);
$old = umask(0027);
mkdir($new, 0750, true);
foreach ($m['files'] as $path => $hash) {
    $content = is_string($c['files'][$path] ?? null) ? base64_decode($c['files'][$path], true) : false;
    if ($content === false || strlen($content) > ReleaseManifest::MAX_FILE_BYTES || !hash_equals($hash, hash('sha256', $content))) {
        $rm($new);
        $result($wanted, false, 'Staged file missing or not matching the signed release: ' . $path);
    }
    $dest = $new . '/' . $path;
    if (!is_dir(dirname($dest))) {
        mkdir(dirname($dest), 0750, true);
    }
    file_put_contents($dest, $content);
}
umask($old);
if (!$test) {
    // As the installer sets it: root:sentinel-agent, folders 0750, files 0640, the installer script executable.
    $gid = (posix_getgrnam('sentinel-agent') ?: ['gid' => 0])['gid'];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($new, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ([$new, ...array_map(static fn ($f): string => $f->getPathname(), iterator_to_array($it, false))] as $p) {
        chown($p, 0);
        chgrp($p, $gid);
        chmod($p, is_dir($p) ? 0750 : 0640);
    }
    chmod($new . '/install/agent-install.sh', 0750);
}

// 3. Pre-flight: the new release checks itself, as the agent's user.
[$code, $check] = $run($asAgent([$php, $new . '/bin/sentinel-agent.php', 'selfcheck']), 60);
if ($code !== 0 || trim($check) !== 'selfcheck ok ' . $m['version']) {
    $rm($new);
    $result($wanted, false, 'The new release did not pass its self-check on this appliance (' . mb_substr(trim($check), 0, 150) . '); upgrade by hand if it needs new packages.');
}

// 4. Swap, units, restart; roll back if the agent doesn't stay up.
// The agent is stopped first: its unit puts .old back when the code folder is missing (a repair after a power cut,
// 1.28), and a restart between the two renames below must not race the swap.
if ($systemd) {
    $run(['/usr/bin/systemctl', 'stop', 'sentinel-agent.service'], 60);
}
$startAgain = static function () use ($systemd, $run): void {
    if ($systemd) {
        $run(['/usr/bin/systemctl', 'start', 'sentinel-agent.service'], 60); // the version in place keeps running
    }
};
$rm($app . '.old');
if (!rename($app, $app . '.old')) {
    $rm($new);
    $startAgain();
    $result($wanted, false, 'Could not move the current version aside.');
}
if (!rename($new, $app)) {
    rename($app . '.old', $app);
    $startAgain();
    $result($wanted, false, 'Could not put the new version in place; the previous one was kept.');
}
if ($systemd) {
    $units = static function (string $root) use ($php): void {
        foreach (['sentinel-agent.service', 'sentinel-agent-update.service', 'sentinel-agent-update.path'] as $unit) {
            $tpl = @file_get_contents($root . '/install/templates/' . $unit);
            if ($tpl !== false) {
                file_put_contents('/etc/systemd/system/' . $unit, str_replace(['__ROOT__', '__PHP__', '__CONF__'], ['/opt/sentinel-agent', $php, '/etc/sentinel-agent'], $tpl));
            }
        }
    };
    $units($app);
    $run(['/usr/bin/systemctl', 'daemon-reload'], 60);
    $run(['/usr/bin/systemctl', 'restart', 'sentinel-agent.service'], 60);
    // Healthy = active at 20 s and again at 50 s, without having been restarted in between (a restart resets NRestarts).
    $healthy = true;
    foreach ([20, 30] as $wait) {
        sleep($wait);
        [$active] = $run(['/usr/bin/systemctl', 'is-active', '--quiet', 'sentinel-agent.service'], 15);
        [, $restarts] = $run(['/usr/bin/systemctl', 'show', '-p', 'NRestarts', '--value', 'sentinel-agent.service'], 15);
        $healthy = $healthy && $active === 0 && trim($restarts) === '0';
    }
    if (!$healthy) {
        // Roll back to the previous version, which was running before (agent stopped first: see the swap above).
        $run(['/usr/bin/systemctl', 'stop', 'sentinel-agent.service'], 60);
        $rm($app . '.failed');
        $back = rename($app, $app . '.failed') && rename($app . '.old', $app);
        if (!$back && !is_dir($app) && is_dir($app . '.failed')) {
            rename($app . '.failed', $app); // never leave no agent at all
        }
        $units($app);
        $run(['/usr/bin/systemctl', 'daemon-reload'], 60);
        $run(['/usr/bin/systemctl', 'restart', 'sentinel-agent.service'], 60);
        $result($wanted, false, $back ? 'Version ' . $m['version'] . ' did not stay running; ' . $installed . ' was put back (rolled back).'
            : 'Version ' . $m['version'] . ' did not stay running and the rollback failed: check the appliance.');
    }
}
$result($m['version'], true, 'Agent updated from ' . $installed . ' to ' . $m['version'] . ' (' . count($m['files']) . ' files, signature and every file checked, self-check passed).');
