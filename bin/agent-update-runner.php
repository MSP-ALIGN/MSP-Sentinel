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
 *    release-key.pub: root-owned, written by the installer, never by an update), is the version requested and newer
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

use Sentinel\System\ReleaseManifest;

const MAX_COLLECTED = 100663296; // 96 MB: the whole staged release as JSON (files are base64)
const COLLECT_SECONDS = 180;

$argv = $_SERVER['argv'] ?? [];
$opt = static function (string $name) use ($argv): ?string {
    $i = array_search('--' . $name, $argv, true);
    return $i !== false ? (string) ($argv[$i + 1] ?? '') : null;
};
$test = getenv('SENTINEL_TEST_MODE') === '1';
foreach (['app', 'state', 'key', 'result'] as $o) {
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
$resultDir = $test && $opt('result') ? rtrim((string) $opt('result'), '/') : '/var/lib/sentinel-agent-update';
$systemd = !($test && in_array('--no-systemd', $argv, true));
$php = PHP_BINARY;
$asAgent = static fn (array $cmd): array => $test ? $cmd : array_merge(['/usr/sbin/runuser', '-u', 'sentinel-agent', '--'], $cmd);
$say = static fn (string $m) => fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . '] ' . $m . "\n");
$requestId = '';
/** Write the result into the root-owned result folder (never the agent's), atomically. */
$result = static function (string $version, bool $ok, string $message) use ($resultDir, $say, $test, &$requestId): never {
    $say(($ok ? 'Updated: ' : 'Update refused: ') . $message);
    if (!is_dir($resultDir)) {
        mkdir($resultDir, 0750, true);
    }
    $tmp = $resultDir . '/result.json.' . bin2hex(random_bytes(6));
    file_put_contents($tmp, json_encode(['version' => mb_substr($version, 0, 20), 'ok' => $ok, 'message' => mb_substr($message, 0, 300), 'request' => $requestId,
        'at' => gmdate('Y-m-d\TH:i:s\Z')], JSON_UNESCAPED_SLASHES));
    chmod($tmp, 0640);
    if (!$test && function_exists('posix_getgrnam') && ($g = posix_getgrnam('sentinel-agent')) !== false) {
        chgrp($tmp, $g['gid']); // a file root just created in its own folder: safe
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

// 1. Collect, as the agent's user.
[$code, $raw] = $run($asAgent(array_merge([$php, __FILE__, '--collect'], $test ? ['--state', $state] : [])), COLLECT_SECONDS, MAX_COLLECTED);
$c = $code === 0 ? json_decode($raw, true) : null;
$req = is_array($c) && is_array($c['request'] ?? null) ? $c['request'] : [];
$wanted = is_string($req['version'] ?? null) && preg_match('/^\d{1,4}\.\d{1,4}\.\d{1,4}$/', $req['version']) === 1 ? $req['version'] : '';
$requestId = is_string($req['request'] ?? null) && preg_match('/^[0-9: -]{1,30}$/', $req['request']) === 1 ? $req['request'] : '';
if (!is_array($c) || $wanted === '') {
    $result('', false, 'No valid update request.');
}

// 2. Check, in memory.
if (!$test) {
    $st = @stat($keyFile);
    if ($st === false || $st['uid'] !== 0 || ($st['mode'] & 0022) !== 0) {
        $result($wanted, false, 'The release key file must exist, belong to root and not be writable by others: ' . $keyFile);
    }
}
$m = ReleaseManifest::verify((string) ($c['manifest'] ?? ''), (string) ($c['signature'] ?? ''), (string) @file_get_contents($keyFile));
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
if ($code !== 0 || !str_contains($check, 'selfcheck ok')) {
    $rm($new);
    $result($wanted, false, 'The new release did not pass its self-check on this appliance (' . mb_substr(trim($check), 0, 150) . '); upgrade by hand if it needs new packages.');
}

// 4. Swap, units, restart; roll back if the agent doesn't stay up.
$rm($app . '.old');
if (!rename($app, $app . '.old')) {
    $rm($new);
    $result($wanted, false, 'Could not move the current version aside.');
}
if (!rename($new, $app)) {
    rename($app . '.old', $app);
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
    sleep(20);
    [$active] = $run(['/usr/bin/systemctl', 'is-active', '--quiet', 'sentinel-agent.service'], 15);
    if ($active !== 0) {
        // Roll back to the previous version, which was running before.
        $rm($app . '.failed');
        rename($app, $app . '.failed');
        rename($app . '.old', $app);
        $units($app);
        $run(['/usr/bin/systemctl', 'daemon-reload'], 60);
        $run(['/usr/bin/systemctl', 'restart', 'sentinel-agent.service'], 60);
        $result($wanted, false, 'Version ' . $m['version'] . ' did not stay running; ' . $installed . ' was put back (rolled back).');
    }
}
$result($m['version'], true, 'Agent updated from ' . $installed . ' to ' . $m['version'] . ' (' . count($m['files']) . ' files, signature and every file checked, self-check passed).');
