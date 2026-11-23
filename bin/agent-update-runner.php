<?php

declare(strict_types=1);

/**
 * MSP Sentinel agent update helper. Runs as ROOT, started by the systemd path unit sentinel-agent-update.path when the
 * agent writes /var/lib/sentinel-agent/update-request. The agent itself is unprivileged and can't change its code; it
 * stages a release in its state folder (src/AgentClient/Updater.php). This helper trusts NOTHING the agent staged:
 *
 * 1. The request is removed first (one attempt per request, no loops).
 * 2. The staged manifest must be signed with the pinned release key (/etc/sentinel-agent/release-key.pub, root-owned,
 *    written by the installer; never from the staged files), be the version requested, and be newer than the installed
 *    one (no downgrades).
 * 3. Every file is COPIED into a new root-owned folder and the copy is hashed: the staged files belong to the agent's
 *    user, so checking them in place would let that user swap a file after the check. Exactly the manifest's files,
 *    no others, no symlinks.
 * 4. The new folder replaces /opt/sentinel-agent (the previous one is kept as /opt/sentinel-agent.old), the systemd
 *    units are written again from the new release's templates, and the agent is restarted.
 * The result is written to /var/lib/sentinel-agent/update-result.json for the agent to report.
 *
 * TEST SUITE ONLY: with SENTINEL_TEST_MODE=1, --app, --state, --key and --no-systemd point it at test folders and it
 * may run unprivileged. Without it, those options are refused and it must run as root.
 */

require dirname(__DIR__) . '/src/System/ReleaseManifest.php';

use Sentinel\System\ReleaseManifest;

$argv = $_SERVER['argv'] ?? [];
$opt = static function (string $name) use ($argv): ?string {
    $i = array_search('--' . $name, $argv, true);
    return $i !== false ? (string) ($argv[$i + 1] ?? '') : null;
};
$test = getenv('SENTINEL_TEST_MODE') === '1';
if (!$test && ($opt('app') !== null || $opt('state') !== null || $opt('key') !== null || in_array('--no-systemd', $argv, true))) {
    fwrite(STDERR, "Test options are only allowed in the test suite.\n");
    exit(2);
}
if (!$test && (!function_exists('posix_geteuid') || posix_geteuid() !== 0)) {
    fwrite(STDERR, "The agent update helper must run as root (it is started by systemd).\n");
    exit(2);
}
$app = $test && $opt('app') ? rtrim((string) $opt('app'), '/') : '/opt/sentinel-agent';
$state = $test && $opt('state') ? rtrim((string) $opt('state'), '/') : '/var/lib/sentinel-agent';
$keyFile = $test && $opt('key') ? (string) $opt('key') : '/etc/sentinel-agent/release-key.pub';
$systemd = !($test && in_array('--no-systemd', $argv, true));
$say = static fn (string $m) => fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . '] ' . $m . "\n");
$result = static function (string $version, bool $ok, string $message) use ($state, $say, $test): never {
    $say(($ok ? 'Updated: ' : 'Update refused: ') . $message);
    file_put_contents($state . '/update-result.json', json_encode(['version' => $version, 'ok' => $ok, 'message' => mb_substr($message, 0, 300), 'at' => gmdate('Y-m-d\TH:i:s\Z')]));
    if (!$test && function_exists('posix_getpwnam') && ($u = posix_getpwnam('sentinel-agent')) !== false) {
        @chown($state . '/update-result.json', $u['uid']);
    }
    exit($ok ? 0 : 1);
};

// 1. One attempt per request.
$request = json_decode((string) @file_get_contents($state . '/update-request'), true);
@unlink($state . '/update-request');
$wanted = is_array($request) && is_string($request['version'] ?? null) ? $request['version'] : '';
if ($wanted === '') {
    $result('', false, 'No valid update request.');
}

// 2. Signed with the pinned release key, the version asked for, newer than installed.
if (!$test) {
    $st = @stat($keyFile);
    if ($st === false || $st['uid'] !== 0 || ($st['mode'] & 0022) !== 0) {
        $result($wanted, false, 'The release key file must exist, belong to root and not be writable by others: ' . $keyFile);
    }
}
$json = (string) @file_get_contents($state . '/update/agent-manifest.json');
$sig = (string) @file_get_contents($state . '/update/agent-manifest.sig');
$m = ReleaseManifest::verify($json, $sig, (string) @file_get_contents($keyFile));
if (is_string($m)) {
    $result($wanted, false, 'Release refused: ' . $m . '.');
}
$installed = trim((string) @file_get_contents($app . '/VERSION'));
if ($m['version'] !== $wanted || !ReleaseManifest::newer($m['version'], $installed)) {
    $result($wanted, false, 'Release ' . $m['version'] . ' is not the one requested or not newer than ' . $installed . '.');
}

// 3. Copy into a root-owned folder, hashing each copy.
$new = $app . '.new';
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
$rm($new);
$old = umask(0027);
mkdir($new, 0750, true);
foreach ($m['files'] as $path => $hash) {
    $src = $state . '/update/files/' . $path;
    if (is_link($src) || !is_file($src) || filesize($src) > ReleaseManifest::MAX_FILE_BYTES) {
        $rm($new);
        $result($wanted, false, 'Staged file missing or not a plain file: ' . $path);
    }
    $content = (string) file_get_contents($src, false, null, 0, ReleaseManifest::MAX_FILE_BYTES + 1);
    if (!hash_equals($hash, hash('sha256', $content))) {
        $rm($new);
        $result($wanted, false, 'Staged file does not match the signed release: ' . $path);
    }
    $dest = $new . '/' . $path;
    if (!is_dir(dirname($dest))) {
        mkdir(dirname($dest), 0750, true);
    }
    file_put_contents($dest, $content);
    if (!hash_equals($hash, (string) hash_file('sha256', $dest))) { // the copy is what gets installed
        $rm($new);
        $result($wanted, false, 'Copy check failed: ' . $path);
    }
}
umask($old);
if (!$test) {
    // As the installer sets it: root:sentinel-agent, folders 0750, files 0640, the installer script executable.
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($new, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    $gid = (posix_getgrnam('sentinel-agent') ?: ['gid' => 0])['gid'];
    foreach ([$new, ...iterator_to_array($it, false)] as $f) {
        $p = is_string($f) ? $f : $f->getPathname();
        chown($p, 0);
        chgrp($p, $gid);
        chmod($p, is_dir($p) ? 0750 : 0640);
    }
    chmod($new . '/install/agent-install.sh', 0750);
}

// 4. Swap, write the units from the new templates, restart.
$rm($app . '.old');
if (!rename($app, $app . '.old')) {
    $rm($new);
    $result($wanted, false, 'Could not move the current version aside.');
}
if (!rename($new, $app)) {
    rename($app . '.old', $app);
    $result($wanted, false, 'Could not put the new version in place; the previous one was kept.');
}
$rm($state . '/update');
if ($systemd) {
    $php = '/usr/bin/php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    foreach (['sentinel-agent.service', 'sentinel-agent-update.service', 'sentinel-agent-update.path'] as $unit) {
        $tpl = @file_get_contents($app . '/install/templates/' . $unit);
        if ($tpl !== false) {
            file_put_contents('/etc/systemd/system/' . $unit, str_replace(['__ROOT__', '__PHP__', '__CONF__'], [$app, $php, '/etc/sentinel-agent'], $tpl));
        }
    }
    foreach ([['daemon-reload'], ['restart', 'sentinel-agent.service']] as $args) {
        $p = proc_open(array_merge(['/usr/bin/systemctl'], $args), [0 => ['file', '/dev/null', 'r'], 1 => STDOUT, 2 => STDOUT], $pipes);
        if (is_resource($p)) {
            proc_close($p);
        }
    }
}
$result($m['version'], true, 'Agent updated from ' . $installed . ' to ' . $m['version'] . ' (' . count($m['files']) . ' files, signature and every file checked).');
