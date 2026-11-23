<?php

declare(strict_types=1);

/**
 * MSP Sentinel agent (Linux): the root update helper's launcher. install/agent-install.sh copies it to
 * /usr/local/lib/sentinel-agent/update-launcher.php (root:root 0644), OUTSIDE the code folder /opt/sentinel-agent, and
 * the systemd units start it as root:
 * - sentinel-agent-update.service runs it instead of bin/agent-update-runner.php. It repairs an update stopped half-way
 *   (/opt/sentinel-agent missing, /opt/sentinel-agent.old there: a power cut between the helper's two renames) and
 *   then runs the helper from /opt/sentinel-agent. The helper itself can't do that repair: its code is in the folder
 *   that is missing. The unit's ExecStartPre refreshes this file from the code folder first, when that folder exists.
 * - sentinel-agent.service runs it with --repair-only before every start of the agent (ExecStartPre, "+": as root).
 *   After a power cut no update request is left (the helper had already taken it), so nothing would start the helper;
 *   the agent's own start at boot repairs the folder instead, and then starts from it.
 * The twin of install/windows/agent-update-launcher.php.
 *
 * Locking: the launcher holds an exclusive lock (/var/lib/sentinel-agent-update/update.lock) for the whole helper run.
 * --repair-only only tries it: while the helper runs, the folders are its to swap, and repairing in the middle of a
 * swap would break the update (the helper repairs or rolls back itself).
 *
 * Nothing here comes from outside: no request, no network, no file the agent's user can write. Fixed paths only, all
 * root-owned: /opt (the code folders), /var/lib/sentinel-agent-update (root:sentinel-agent 0750; the lock file is
 * refused if it is a symlink). The helper it starts is the root-owned code root already trusted to run as root.
 *
 * TEST SUITE ONLY: with SENTINEL_TEST_MODE=1, --app and --result point it at test folders (the helper reads the same
 * options, and its other test options, from the same command line). Without it those options are refused and it
 * must run as root.
 */

$sentinelLauncher = (static function (): array {
    $argv = $_SERVER['argv'] ?? [];
    $test = getenv('SENTINEL_TEST_MODE') === '1';
    $opt = static function (string $name) use ($argv): ?string {
        $i = array_search('--' . $name, $argv, true);
        return $i !== false ? (string) ($argv[$i + 1] ?? '') : null;
    };
    foreach (['app', 'result'] as $o) {
        if (!$test && $opt($o) !== null) {
            fwrite(STDERR, "Test options are only allowed in the test suite.\n");
            exit(2);
        }
    }
    if (!$test && (!function_exists('posix_geteuid') || posix_geteuid() !== 0)) {
        fwrite(STDERR, "The agent update launcher must run as root (it is started by systemd).\n");
        exit(2);
    }
    $app = $test && $opt('app') ? rtrim((string) $opt('app'), '/') : '/opt/sentinel-agent';
    $resultDir = $test && $opt('result') ? rtrim((string) $opt('result'), '/') : '/var/lib/sentinel-agent-update';
    $repairOnly = in_array('--repair-only', $argv, true);
    $say = static fn (string $m) => fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . '] ' . $m . "\n");

    // The lock, in the helper's own root-owned folder (created as the installer and the unit do, if missing).
    if (!is_dir($resultDir)) {
        @mkdir($resultDir, 0750, true);
        if (!$test && function_exists('posix_getgrnam') && ($g = posix_getgrnam('sentinel-agent')) !== false) {
            @chgrp($resultDir, $g['gid']); // the agent reads its results here
        }
    }
    $lockFile = $resultDir . '/update.lock';
    $lock = !is_link($lockFile) ? @fopen($lockFile, 'c') : false;
    if ($lock === false) {
        fwrite(STDERR, 'Could not open the update lock ' . $lockFile . ".\n");
        exit(1);
    }
    if (!flock($lock, $repairOnly ? LOCK_EX | LOCK_NB : LOCK_EX)) {
        exit(0); // --repair-only while the helper runs: the folders are the helper's to swap
    }

    // An update stopped half-way: put the previous version back before anything else.
    $repaired = false;
    if (!file_exists($app) && !is_link($app) && is_dir($app . '.old') && !is_link($app . '.old')) {
        $repaired = rename($app . '.old', $app);
        $say($repaired ? 'Restored ' . $app . ' from ' . $app . '.old (an earlier update stopped half-way).'
            : 'Could not restore ' . $app . ' from ' . $app . '.old.');
    }
    return ['app' => $app, 'lock' => $lock, 'repaired' => $repaired, 'repairOnly' => $repairOnly];
})();

if ($sentinelLauncher['repairOnly']) {
    exit(is_dir($sentinelLauncher['app']) ? 0 : 1);
}
if ($sentinelLauncher['repaired']) {
    define('SENTINEL_UPDATE_REPAIRED', true); // the helper starts the agent again
}
// The lock stays held (this variable keeps it open) until the helper exits.
require $sentinelLauncher['app'] . '/bin/agent-update-runner.php';
