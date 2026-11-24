<?php

declare(strict_types=1);

/**
 * MSP Sentinel agent (Windows): the update task's launcher. install-agent.ps1 copies it to
 * C:\Program Files\MSP Sentinel Agent\agent-update-launcher.php, OUTSIDE the code folder (app\), and Task Scheduler
 * runs it as SYSTEM. PHP keeps the script it was started with open, and Windows can't rename a folder with an open
 * file in it: started from here, the task can swap app\ for a new release (files it includes are closed after loading).
 *
 * It also repairs an update stopped half-way (app\ missing, app.old\ there) before anything else, which the task
 * itself could not do (its code is in app\).
 *
 * Frozen update code (1.35): the task's code runs from updater\ next to this file, a copy that remote updates never
 * change, so code from a new release never runs as SYSTEM (a release only ever runs as the agent's service account).
 * install-agent.ps1 refreshes the copy on install and -Upgrade; when it is missing (an agent updated from an older
 * version), it is made once here from the installed app\ (checked when it was installed), before anything is swapped.
 *
 * Nothing here comes from outside: fixed paths next to this file (Administrators and SYSTEM only).
 */

$app = __DIR__ . '\\app';
$updater = __DIR__ . '\\updater';
if (!is_dir($app) && is_dir($app . '.old') && rename($app . '.old', $app)) {
    define('SENTINEL_UPDATE_REPAIRED', true); // the task starts the service again (under its lock)
}
if (!is_file($updater . '\\bin\\agent-update-task.php')) {
    /** Copy a folder tree (plain files and folders only; links are skipped). */
    $copy = static function (string $from, string $to) use (&$copy): bool {
        if (!is_dir($to) && !mkdir($to, 0755, true)) {
            return false;
        }
        foreach (scandir($from) ?: [] as $name) {
            if ($name === '.' || $name === '..' || is_link($from . '\\' . $name)) {
                continue;
            }
            $ok = is_dir($from . '\\' . $name) ? $copy($from . '\\' . $name, $to . '\\' . $name) : copy($from . '\\' . $name, $to . '\\' . $name);
            if (!$ok) {
                return false;
            }
        }
        return true;
    };
    $tmp = $updater . '.tmp';
    if (!is_dir($app . '\\src') || !$copy($app . '\\src', $tmp . '\\src') || !is_dir($tmp . '\\bin') && !mkdir($tmp . '\\bin', 0755, true)
        || !copy($app . '\\bin\\agent-update-task.php', $tmp . '\\bin\\agent-update-task.php') || !rename($tmp, $updater)) {
        fwrite(STDERR, "Could not prepare the update code folder (updater): run install-agent.ps1 -Upgrade.\n");
        exit(1);
    }
}
define('SENTINEL_UPDATE_APP', $app);
require $updater . '\\bin\\agent-update-task.php';
