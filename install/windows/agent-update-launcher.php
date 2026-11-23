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
 * Nothing here comes from outside: fixed paths next to this file (Administrators and SYSTEM only).
 */

$app = __DIR__ . '\\app';
if (!is_dir($app) && is_dir($app . '.old') && rename($app . '.old', $app)) {
    define('SENTINEL_UPDATE_REPAIRED', true); // the task starts the service again (under its lock)
}
define('SENTINEL_UPDATE_APP', $app);
require $app . '\\bin\\agent-update-task.php';
