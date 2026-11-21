<?php

declare(strict_types=1);

/**
 * CLI: the scan worker. Queues weekly scans and runs the next job whose scan
 * window is open. Run it from cron every minute:
 *
 *   * * * * *  php /path/to/msp-sentinel/bin/worker.php
 *
 * Only one worker runs at a time (database lock), so overlapping cron runs exit at once.
 *
 * Options: --no-schedule (don't queue weekly scans this time), --job=ID (run only that queued job).
 *
 * Security assumptions: CLI only. Run it as an ordinary, unprivileged user
 * (never root): nmap uses TCP connect scans and needs no privileges.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;

if (function_exists('posix_geteuid') && posix_geteuid() === 0 && getenv('SENTINEL_ALLOW_ROOT') !== '1') {
    fwrite(STDERR, "Refusing to run the scan worker as root. Run it as an unprivileged user.\n");
    exit(1);
}

try {
    App::boot();
    $worker = App::scanWorker(static function (string $line): void {
        fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . '] ' . $line . "\n");
    });
    $opts = getopt('', ['no-schedule', 'job:']);
    $jobId = isset($opts['job']) && ctype_digit((string) $opts['job']) ? (int) $opts['job'] : null;
    fwrite(STDOUT, $worker->tick(!isset($opts['no-schedule']), $jobId) . "\n");
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Worker failed: ' . $ex->getMessage() . "\n");
    exit(1);
}
