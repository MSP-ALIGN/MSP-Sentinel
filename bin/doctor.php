<?php

declare(strict_types=1);

/**
 * CLI: check that this install is healthy (PHP, database, migrations, nmap,
 * cron, storage, HTTPS, mail, updates).
 *
 * Usage: php bin/doctor.php [--json]
 * Exit code: 0 = no failures (warnings allowed), 1 = at least one failure, 2 = could not run.
 *
 * Security assumptions: run by the server administrator only (refuses to run
 * from the web). Output never contains secrets.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;

try {
    App::boot();
    $checks = App::health()->run();
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Health check could not run: ' . $ex->getMessage() . "\n");
    exit(2);
}
$failed = count(array_filter($checks, static fn (array $c): bool => $c['status'] === 'fail'));
if (in_array('--json', $argv, true)) {
    fwrite(STDOUT, json_encode(['version' => App::version(), 'checks' => $checks], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
} else {
    fwrite(STDOUT, 'MSP Sentinel ' . App::version() . "\n\n");
    foreach ($checks as $c) {
        $mark = ['ok' => ' OK ', 'warn' => 'WARN', 'fail' => 'FAIL'][$c['status']];
        fwrite(STDOUT, sprintf("[%s] %-26s %s\n", $mark, $c['label'], $c['detail']));
    }
    fwrite(STDOUT, "\n" . ($failed === 0 ? "No failures.\n" : "{$failed} failure(s): fix these first.\n"));
}
exit($failed === 0 ? 0 : 1);
