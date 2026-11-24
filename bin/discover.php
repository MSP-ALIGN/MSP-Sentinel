<?php

declare(strict_types=1);

/**
 * CLI: run passive target discovery for every eligible client (for the weekly cron job).
 *
 * Usage: php bin/discover.php [--client=ID]
 * Cron example (Sundays 03:17): 17 3 * * 0  php /path/to/msp-sentinel/bin/discover.php
 *
 * Security assumptions: CLI only. Discovery itself refuses archived or paused
 * clients and clients without an active authorisation, and honours the
 * global kill switch. Runs have no time budget here, but each run is capped
 * by a query limit.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;

$opts = getopt('', ['client::']);
try {
    App::boot();
    $service = App::discovery();
    $ids = isset($opts['client'])
        ? [(int) $opts['client']]
        : array_map(static fn (array $c): int => (int) $c['id'], App::clients()->all(false));
    $exit = 0;
    foreach ($ids as $id) {
        $result = $service->run($id, 'scheduled', null, null);
        if ($result['status'] !== 'refused') {
            App::audit()->log('discovery.run', null, 'cli', 'client', $id, ['status' => $result['status'], 'new' => $result['new'], 'run_id' => $result['run_id']]);
        }
        fwrite(STDOUT, sprintf("client %d: %s - %s\n", $id, $result['status'], $result['message']));
        if ($result['status'] === 'failed') {
            $exit = 1;
        }
    }
    exit($exit);
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Discovery failed: ' . $ex->getMessage() . "\n");
    exit(1);
}
