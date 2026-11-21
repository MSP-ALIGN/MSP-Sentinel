<?php

declare(strict_types=1);

/**
 * CLI: apply pending database migrations.
 *
 * Usage: php bin/migrate.php
 *
 * Security assumptions: run by the server administrator only (refuses to run
 * from the web). Safe to run any number of times, because migrations are
 * idempotent.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;
use Sentinel\Migrations\Migrator;

try {
    App::boot();
    $applied = (new Migrator(App::db(), SENTINEL_ROOT . '/migrations'))->migrate(static function (string $line): void {
        fwrite(STDOUT, $line . "\n");
    });
    fwrite(STDOUT, $applied === [] ? "Database is up to date.\n" : 'Applied ' . count($applied) . " migration(s).\n");
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Migration failed: ' . $ex->getMessage() . "\n");
    exit(1);
}
