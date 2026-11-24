<?php

declare(strict_types=1);

/**
 * Migration 0054 (1.48): users.timezone, the time zone a user sees times in ('' = the organisation's, from Settings).
 * Times are still stored and compared in UTC; this only changes how they are shown.
 *
 * Idempotent: the column is added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Per-user display time zone',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('users', 'timezone', "VARCHAR(64) NOT NULL DEFAULT ''");
    },
];
