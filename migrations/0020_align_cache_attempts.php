<?php

declare(strict_types=1);

/**
 * Migration 0020: when MSP Align was last tried for a client (also after a failure), so an unreachable MSP Align
 * isn't asked again on every page view.
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'MSP Align cache: last attempt',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('align_cache', 'attempted_at', 'DATETIME NULL');
    },
];
