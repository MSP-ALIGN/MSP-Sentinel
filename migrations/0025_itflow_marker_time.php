<?php

declare(strict_types=1);

/**
 * Migration 0025: itflow_tickets.marker_at - when Sentinel sent the create call carrying that row's marker. After an
 * unclear answer, the lookup reads the client's tickets from the newest and stops at tickets older than this, instead
 * of reading the whole list.
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'ITFlow ticket marker time',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('itflow_tickets', 'marker_at', 'DATETIME NULL');
    },
];
