<?php

declare(strict_types=1);

/**
 * Migration 0052 (1.45.1): clients.itflow_resumed_at, when "Don't sync with ITFlow" was last turned off. Findings opened
 * before then get no new ITFlow ticket, so turning the switch off doesn't send a backlog of old findings to ITFlow.
 *
 * Idempotent: the column is added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'When a client\'s ITFlow sync was turned back on',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('clients', 'itflow_resumed_at', 'DATETIME NULL DEFAULT NULL');
    },
];
