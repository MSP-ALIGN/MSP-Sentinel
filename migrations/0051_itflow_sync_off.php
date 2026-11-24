<?php

declare(strict_types=1);

/**
 * Migration 0051 (1.45): clients.itflow_sync_off, a per-client switch "Don't sync with ITFlow": the ITFlow sync never
 * renames, archives, restores or links that client, and no ITFlow tickets are opened or updated for it.
 *
 * Idempotent: the column is added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Per-client ITFlow sync switch',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('clients', 'itflow_sync_off', 'TINYINT(1) NOT NULL DEFAULT 0');
    },
];
