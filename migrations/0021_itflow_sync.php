<?php

declare(strict_types=1);

/**
 * Migration 0021: ITFlow client sync. clients.itflow_archived marks clients the sync archived (because they were
 * archived in ITFlow), so unarchiving in ITFlow restores only those, never a client an admin archived in Sentinel.
 * clients.itflow_client_id and its index already exist (migration 0002).
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'ITFlow client sync',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('clients', 'itflow_archived', 'TINYINT(1) NOT NULL DEFAULT 0');
    },
];
