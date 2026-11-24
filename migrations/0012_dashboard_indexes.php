<?php

declare(strict_types=1);

/**
 * Migration 0012: index for the dashboards' "last scan" per client.
 *
 * Idempotent: the index is only added if it is missing. Safe to run twice.
 * Security notes: none (an index only).
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Dashboard index: scan jobs by client and finish time',
    'up' => static function (PDO $db, Migrator $m): void {
        if (!$m->indexExists('scan_jobs', 'idx_jobs_client_finished')) {
            $db->exec('ALTER TABLE scan_jobs ADD KEY idx_jobs_client_finished (client_id, finished_at)');
        }
    },
];
