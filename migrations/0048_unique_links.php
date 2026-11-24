<?php

declare(strict_types=1);

/**
 * Migration 0048 (1.42.2): one Sentinel client per MSP Align client and per ITFlow client, in the database too.
 *
 * - UNIQUE keys on clients.align_client_id and clients.itflow_client_id (NULLs allowed many times). The forms already
 *   refuse a link in use; the keys also close the race between two saves.
 * - An install that already has a duplicate keeps working: the key is only added when there is none, and the System
 *   page's health check isn't affected. Clear the duplicate link on one of the clients and run the migration again.
 *
 * Idempotent: each key is added only when missing and the column has no duplicates. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Unique MSP Align and ITFlow links',
    'up' => static function (PDO $db, Migrator $m): void {
        foreach (['align_client_id' => 'uq_clients_align', 'itflow_client_id' => 'uq_clients_itflow'] as $column => $key) {
            if ($m->indexExists('clients', $key)) {
                continue;
            }
            $dupes = (int) $db->query("SELECT COUNT(*) FROM (SELECT {$column} FROM clients WHERE {$column} IS NOT NULL GROUP BY {$column} HAVING COUNT(*) > 1) d")->fetchColumn();
            if ($dupes === 0) {
                $db->exec("ALTER TABLE clients ADD UNIQUE KEY {$key} ({$column})");
            } else {
                error_log("[msp-sentinel] migration 0048: {$dupes} duplicate {$column} value(s); unique key not added until they are cleared");
            }
        }
    },
];
