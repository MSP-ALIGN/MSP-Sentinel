<?php

declare(strict_types=1);

/**
 * Migration 0019: MSP Align compliance (read-only). A client can be linked to its MSP Align client, and the
 * frameworks and controls read from MSP Align are cached per client (so the Compliance page doesn't call MSP Align
 * on every view).
 *
 * Idempotent: addColumnIfMissing and CREATE TABLE IF NOT EXISTS only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'MSP Align compliance link and cache',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('clients', 'align_client_id', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('clients', 'align_client_name', 'VARCHAR(190) NULL');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS align_cache (
                client_id INT UNSIGNED NOT NULL PRIMARY KEY,
                fetched_at DATETIME NOT NULL,
                data MEDIUMTEXT NOT NULL,
                CONSTRAINT fk_align_cache_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
    },
];
