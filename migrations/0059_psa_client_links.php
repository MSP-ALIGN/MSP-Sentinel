<?php

declare(strict_types=1);

/**
 * Migration 0059 (1.54): psa_client_links, the link between a Sentinel client and its client in a ticketing system
 * (PSA). The PSA's client ID is kept as text compared exactly (utf8mb4_bin), so PSAs with text or GUID IDs fit too.
 * One link per client per PSA, and a PSA client belongs to at most one Sentinel client.
 *
 * Existing ITFlow links are copied from clients.itflow_client_id, which stays and is kept in step (the REST API and
 * MSP Align matching read it).
 *
 * Idempotent: the table is created only when missing, and the copy skips links that already exist (INSERT IGNORE).
 * Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Client links to ticketing systems',
    'up' => static function (PDO $db, Migrator $m): void {
        $db->exec("CREATE TABLE IF NOT EXISTS psa_client_links (
            client_id INT UNSIGNED NOT NULL,
            provider VARCHAR(20) NOT NULL,
            external_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
            linked_at DATETIME NOT NULL,
            PRIMARY KEY (client_id, provider),
            UNIQUE KEY uq_psa_external (provider, external_id),
            CONSTRAINT fk_psa_link_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        $db->exec("INSERT IGNORE INTO psa_client_links (client_id, provider, external_id, linked_at)
                   SELECT id, 'itflow', CAST(itflow_client_id AS CHAR), UTC_TIMESTAMP() FROM clients WHERE itflow_client_id IS NOT NULL");
    },
];
