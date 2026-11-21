<?php

declare(strict_types=1);

/**
 * Migration 0002: clients, sites and the "authorised to scan" register.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, and default settings are inserted
 * with INSERT IGNORE. Safe to run twice.
 *
 * Security notes:
 * - scan_authorisations rows are never updated except to revoke them. The
 *   app has no edit path, so the record stays trustworthy as evidence.
 * - scope_entries holds only canonical values produced by ScopeParser. IP
 *   ranges are also stored as packed start and end addresses (VARBINARY(16))
 *   for exact range checks in SQL.
 * - Foreign keys use RESTRICT on authorisations, so evidence can't vanish
 *   by deleting a client. Clients are archived, not deleted.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Clients, sites, scan authorisations and scope entries; scanning kill switch',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $db->exec("CREATE TABLE IF NOT EXISTS clients (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(150) NOT NULL,
            itflow_client_id INT UNSIGNED NULL,
            timezone VARCHAR(64) NOT NULL DEFAULT 'UTC',
            scan_window_start TIME NOT NULL DEFAULT '22:00:00',
            scan_window_end TIME NOT NULL DEFAULT '06:00:00',
            scanning_paused TINYINT(1) NOT NULL DEFAULT 0,
            notes TEXT NULL,
            is_archived TINYINT(1) NOT NULL DEFAULT 0,
            created_by INT UNSIGNED NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            UNIQUE KEY uq_clients_name (name),
            KEY idx_clients_itflow (itflow_client_id)
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS sites (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            name VARCHAR(150) NOT NULL,
            itflow_location_id INT UNSIGNED NULL,
            is_default TINYINT(1) NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            UNIQUE KEY uq_sites_client_name (client_id, name),
            CONSTRAINT fk_sites_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS scan_authorisations (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            approved_by_name VARCHAR(150) NOT NULL,
            approved_by_role VARCHAR(150) NOT NULL,
            approved_on DATE NOT NULL,
            valid_from DATE NOT NULL,
            valid_until DATE NOT NULL,
            document_ref VARCHAR(190) NOT NULL DEFAULT '',
            notes TEXT NULL,
            recorded_by INT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL,
            revoked_at DATETIME NULL,
            revoked_by INT UNSIGNED NULL,
            revoke_reason VARCHAR(500) NULL,
            KEY idx_auth_client (client_id),
            CONSTRAINT fk_auth_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT,
            CONSTRAINT fk_auth_recorded_by FOREIGN KEY (recorded_by) REFERENCES users (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS scope_entries (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            authorisation_id INT UNSIGNED NOT NULL,
            client_id INT UNSIGNED NOT NULL,
            entry_type ENUM('ip','cidr','domain') NOT NULL,
            value VARCHAR(260) NOT NULL,
            range_start VARBINARY(16) NULL,
            range_end VARBINARY(16) NULL,
            KEY idx_scope_auth (authorisation_id),
            KEY idx_scope_client (client_id),
            KEY idx_scope_range (range_start, range_end),
            KEY idx_scope_value (value),
            CONSTRAINT fk_scope_auth FOREIGN KEY (authorisation_id) REFERENCES scan_authorisations (id) ON DELETE RESTRICT,
            CONSTRAINT fk_scope_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        // Global kill switch, off by default.
        $db->exec("INSERT IGNORE INTO settings (name, value) VALUES ('scanning_paused', '0')");
    },
];
