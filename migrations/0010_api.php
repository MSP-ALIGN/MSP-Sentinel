<?php

declare(strict_types=1);

/**
 * Migration 0010: API tokens (with per-client limits), change timestamps for
 * "updated_since" queries, and the outbound event channel.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, addColumnIfMissing, and the enum
 * change is only made if 'event' is missing. Safe to run twice.
 *
 * Security notes:
 * - Tokens are never stored: only a keyed hash (HMAC with the app key) and a
 *   short public prefix used to find the row. A database leak alone does not
 *   reveal usable tokens.
 * - Every token has an expiry date and records who created it, when it was
 *   last used and from where.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'API tokens, updated_at for findings and assets, event deliveries',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $db->exec("CREATE TABLE IF NOT EXISTS api_tokens (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            token_prefix CHAR(12) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            all_clients TINYINT(1) NOT NULL DEFAULT 0,
            can_triage TINYINT(1) NOT NULL DEFAULT 0,
            can_scan TINYINT(1) NOT NULL DEFAULT 0,
            ip_allowlist VARCHAR(500) NOT NULL DEFAULT '',
            expires_at DATETIME NOT NULL,
            created_by INT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL,
            last_used_at DATETIME NULL,
            last_used_ip VARCHAR(45) NULL,
            revoked_at DATETIME NULL,
            revoked_by INT UNSIGNED NULL,
            UNIQUE KEY uq_api_token_prefix (token_prefix),
            CONSTRAINT fk_api_tokens_user FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS api_token_clients (
            token_id INT UNSIGNED NOT NULL,
            client_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (token_id, client_id),
            CONSTRAINT fk_api_tc_token FOREIGN KEY (token_id) REFERENCES api_tokens (id) ON DELETE CASCADE,
            CONSTRAINT fk_api_tc_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        // Change timestamps kept by the database itself, so every update path is covered.
        foreach (['findings', 'assets'] as $table) {
            $exists = (int) $db->query("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{$table}' AND COLUMN_NAME = 'updated_at'")->fetchColumn();
            if ($exists === 0) {
                $db->exec("ALTER TABLE {$table} ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, ADD KEY idx_{$table}_updated (updated_at)");
                $db->exec("UPDATE {$table} SET updated_at = last_seen");
            }
        }

        // Who queued a scan through the API.
        $m->addColumnIfMissing('scan_jobs', 'api_token_id', 'INT UNSIGNED NULL');

        // Outbound events share the delivery outbox.
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'deliveries' AND COLUMN_NAME = 'channel'")->fetchColumn();
        if (!str_contains($type, "'event'")) {
            $db->exec("ALTER TABLE deliveries MODIFY channel ENUM('email','webhook','event') NOT NULL");
        }
    },
];
