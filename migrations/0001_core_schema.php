<?php

declare(strict_types=1);

/**
 * Migration 0001: core tables for users, 2FA, throttling, settings and audit.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, and the index is only added when
 * missing. Safe to run twice.
 *
 * Security notes:
 * - users.username uses a case-insensitive collation, so "Alice" and
 *   "alice" can't both exist (no look-alike accounts).
 * - totp_secret_enc holds the TOTP seed encrypted with the app key.
 * - user_recovery_codes stores HMACs only, never the codes themselves.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Core schema: users, recovery codes, auth throttle, settings, audit log',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $db->exec("CREATE TABLE IF NOT EXISTS users (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            email VARCHAR(190) NOT NULL DEFAULT '',
            role ENUM('admin','technician','viewer') NOT NULL DEFAULT 'viewer',
            password_hash VARCHAR(255) NOT NULL,
            must_change_password TINYINT(1) NOT NULL DEFAULT 1,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            totp_secret_enc VARCHAR(255) NULL,
            totp_enabled_at DATETIME NULL,
            totp_last_step BIGINT NULL,
            session_version INT UNSIGNED NOT NULL DEFAULT 1,
            last_login_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            UNIQUE KEY uq_users_username (username)
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS user_recovery_codes (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT UNSIGNED NOT NULL,
            code_hash CHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            used_at DATETIME NULL,
            KEY idx_recovery_user (user_id),
            CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS auth_throttle (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            bucket CHAR(64) NOT NULL,
            attempted_at DATETIME NOT NULL,
            KEY idx_throttle_bucket_time (bucket, attempted_at)
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS settings (
            name VARCHAR(64) NOT NULL PRIMARY KEY,
            value TEXT NOT NULL
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS audit_log (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            created_at DATETIME NOT NULL,
            user_id INT UNSIGNED NULL,
            username VARCHAR(100) NULL,
            action VARCHAR(64) NOT NULL,
            target_type VARCHAR(32) NULL,
            target_id BIGINT UNSIGNED NULL,
            ip VARCHAR(45) NULL,
            details TEXT NULL,
            KEY idx_audit_created (created_at)
        ) {$opts}");

        if (!$m->indexExists('audit_log', 'idx_audit_action')) {
            $db->exec('CREATE INDEX idx_audit_action ON audit_log (action)');
        }
    },
];
