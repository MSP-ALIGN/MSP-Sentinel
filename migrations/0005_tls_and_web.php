<?php

declare(strict_types=1);

/**
 * Migration 0005: TLS certificate checks and web admin-page detection.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, and the job_type enum is widened
 * only if it doesn't already include 'tls'. Safe to run twice.
 *
 * Security notes: every stored value comes from remote servers (certificate
 * fields, page titles, headers). It is cleaned and length-limited before
 * storage and escaped on output.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'TLS endpoints, web pages, daily TLS check jobs',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scan_jobs' AND COLUMN_NAME = 'job_type'")->fetchColumn();
        if (!str_contains($type, "'tls'")) {
            $db->exec("ALTER TABLE scan_jobs MODIFY job_type ENUM('ports','tls') NOT NULL DEFAULT 'ports'");
        }

        $db->exec("CREATE TABLE IF NOT EXISTS tls_endpoints (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            asset_id INT UNSIGNED NOT NULL,
            port SMALLINT UNSIGNED NOT NULL,
            sni VARCHAR(260) NOT NULL DEFAULT '',
            subject_cn VARCHAR(260) NOT NULL DEFAULT '',
            sans TEXT NULL,
            issuer VARCHAR(300) NOT NULL DEFAULT '',
            not_before DATETIME NULL,
            not_after DATETIME NULL,
            self_signed TINYINT(1) NULL,
            chain_trusted TINYINT(1) NULL,
            hostname_match TINYINT(1) NULL,
            key_type VARCHAR(20) NOT NULL DEFAULT '',
            key_bits SMALLINT UNSIGNED NULL,
            signature_alg VARCHAR(80) NOT NULL DEFAULT '',
            protocol VARCHAR(20) NOT NULL DEFAULT '',
            accepts_tls10 TINYINT(1) NULL,
            accepts_tls11 TINYINT(1) NULL,
            last_error VARCHAR(300) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_checked DATETIME NOT NULL,
            UNIQUE KEY uq_tls_endpoint (asset_id, port, sni),
            KEY idx_tls_expiry (not_after),
            CONSTRAINT fk_tls_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS web_pages (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            asset_id INT UNSIGNED NOT NULL,
            port SMALLINT UNSIGNED NOT NULL,
            scheme ENUM('http','https') NOT NULL,
            host_header VARCHAR(260) NOT NULL DEFAULT '',
            status_code SMALLINT UNSIGNED NULL,
            title VARCHAR(300) NOT NULL DEFAULT '',
            server_header VARCHAR(200) NOT NULL DEFAULT '',
            redirect_to VARCHAR(500) NOT NULL DEFAULT '',
            category VARCHAR(40) NULL,
            matched VARCHAR(100) NOT NULL DEFAULT '',
            last_error VARCHAR(300) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_checked DATETIME NOT NULL,
            UNIQUE KEY uq_web_page (asset_id, port),
            CONSTRAINT fk_web_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE RESTRICT
        ) {$opts}");
    },
];
