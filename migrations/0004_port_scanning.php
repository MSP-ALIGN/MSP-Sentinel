<?php

declare(strict_types=1);

/**
 * Migration 0004: port scanning (jobs, append-only scan log, assets, services,
 * per-client port settings).
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS and addColumnIfMissing. Safe to run twice.
 *
 * Security notes:
 * - scan_log is append-only: one row per host the worker decided about
 *   (scanned, or skipped and why). It is the evidence of exactly what was
 *   touched, and when.
 * - scan_jobs.payload is a self-contained JSON snapshot of the targets and
 *   ports at queue time. The worker still re-checks the live scope before
 *   each host.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Port scanning: jobs, scan log, assets, services, client port settings',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $m->addColumnIfMissing('clients', 'ports_extra', "VARCHAR(500) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('clients', 'ports_excluded', "VARCHAR(500) NOT NULL DEFAULT ''");

        $db->exec("CREATE TABLE IF NOT EXISTS scan_jobs (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            job_type ENUM('ports') NOT NULL DEFAULT 'ports',
            trigger_type ENUM('manual','scheduled') NOT NULL,
            requested_by INT UNSIGNED NULL,
            outside_window TINYINT(1) NOT NULL DEFAULT 0,
            override_reason VARCHAR(300) NULL,
            status ENUM('queued','running','done','partial','failed','cancelled') NOT NULL DEFAULT 'queued',
            cancel_requested TINYINT(1) NOT NULL DEFAULT 0,
            payload MEDIUMTEXT NOT NULL,
            summary TEXT NULL,
            created_at DATETIME NOT NULL,
            started_at DATETIME NULL,
            finished_at DATETIME NULL,
            KEY idx_jobs_status (status, id),
            KEY idx_jobs_client (client_id, id),
            CONSTRAINT fk_jobs_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        // Installs that ran an earlier draft of this migration have a TEXT column (64 KB): widen it.
        $type = $db->query("SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scan_jobs' AND COLUMN_NAME = 'payload'")->fetchColumn();
        if ($type === 'text') {
            $db->exec('ALTER TABLE scan_jobs MODIFY payload MEDIUMTEXT NOT NULL');
        }

        $db->exec("CREATE TABLE IF NOT EXISTS scan_log (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            job_id INT UNSIGNED NOT NULL,
            client_id INT UNSIGNED NOT NULL,
            target VARCHAR(45) NOT NULL,
            hostname VARCHAR(260) NULL,
            ports VARCHAR(1000) NOT NULL DEFAULT '',
            result VARCHAR(40) NOT NULL,
            detail VARCHAR(500) NOT NULL DEFAULT '',
            started_at DATETIME NOT NULL,
            finished_at DATETIME NULL,
            KEY idx_scanlog_client (client_id, id),
            KEY idx_scanlog_job (job_id),
            CONSTRAINT fk_scanlog_job FOREIGN KEY (job_id) REFERENCES scan_jobs (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS assets (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            site_id INT UNSIGNED NULL,
            ip VARCHAR(45) NOT NULL,
            hostnames VARCHAR(1000) NOT NULL DEFAULT '',
            itflow_asset_id INT UNSIGNED NULL,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            last_scanned DATETIME NULL,
            UNIQUE KEY uq_assets_client_ip (client_id, ip),
            CONSTRAINT fk_assets_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS services (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            asset_id INT UNSIGNED NOT NULL,
            port SMALLINT UNSIGNED NOT NULL,
            protocol ENUM('tcp','udp') NOT NULL DEFAULT 'tcp',
            is_open TINYINT(1) NOT NULL DEFAULT 1,
            service_name VARCHAR(100) NOT NULL DEFAULT '',
            product VARCHAR(200) NOT NULL DEFAULT '',
            version VARCHAR(100) NOT NULL DEFAULT '',
            extra_info VARCHAR(200) NOT NULL DEFAULT '',
            cpe VARCHAR(255) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            closed_at DATETIME NULL,
            last_job_id INT UNSIGNED NULL,
            UNIQUE KEY uq_services_asset_port (asset_id, port, protocol),
            CONSTRAINT fk_services_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE RESTRICT
        ) {$opts}");
    },
];
