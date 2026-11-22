<?php

declare(strict_types=1);

/**
 * Migration 0009: reports (frozen snapshots), daily finding counts for trends,
 * per-client monthly report settings, and report attachments on deliveries.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS and addColumnIfMissing. Safe to run twice.
 *
 * Security notes:
 * - A report stores the rendered HTML and the snapshot it was built from, so
 *   it never changes after it is issued. Its SHA-256 is kept to show that.
 * - Report content comes from scan data (untrusted); it is escaped when the
 *   report is rendered, and served with a CSP that allows no scripts.
 * - report_recipients are MSP staff addresses (validated by the controller).
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Reports, finding trend counts, monthly report settings',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $db->exec("CREATE TABLE IF NOT EXISTS reports (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            kind ENUM('executive','technical') NOT NULL,
            source ENUM('manual','scheduled') NOT NULL DEFAULT 'manual',
            title VARCHAR(300) NOT NULL,
            period_start DATE NOT NULL,
            period_end DATE NOT NULL,
            generated_at DATETIME NOT NULL,
            generated_by INT UNSIGNED NULL,
            html MEDIUMTEXT NOT NULL,
            snapshot MEDIUMTEXT NOT NULL,
            html_sha256 CHAR(64) NOT NULL,
            KEY idx_reports_client (client_id, id),
            KEY idx_reports_sched (client_id, source, period_start),
            CONSTRAINT fk_reports_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        // One row per client per day: open Fail/Warning counts, for the trend chart.
        $db->exec("CREATE TABLE IF NOT EXISTS finding_stats (
            client_id INT UNSIGNED NOT NULL,
            day DATE NOT NULL,
            fail_open INT UNSIGNED NOT NULL DEFAULT 0,
            warn_open INT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY (client_id, day),
            CONSTRAINT fk_stats_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $m->addColumnIfMissing('clients', 'report_monthly', 'TINYINT(1) NOT NULL DEFAULT 0');
        $m->addColumnIfMissing('clients', 'report_recipients', "VARCHAR(1300) NOT NULL DEFAULT ''");
        // Report IDs to attach to an email (comma-separated). The HTML is read from `reports` when sending.
        $m->addColumnIfMissing('deliveries', 'report_ids', "VARCHAR(100) NOT NULL DEFAULT ''");
    },
];
