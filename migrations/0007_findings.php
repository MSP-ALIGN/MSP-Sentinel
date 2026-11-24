<?php

declare(strict_types=1);

/**
 * Migration 0007: findings (one list of graded problems per client) and their history.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS. Safe to run twice.
 *
 * Security notes:
 * - finding_events is append-only: every change (opened, resolved, reopened,
 *   triaged, evidence changed) is recorded with who and when.
 * - Titles and details are built from scan data (untrusted) and escaped on output.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Findings and finding history',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $db->exec("CREATE TABLE IF NOT EXISTS findings (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            asset_id INT UNSIGNED NULL,
            finding_key VARCHAR(190) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
            finding_type ENUM('port','tls','web','vuln') NOT NULL,
            severity ENUM('fail','warn') NOT NULL,
            title VARCHAR(300) NOT NULL,
            detail VARCHAR(1000) NOT NULL DEFAULT '',
            target VARCHAR(320) NOT NULL DEFAULT '',
            evidence VARCHAR(500) NOT NULL DEFAULT '',
            cve_id VARCHAR(20) NULL,
            status ENUM('open','resolved','accepted','false_positive') NOT NULL DEFAULT 'open',
            triage_note TEXT NULL,
            triaged_by INT UNSIGNED NULL,
            triaged_at DATETIME NULL,
            reappeared TINYINT(1) NOT NULL DEFAULT 0,
            reopened_count INT UNSIGNED NOT NULL DEFAULT 0,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            resolved_at DATETIME NULL,
            resolved_from ENUM('open','accepted','false_positive') NULL,
            UNIQUE KEY uq_finding_key (client_id, finding_key),
            KEY idx_findings_status (status, severity),
            KEY idx_findings_client (client_id, status),
            CONSTRAINT fk_findings_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS finding_events (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            finding_id INT UNSIGNED NOT NULL,
            event VARCHAR(30) NOT NULL,
            user_id INT UNSIGNED NULL,
            note TEXT NULL,
            created_at DATETIME NOT NULL,
            KEY idx_events_finding (finding_id, id),
            CONSTRAINT fk_events_finding FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE RESTRICT
        ) {$opts}");
    },
];
