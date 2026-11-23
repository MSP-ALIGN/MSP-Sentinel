<?php

declare(strict_types=1);

/**
 * Migration 0036 (1.27): engagement scans.
 * - scan_jobs.job_type gains 'engagement' (an engagement's external tests, run by the scan worker).
 * - engagement_results: what each engagement test found per host (external from Sentinel, internal from an agent):
 *   open ports with service details, nmap script results and anonymous-access checks. Raw evidence for the pen-test
 *   report; values came from the tested hosts and are untrusted (escaped when shown).
 *
 * Idempotent: the enum is widened only when 'engagement' is missing; CREATE TABLE IF NOT EXISTS. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Engagement scan jobs and results',
    'up' => static function (PDO $db, Migrator $m): void {
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scan_jobs' AND COLUMN_NAME = 'job_type'")->fetchColumn();
        if (!str_contains($type, "'engagement'")) {
            $db->exec("ALTER TABLE scan_jobs MODIFY job_type ENUM('ports','tls','verify','engagement') NOT NULL DEFAULT 'ports'");
        }
        $db->exec("CREATE TABLE IF NOT EXISTS engagement_results (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            engagement_id INT UNSIGNED NOT NULL,
            origin ENUM('external','internal') NOT NULL,
            site_id INT UNSIGNED NULL,
            job_ref VARCHAR(40) NOT NULL DEFAULT '',
            ip VARCHAR(45) NOT NULL,
            hostnames VARCHAR(500) NOT NULL DEFAULT '',
            ports MEDIUMTEXT NOT NULL,
            checks MEDIUMTEXT NULL,
            complete TINYINT(1) NOT NULL DEFAULT 0,
            scanned_at DATETIME NOT NULL,
            KEY idx_engr_engagement (engagement_id, ip),
            CONSTRAINT fk_engr_engagement FOREIGN KEY (engagement_id) REFERENCES engagements (id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    },
];
