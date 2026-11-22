<?php

declare(strict_types=1);

/**
 * Migration 0006: vulnerability data (NVD answers, CISA KEV, EPSS) and
 * matches between services and CVEs.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS. Safe to run twice.
 *
 * Security notes: all feed data is public, but it is still untrusted input.
 * It is validated and length-limited before storage and escaped on output.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Vulnerability data: CVEs, KEV, EPSS, CPE query cache, service matches, feed status',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $db->exec("CREATE TABLE IF NOT EXISTS cves (
            cve_id VARCHAR(20) NOT NULL PRIMARY KEY,
            summary VARCHAR(1000) NOT NULL DEFAULT '',
            cvss_score DECIMAL(3,1) NULL,
            cvss_severity VARCHAR(10) NOT NULL DEFAULT '',
            cvss_version VARCHAR(5) NOT NULL DEFAULT '',
            published DATE NULL,
            last_modified DATETIME NULL,
            fetched_at DATETIME NOT NULL
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS kev_catalog (
            cve_id VARCHAR(20) NOT NULL PRIMARY KEY,
            vendor VARCHAR(200) NOT NULL DEFAULT '',
            product VARCHAR(200) NOT NULL DEFAULT '',
            name VARCHAR(300) NOT NULL DEFAULT '',
            date_added DATE NULL,
            due_date DATE NULL,
            ransomware VARCHAR(20) NOT NULL DEFAULT '',
            required_action VARCHAR(500) NOT NULL DEFAULT ''
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS epss_scores (
            cve_id VARCHAR(20) NOT NULL PRIMARY KEY,
            score DECIMAL(6,5) NOT NULL,
            percentile DECIMAL(6,5) NOT NULL,
            score_date DATE NULL
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS cpe_queries (
            query VARCHAR(255) NOT NULL PRIMARY KEY,
            status ENUM('pending','ok','error') NOT NULL DEFAULT 'pending',
            result_count INT UNSIGNED NOT NULL DEFAULT 0,
            error VARCHAR(300) NOT NULL DEFAULT '',
            fail_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
            fetched_at DATETIME NULL,
            last_needed DATETIME NULL,
            created_at DATETIME NOT NULL
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS cpe_query_cves (
            query VARCHAR(255) NOT NULL,
            cve_id VARCHAR(20) NOT NULL,
            PRIMARY KEY (query, cve_id),
            KEY idx_cqc_cve (cve_id)
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS service_vulns (
            service_id INT UNSIGNED NOT NULL,
            cve_id VARCHAR(20) NOT NULL,
            confidence ENUM('confirmed','distro','possible') NOT NULL,
            cpe VARCHAR(255) NOT NULL,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            PRIMARY KEY (service_id, cve_id),
            KEY idx_sv_cve (cve_id),
            CONSTRAINT fk_sv_service FOREIGN KEY (service_id) REFERENCES services (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS feed_status (
            name VARCHAR(20) NOT NULL PRIMARY KEY,
            last_attempt DATETIME NULL,
            last_success DATETIME NULL,
            message VARCHAR(300) NOT NULL DEFAULT '',
            item_count INT UNSIGNED NOT NULL DEFAULT 0,
            last_request DOUBLE NULL,
            blocked_until DATETIME NULL
        ) {$opts}");
    },
];
