<?php

declare(strict_types=1);

/**
 * Migration 0013: website checks (headers, cookies, exposed files), detected
 * CMS/JavaScript components with their vulnerability matches, email security
 * records per domain, and the new "email" finding type.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, addColumnIfMissing, and the enum
 * change only when 'email' is missing. Safe to run twice.
 *
 * Security notes: results are summaries (codes, short cleaned strings). The
 * content of exposed files is never stored.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Website checks, web components, email security records',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
        $m->addColumnIfMissing('web_pages', 'checks', 'MEDIUMTEXT NULL');
        $m->addColumnIfMissing('web_pages', 'checks_at', 'DATETIME NULL');

        $db->exec("CREATE TABLE IF NOT EXISTS web_components (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            web_page_id INT UNSIGNED NOT NULL,
            kind ENUM('cms','library') NOT NULL,
            name VARCHAR(40) NOT NULL,
            version VARCHAR(40) NOT NULL DEFAULT '',
            cpe VARCHAR(255) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            UNIQUE KEY uq_component (web_page_id, name),
            CONSTRAINT fk_component_page FOREIGN KEY (web_page_id) REFERENCES web_pages (id) ON DELETE CASCADE
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS component_vulns (
            component_id INT UNSIGNED NOT NULL,
            cve_id VARCHAR(20) NOT NULL,
            confidence ENUM('confirmed','possible') NOT NULL,
            cpe VARCHAR(255) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            PRIMARY KEY (component_id, cve_id),
            CONSTRAINT fk_cv_component FOREIGN KEY (component_id) REFERENCES web_components (id) ON DELETE CASCADE
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS email_checks (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            domain VARCHAR(253) NOT NULL,
            has_mx TINYINT(1) NOT NULL DEFAULT 0,
            result MEDIUMTEXT NOT NULL,
            checked_at DATETIME NOT NULL,
            UNIQUE KEY uq_email_domain (client_id, domain),
            CONSTRAINT fk_email_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'findings' AND COLUMN_NAME = 'finding_type'")->fetchColumn();
        if (!str_contains($type, "'email'")) {
            $db->exec("ALTER TABLE findings MODIFY finding_type ENUM('port','tls','web','vuln','email') NOT NULL");
        }
    },
];
