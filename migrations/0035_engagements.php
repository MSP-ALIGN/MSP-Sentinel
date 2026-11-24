<?php

declare(strict_types=1);

/**
 * Migration 0035 (1.27): pen-test engagements.
 *
 * An engagement is a time-boxed, deeper test the client authorised in writing (the signed document is stored as a
 * file; its SHA-256 is kept here). It never widens what may be tested: every target must already be inside the
 * client's active "authorised to scan" scope (external) or a site's active internal authorisation (internal). It
 * adds the client's consent to test those targets harder, within a window, with chosen test types.
 *
 * - engagements: one row per engagement. Never edited after approval (evidence); it can only be stopped (kill
 *   switch) or closed. approved_by must differ from created_by (two-person rule, checked in the app).
 * - engagement_targets: the exact scope: external targets (canonical IPs, ranges, domains), internal ranges per site,
 *   and exclusions (kind 'exclude', external or internal).
 * - findings.engagement_id: findings an engagement's tests produced (NULL for everything else).
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, addColumnIfMissing, index only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Pen-test engagements and their scope',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
        $db->exec("CREATE TABLE IF NOT EXISTS engagements (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            name VARCHAR(150) NOT NULL,
            window_start DATETIME NOT NULL,
            window_end DATETIME NOT NULL,
            intensity ENUM('gentle','normal') NOT NULL DEFAULT 'gentle',
            tests VARCHAR(255) NOT NULL,
            signer_name VARCHAR(150) NOT NULL,
            signer_role VARCHAR(150) NOT NULL,
            signed_on DATE NOT NULL,
            document_sha256 CHAR(64) NOT NULL,
            document_name VARCHAR(190) NOT NULL,
            document_bytes INT UNSIGNED NOT NULL,
            notes TEXT NULL,
            created_by INT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL,
            approved_by INT UNSIGNED NULL,
            approved_at DATETIME NULL,
            stopped_by INT UNSIGNED NULL,
            stopped_at DATETIME NULL,
            stop_reason VARCHAR(500) NULL,
            cancelled_at DATETIME NULL,
            KEY idx_eng_client (client_id),
            CONSTRAINT fk_eng_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT,
            CONSTRAINT fk_eng_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT
        ) {$opts}");
        $db->exec("CREATE TABLE IF NOT EXISTS engagement_targets (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            engagement_id INT UNSIGNED NOT NULL,
            kind ENUM('external','internal','exclude') NOT NULL,
            site_id INT UNSIGNED NULL,
            entry_type ENUM('ip','cidr','domain') NOT NULL,
            value VARCHAR(260) NOT NULL,
            range_start VARBINARY(16) NULL,
            range_end VARBINARY(16) NULL,
            KEY idx_engt_engagement (engagement_id),
            CONSTRAINT fk_engt_engagement FOREIGN KEY (engagement_id) REFERENCES engagements (id) ON DELETE RESTRICT
        ) {$opts}");
        $m->addColumnIfMissing('findings', 'engagement_id', 'INT UNSIGNED NULL');
        if (!$m->indexExists('findings', 'idx_findings_engagement')) {
            $db->exec('CREATE INDEX idx_findings_engagement ON findings (engagement_id)');
        }
    },
];
