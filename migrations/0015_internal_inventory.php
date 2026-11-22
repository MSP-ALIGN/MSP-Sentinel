<?php

declare(strict_types=1);

/**
 * Migration 0015: internal devices from inventory sources (NinjaOne first,
 * the on-premises agent later): devices with OS and protection status, their
 * installed software (matched to CVEs), missing OS patches, and the link
 * between a client and its organisation in each source. Findings record
 * their source (external scan or an inventory source), and get the new
 * types "patch" (missing OS patches) and "device" (unsupported OS,
 * antivirus, disk encryption).
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, addColumnIfMissing, and enum
 * changes only when a value is missing. Safe to run twice.
 *
 * Security notes: inventory data is untrusted text from the source and is
 * stored short. Nothing here can make Sentinel touch a device: inventory is
 * read from the source's API only.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Internal inventory: devices, software, patches, sources',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        // Which organisation in a source belongs to which client (linked by an admin, never automatically).
        $db->exec("CREATE TABLE IF NOT EXISTS source_links (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            source VARCHAR(20) NOT NULL,
            org_id VARCHAR(64) NOT NULL,
            org_name VARCHAR(200) NOT NULL DEFAULT '',
            linked_by INT UNSIGNED NULL,
            linked_at DATETIME NOT NULL,
            last_sync_at DATETIME NULL,
            last_sync_status VARCHAR(20) NOT NULL DEFAULT '',
            last_sync_message VARCHAR(500) NOT NULL DEFAULT '',
            UNIQUE KEY uq_link_client (client_id, source),
            UNIQUE KEY uq_link_org (source, org_id),
            CONSTRAINT fk_link_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS devices (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            source VARCHAR(20) NOT NULL,
            source_id VARCHAR(64) NOT NULL,
            name VARCHAR(255) NOT NULL DEFAULT '',
            dns_name VARCHAR(255) NOT NULL DEFAULT '',
            device_class VARCHAR(40) NOT NULL DEFAULT '',
            os_name VARCHAR(255) NOT NULL DEFAULT '',
            os_build VARCHAR(64) NOT NULL DEFAULT '',
            os_release VARCHAR(64) NOT NULL DEFAULT '',
            ip_addresses VARCHAR(500) NOT NULL DEFAULT '',
            last_contact DATETIME NULL,
            av_product VARCHAR(200) NOT NULL DEFAULT '',
            av_state VARCHAR(20) NOT NULL DEFAULT '',
            av_definitions VARCHAR(20) NOT NULL DEFAULT '',
            encryption VARCHAR(20) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            removed_at DATETIME NULL,
            UNIQUE KEY uq_device_source (source, source_id),
            KEY idx_devices_client (client_id, removed_at),
            CONSTRAINT fk_devices_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS device_software (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            device_id INT UNSIGNED NOT NULL,
            name VARCHAR(255) NOT NULL,
            publisher VARCHAR(255) NOT NULL DEFAULT '',
            version VARCHAR(100) NOT NULL DEFAULT '',
            product VARCHAR(80) NOT NULL DEFAULT '',
            cpe VARCHAR(255) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            UNIQUE KEY uq_device_software (device_id, name(150), version(50)),
            KEY idx_software_cpe (cpe(100)),
            CONSTRAINT fk_software_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS software_vulns (
            software_id INT UNSIGNED NOT NULL,
            cve_id VARCHAR(20) NOT NULL,
            confidence ENUM('confirmed','possible') NOT NULL,
            cpe VARCHAR(255) NOT NULL DEFAULT '',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            PRIMARY KEY (software_id, cve_id),
            CONSTRAINT fk_sv_software FOREIGN KEY (software_id) REFERENCES device_software (id) ON DELETE CASCADE
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS device_patches (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            device_id INT UNSIGNED NOT NULL,
            patch_id VARCHAR(100) NOT NULL,
            name VARCHAR(300) NOT NULL DEFAULT '',
            kb VARCHAR(20) NOT NULL DEFAULT '',
            severity VARCHAR(20) NOT NULL DEFAULT '',
            status VARCHAR(20) NOT NULL DEFAULT '',
            detected_at DATETIME NULL,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            UNIQUE KEY uq_device_patch (device_id, patch_id),
            CONSTRAINT fk_patch_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        ) {$opts}");

        $m->addColumnIfMissing('findings', 'source', "VARCHAR(20) NOT NULL DEFAULT 'external'");
        $m->addColumnIfMissing('findings', 'device_id', 'INT UNSIGNED NULL');
        if (!$m->indexExists('findings', 'idx_findings_source')) {
            $db->exec('ALTER TABLE findings ADD KEY idx_findings_source (client_id, source, status)');
        }
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'findings' AND COLUMN_NAME = 'finding_type'")->fetchColumn();
        if (!str_contains($type, "'patch'") || !str_contains($type, "'device'")) {
            $db->exec("ALTER TABLE findings MODIFY finding_type ENUM('port','tls','web','vuln','email','patch','device') NOT NULL");
        }
    },
];
