<?php

declare(strict_types=1);

/**
 * Migration 0016: the on-premises scanning agent. Internal authorisations
 * per site (signed when an admin records them), agents and their one-time
 * enrolment codes, agent jobs, a kill switch per site, and the open ports
 * (with certificate and web page results) of internal devices.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, addColumnIfMissing, enum changes
 * only when a value is missing. Safe to run twice.
 *
 * Security notes: agent tokens and enrolment codes are stored only as
 * HMAC hashes. Authorisation signatures are made with a key derived from
 * the config file's app key, never stored in the database, so changing the
 * database alone can't approve new internal ranges.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'On-premises agents: internal authorisations, enrolment, jobs, device ports',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';

        $m->addColumnIfMissing('sites', 'scanning_paused', 'TINYINT(1) NOT NULL DEFAULT 0');

        $db->exec("CREATE TABLE IF NOT EXISTS internal_authorisations (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            site_id INT UNSIGNED NOT NULL,
            approved_by_name VARCHAR(150) NOT NULL,
            approved_by_role VARCHAR(150) NOT NULL,
            approved_on DATE NOT NULL,
            valid_from DATE NOT NULL,
            valid_until DATE NOT NULL,
            document_ref VARCHAR(190) NOT NULL DEFAULT '',
            notes TEXT NULL,
            ranges TEXT NOT NULL,
            signed_payload TEXT NOT NULL,
            signature VARCHAR(100) NOT NULL,
            recorded_by INT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL,
            revoked_at DATETIME NULL,
            revoked_by INT UNSIGNED NULL,
            revoke_reason VARCHAR(500) NULL,
            KEY idx_iauth_site (site_id, revoked_at),
            CONSTRAINT fk_iauth_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT,
            CONSTRAINT fk_iauth_site FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS agents (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            site_id INT UNSIGNED NOT NULL,
            name VARCHAR(100) NOT NULL,
            token_prefix CHAR(12) NOT NULL,
            token_hash CHAR(64) NOT NULL,
            hostname VARCHAR(255) NOT NULL DEFAULT '',
            version VARCHAR(20) NOT NULL DEFAULT '',
            status ENUM('active','revoked') NOT NULL DEFAULT 'active',
            enrolled_at DATETIME NOT NULL,
            enrolled_by INT UNSIGNED NULL,
            last_seen_at DATETIME NULL,
            last_ip VARCHAR(45) NOT NULL DEFAULT '',
            revoked_at DATETIME NULL,
            revoked_by INT UNSIGNED NULL,
            UNIQUE KEY uq_agent_prefix (token_prefix),
            KEY idx_agents_site (site_id, status),
            CONSTRAINT fk_agents_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT,
            CONSTRAINT fk_agents_site FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS agent_enrolments (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            site_id INT UNSIGNED NOT NULL,
            code_hash CHAR(64) NOT NULL,
            created_by INT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            used_at DATETIME NULL,
            agent_id INT UNSIGNED NULL,
            UNIQUE KEY uq_enrol_code (code_hash),
            CONSTRAINT fk_enrol_site FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS agent_jobs (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            agent_id INT UNSIGNED NOT NULL,
            client_id INT UNSIGNED NOT NULL,
            site_id INT UNSIGNED NOT NULL,
            authorisation_id INT UNSIGNED NOT NULL,
            kind ENUM('full','light') NOT NULL,
            trigger_type ENUM('scheduled','manual') NOT NULL DEFAULT 'scheduled',
            requested_by INT UNSIGNED NULL,
            status ENUM('queued','sent','done','partial','failed','cancelled','expired') NOT NULL DEFAULT 'queued',
            ports TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            sent_at DATETIME NULL,
            finished_at DATETIME NULL,
            expires_at DATETIME NOT NULL,
            cancel_requested TINYINT(1) NOT NULL DEFAULT 0,
            summary TEXT NULL,
            KEY idx_ajobs_agent (agent_id, status),
            KEY idx_ajobs_site (site_id, kind, id),
            CONSTRAINT fk_ajobs_agent FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE RESTRICT,
            CONSTRAINT fk_ajobs_auth FOREIGN KEY (authorisation_id) REFERENCES internal_authorisations (id) ON DELETE RESTRICT
        ) {$opts}");

        $db->exec("CREATE TABLE IF NOT EXISTS device_ports (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            device_id INT UNSIGNED NOT NULL,
            port SMALLINT UNSIGNED NOT NULL,
            service VARCHAR(60) NOT NULL DEFAULT '',
            product VARCHAR(120) NOT NULL DEFAULT '',
            version VARCHAR(80) NOT NULL DEFAULT '',
            extra_info VARCHAR(200) NOT NULL DEFAULT '',
            tls MEDIUMTEXT NULL,
            web MEDIUMTEXT NULL,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            UNIQUE KEY uq_device_port (device_id, port),
            CONSTRAINT fk_dport_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        ) {$opts}");

        $m->addColumnIfMissing('devices', 'site_id', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('devices', 'mac', "VARCHAR(17) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('device_software', 'distro', 'TINYINT(1) NOT NULL DEFAULT 0');
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'software_vulns' AND COLUMN_NAME = 'confidence'")->fetchColumn();
        if (!str_contains($type, "'distro'")) {
            $db->exec("ALTER TABLE software_vulns MODIFY confidence ENUM('confirmed','distro','possible') NOT NULL");
        }
    },
];
