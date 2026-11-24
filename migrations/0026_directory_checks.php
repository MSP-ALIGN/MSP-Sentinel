<?php

declare(strict_types=1);

/**
 * Migration 0026: Active Directory checks through the on-premises agent.
 *
 * - agents.box_public_key: the agent's own P-256 public key (SPKI, base64). Browsers encrypt a site's directory
 *   password to it, so only that agent can read it; Sentinel never can.
 * - site_directory: per site, the domain, the domain controller's address, the read-only account's user name (not a
 *   secret), the DC certificate (fingerprint the agent saw, and the one an admin trusted), where the password is
 *   (waiting for the agent / held by agent #n), and the latest directory results (account names capped, no secrets).
 * - agent_secret_drops: a sealed password on its way to an agent. Sentinel can't open it; it is deleted when the agent
 *   confirms it, or after it expires.
 * - sites.llmnr_results / llmnr_checked_at: what the agent heard while listening for LLMNR and NetBIOS name requests
 *   (devices that would answer a name-poisoning tool); independent of the directory settings.
 * - findings.finding_type gains 'directory'.
 *
 * Idempotent: addColumnIfMissing, CREATE TABLE IF NOT EXISTS, and the ENUM is only changed when 'directory' is
 * missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Active Directory checks: agent keys, site directory settings, sealed password drops',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
        $m->addColumnIfMissing('agents', 'box_public_key', "VARCHAR(255) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('sites', 'llmnr_results', 'TEXT NULL');
        $m->addColumnIfMissing('sites', 'llmnr_checked_at', 'DATETIME NULL');
        $db->exec("CREATE TABLE IF NOT EXISTS site_directory (
            site_id INT UNSIGNED NOT NULL PRIMARY KEY,
            client_id INT UNSIGNED NOT NULL,
            domain VARCHAR(253) NOT NULL,
            dc_ip VARCHAR(45) NOT NULL,
            username VARCHAR(256) NOT NULL DEFAULT '',
            cert_seen VARCHAR(64) NOT NULL DEFAULT '',
            cert_seen_subject VARCHAR(255) NOT NULL DEFAULT '',
            cert_seen_at DATETIME NULL,
            cert_trusted VARCHAR(64) NOT NULL DEFAULT '',
            cert_trusted_by INT UNSIGNED NULL,
            cred_state ENUM('none','waiting','held','failed') NOT NULL DEFAULT 'none',
            cred_agent_id INT UNSIGNED NULL,
            cred_set_at DATETIME NULL,
            cred_confirmed_at DATETIME NULL,
            cred_error VARCHAR(255) NOT NULL DEFAULT '',
            results MEDIUMTEXT NULL,
            checked_at DATETIME NULL,
            last_error VARCHAR(500) NOT NULL DEFAULT '',
            last_attempt_at DATETIME NULL,
            updated_at DATETIME NOT NULL,
            KEY idx_sdir_client (client_id),
            CONSTRAINT fk_sdir_site FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE
        ) {$opts}");
        $db->exec("CREATE TABLE IF NOT EXISTS agent_secret_drops (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            agent_id INT UNSIGNED NOT NULL,
            site_id INT UNSIGNED NOT NULL,
            nonce CHAR(32) NOT NULL,
            username VARCHAR(256) NOT NULL,
            sealed TEXT NOT NULL,
            created_by INT UNSIGNED NULL,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            KEY idx_drops_agent (agent_id),
            CONSTRAINT fk_drops_agent FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
        ) {$opts}");
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'findings' AND COLUMN_NAME = 'finding_type'")->fetchColumn();
        if ($type !== '' && !str_contains($type, "'directory'")) {
            $values = array_map(static fn (string $v): string => trim($v, "'"), explode(',', substr($type, 5, -1)));
            $values[] = 'directory';
            $db->exec('ALTER TABLE findings MODIFY finding_type ENUM(' . implode(',', array_map(static fn (string $v): string => $db->quote($v), $values)) . ') NOT NULL');
        }
    },
];
