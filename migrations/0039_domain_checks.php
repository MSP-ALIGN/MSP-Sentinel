<?php

declare(strict_types=1);

/**
 * Migration 0039 (1.28): DNS checks of authorised names.
 * - domain_checks: per client and name, the latest zone-transfer ('zone') or subdomain-takeover ('takeover') result
 *   (JSON; values came from DNS servers and web pages: untrusted, shown escaped).
 * - findings.finding_type gains 'dns'.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS; the enum is widened only when 'dns' is missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'DNS checks: zone transfers and subdomain takeover',
    'up' => static function (PDO $db, Migrator $m): void {
        $db->exec("CREATE TABLE IF NOT EXISTS domain_checks (
            client_id INT UNSIGNED NOT NULL,
            name VARCHAR(253) NOT NULL,
            kind ENUM('zone','takeover') NOT NULL,
            result MEDIUMTEXT NOT NULL,
            checked_at DATETIME NOT NULL,
            PRIMARY KEY (client_id, kind, name),
            CONSTRAINT fk_domchk_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'findings' AND COLUMN_NAME = 'finding_type'")->fetchColumn();
        if ($type !== '' && !str_contains($type, "'dns'")) {
            $values = array_map(static fn (string $v): string => trim($v, "'"), explode(',', substr($type, 5, -1)));
            $values[] = 'dns';
            $db->exec('ALTER TABLE findings MODIFY finding_type ENUM(' . implode(',', array_map(static fn (string $v): string => $db->quote($v), $values)) . ') NOT NULL');
        }
    },
];
