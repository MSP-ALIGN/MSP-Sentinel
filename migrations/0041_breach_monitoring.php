<?php

declare(strict_types=1);

/**
 * Migration 0041 (1.33): breach monitoring (addresses of a client's verified domains found in known data breaches).
 *
 * - breach_exposures: per client and address, the breaches it was found in (name, date, what was exposed; never a
 *   password or hash), when Sentinel first and last saw it. The address is personal data: it is shown only to signed-in
 *   users, never logged, and removed when the provider no longer lists it or the domain leaves the client's scope.
 * - findings.finding_type gains 'breach'.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS, and the ENUM is only changed when 'breach' is missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Breach monitoring',
    'up' => static function (PDO $db, Migrator $m): void {
        $db->exec("CREATE TABLE IF NOT EXISTS breach_exposures (
            client_id INT UNSIGNED NOT NULL,
            email VARCHAR(254) NOT NULL,
            domain VARCHAR(253) NOT NULL,
            breaches MEDIUMTEXT NOT NULL,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            PRIMARY KEY (client_id, email),
            KEY idx_breach_domain (client_id, domain),
            CONSTRAINT fk_breach_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'findings' AND COLUMN_NAME = 'finding_type'")->fetchColumn();
        if ($type !== '' && !str_contains($type, "'breach'")) {
            $values = array_map(static fn (string $v): string => trim($v, "'"), explode(',', substr($type, 5, -1)));
            $values[] = 'breach';
            $db->exec('ALTER TABLE findings MODIFY finding_type ENUM(' . implode(',', array_map(static fn (string $v): string => $db->quote($v), $values)) . ') NOT NULL');
        }
    },
];
