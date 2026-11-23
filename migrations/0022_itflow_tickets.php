<?php

declare(strict_types=1);

/**
 * Migration 0022: ITFlow tickets opened by Sentinel (phase 2 of docs/ROADMAP-itflow.md). One row per ticket: either
 * for one finding (kind "finding": a Fail or a known-exploited problem) or the weekly Warnings ticket of a client
 * (kind "weekly"). The unique (kind, finding_id) key is what keeps a finding from ever getting two tickets.
 * Phase 3 adds the ticket's status from ITFlow to these rows.
 *
 * Idempotent: CREATE TABLE IF NOT EXISTS only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'ITFlow tickets opened by Sentinel',
    'up' => static function (PDO $db, Migrator $m): void {
        $db->exec(
            "CREATE TABLE IF NOT EXISTS itflow_tickets (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                client_id INT UNSIGNED NOT NULL,
                kind ENUM('finding','weekly') NOT NULL,
                finding_id INT UNSIGNED NULL,
                itflow_ticket_id INT UNSIGNED NOT NULL,
                reference VARCHAR(40) NOT NULL DEFAULT '',
                url VARCHAR(500) NOT NULL DEFAULT '',
                severity_at_open ENUM('fail','warn') NULL,
                kev_noted TINYINT(1) NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL,
                last_note_at DATETIME NULL,
                UNIQUE KEY uq_itflow_ticket_finding (kind, finding_id),
                KEY idx_itflow_ticket_client (client_id, kind, created_at),
                CONSTRAINT fk_itflow_ticket_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
                CONSTRAINT fk_itflow_ticket_finding FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    },
];
