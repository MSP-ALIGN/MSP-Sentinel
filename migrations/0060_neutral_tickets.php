<?php

declare(strict_types=1);

/**
 * Migration 0060 (1.55): tickets and their settings no longer assume ITFlow.
 * - itflow_tickets.provider: the ticketing system a ticket belongs to ('itflow' for every existing row).
 * - itflow_tickets.external_ticket_id: the ticket's ID in that system as exact text (utf8mb4_bin), so systems with text
 *   IDs fit; filled from itflow_ticket_id, which stays and is kept in step.
 * - The ticket settings get neutral names (tickets_enabled, tickets_since, tickets_weekly_since, tickets_last_run,
 *   tickets_last_result, tickets_last_ok), copied from the itflow_tickets_* ones, which are left as they were.
 *
 * Idempotent: columns are added only when missing, the copy only fills empty IDs, and settings are copied with INSERT
 * IGNORE (a value already under the new name is kept). Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Tickets and ticket settings for any ticketing system',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('itflow_tickets', 'provider', "VARCHAR(20) NOT NULL DEFAULT 'itflow'");
        $m->addColumnIfMissing('itflow_tickets', 'external_ticket_id', "VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT ''");
        $db->exec("UPDATE itflow_tickets SET external_ticket_id = CAST(itflow_ticket_id AS CHAR) WHERE itflow_ticket_id > 0 AND external_ticket_id = ''");
        foreach (['enabled', 'since', 'weekly_since', 'last_run', 'last_result', 'last_ok'] as $key) {
            $db->prepare('INSERT IGNORE INTO settings (name, value) SELECT :new, value FROM settings WHERE name = :old')
                ->execute(['new' => 'tickets_' . $key, 'old' => 'itflow_tickets_' . $key]);
        }
    },
];
