<?php

declare(strict_types=1);

/**
 * Migration 0023: two-way ticket status (phase 3 of docs/ROADMAP-itflow.md).
 * - itflow_tickets.state: where Sentinel is with the ticket (open; resolved by Sentinel; closed in ITFlow and waiting
 *   for Sentinel's check; done; replaced by a new ticket; unconfirmed; gone from ITFlow), the ticket's last known
 *   status in ITFlow, when that was checked, when Sentinel saw it closed, and the finding a replaced ticket was for.
 * - Pending and failed tickets (the 1.18.0 review): a row is written before the ticket is opened ('pending'), so a
 *   create call that timed out is looked up in ITFlow (by its marker) instead of opened twice; a ticket ITFlow refused
 *   is 'failed' and retried later (attempts, retry_at, last_error), without holding up the others.
 * - itflow_tickets.url is emptied: ITFlow's ticket_url is the client's guest link with the ticket's secret key in it.
 *   Sentinel now links to the agent view, built from the ticket number.
 * - Setting itflow_tickets_weekly_since: weekly Warnings tickets keep their own start, so "open tickets for existing
 *   Fails" no longer sends a weekly ticket to every client at once.
 * - findings.verify_result / verify_result_at: the outcome of the last "verify fix" recheck (VerifyOutcome::RESULTS),
 *   so a closed ticket can be reopened only on a conclusive "still present".
 *
 * Idempotent: addColumnIfMissing, a blanket UPDATE and INSERT IGNORE. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'ITFlow two-way ticket status; verify results',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('itflow_tickets', 'state', "ENUM('pending','failed','open','sentinel_resolved','awaiting_check','done','replaced','unconfirmed','gone') NOT NULL DEFAULT 'open'");
        $m->addColumnIfMissing('itflow_tickets', 'itflow_status', "VARCHAR(10) NOT NULL DEFAULT 'open'");
        $m->addColumnIfMissing('itflow_tickets', 'status_checked_at', 'DATETIME NULL');
        $m->addColumnIfMissing('itflow_tickets', 'closed_seen_at', 'DATETIME NULL');
        $m->addColumnIfMissing('itflow_tickets', 'history_finding_id', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('itflow_tickets', 'marker', "VARCHAR(40) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('itflow_tickets', 'attempts', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
        $m->addColumnIfMissing('itflow_tickets', 'retry_at', 'DATETIME NULL');
        $m->addColumnIfMissing('itflow_tickets', 'last_error', "VARCHAR(255) NOT NULL DEFAULT ''");
        $db->exec("UPDATE itflow_tickets SET url = '' WHERE url <> ''");
        // Weekly tickets start from when tickets were turned on, not from the "existing Fails" date (2000-01-01).
        $db->exec("INSERT IGNORE INTO settings (name, value)
                   SELECT 'itflow_tickets_weekly_since', IF(value < '2001', DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'), value)
                   FROM settings WHERE name = 'itflow_tickets_since'");
        $m->addColumnIfMissing('findings', 'verify_result', 'VARCHAR(20) NULL');
        $m->addColumnIfMissing('findings', 'verify_result_at', 'DATETIME NULL');
    },
];
