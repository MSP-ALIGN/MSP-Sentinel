<?php

declare(strict_types=1);

/**
 * Migration 0040 (1.32): one ITFlow ticket per issue per client.
 *
 * - itflow_tickets.kind gains 'member': a finding that rides on another finding's ticket (the same issue on another
 *   target of the same client). Its row keeps the finding's own state; parent_id points at the ticket's leading row,
 *   and itflow_ticket_id / reference are copied from it. The unique (kind, finding_id) key still gives a finding at
 *   most one row of each kind, and Sentinel never gives a finding both.
 * - itflow_tickets.parent_id: the leading row of a member (NULL for every other row), indexed.
 * - itflow_tickets.target_noted: 1 once the ticket got a note that this row's target is fixed or decided (while other
 *   targets are still open); back to 0 when it is seen again.
 *
 * Idempotent: the ENUM is only changed when 'member' is missing; columns and the index only when missing. Safe to run
 * twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'ITFlow: one ticket per issue (member rows)',
    'up' => static function (PDO $db, Migrator $m): void {
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'itflow_tickets' AND COLUMN_NAME = 'kind'")->fetchColumn();
        if ($type !== '' && !str_contains($type, "'member'")) {
            $values = array_map(static fn (string $v): string => trim($v, "'"), explode(',', substr($type, 5, -1)));
            $values[] = 'member';
            $db->exec('ALTER TABLE itflow_tickets MODIFY kind ENUM(' . implode(',', array_map(static fn (string $v): string => $db->quote($v), $values)) . ') NOT NULL');
        }
        $m->addColumnIfMissing('itflow_tickets', 'parent_id', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('itflow_tickets', 'target_noted', 'TINYINT(1) NOT NULL DEFAULT 0');
        if (!$m->indexExists('itflow_tickets', 'idx_itflow_ticket_parent')) {
            $db->exec('ALTER TABLE itflow_tickets ADD KEY idx_itflow_ticket_parent (parent_id)');
        }
    },
];
