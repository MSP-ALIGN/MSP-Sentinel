<?php

declare(strict_types=1);

/**
 * Migration 0024: fixes from the 1.19.0 review of two-way ITFlow tickets.
 * - itflow_tickets.gone_seen_at: a ticket is only given up as gone after two "not there" answers an hour apart (ITFlow
 *   answers "No resource" for its own query errors too).
 * - itflow_tickets.fixed_noted_at: the "verified fixed" note was sent, so a retried resolve doesn't send it twice.
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'ITFlow two-way ticket fixes',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('itflow_tickets', 'gone_seen_at', 'DATETIME NULL');
        $m->addColumnIfMissing('itflow_tickets', 'fixed_noted_at', 'DATETIME NULL');
    },
];
