<?php

declare(strict_types=1);

/**
 * Migration 0029: agent updates from Sentinel (1.22).
 * - agents.update_to / update_requested_at / update_requested_by: an admin asked this agent to update to that version
 *   (handed out at its next idle check-in; cleared when it reports that version, or a refusal).
 * - agents.update_result / update_result_at: what the agent or its update helper last reported (version, ok, message).
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent updates from Sentinel',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('agents', 'update_to', "VARCHAR(20) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('agents', 'update_requested_at', 'DATETIME NULL');
        $m->addColumnIfMissing('agents', 'update_requested_by', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('agents', 'update_result', 'TEXT NULL');
        $m->addColumnIfMissing('agents', 'update_result_at', 'DATETIME NULL');
    },
];
