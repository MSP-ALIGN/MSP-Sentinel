<?php

declare(strict_types=1);

/**
 * Migration 0032: agent moves hardened (1.23.0 review).
 * - agents.move_request / move_handouts / move_handed_at: a move instruction goes to an agent at most a few times per
 *   move, some minutes apart (scans go on in between).
 * - The move itself is now ONE secret setting (agent_move, encrypted and authenticated with the app key): the old plain
 *   settings agent_move_url / agent_move_ca / agent_move_requested_at (1.23.0) are deleted, so an admin sets any move
 *   again (it needs their password now).
 *
 * Idempotent: addColumnIfMissing and a DELETE of rows that may be absent. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent moves hardened',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('agents', 'move_request', "VARCHAR(20) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('agents', 'move_handouts', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
        $m->addColumnIfMissing('agents', 'move_handed_at', 'DATETIME NULL');
        $db->exec("DELETE FROM settings WHERE name IN ('agent_move_url', 'agent_move_ca', 'agent_move_requested_at')");
    },
];
