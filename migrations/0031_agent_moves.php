<?php

declare(strict_types=1);

/**
 * Migration 0031: moving agents to a new Sentinel address (1.23). The new address and its CA (if any) are settings
 * (not secrets: agent_move_url, agent_move_ca, agent_move_requested_at). Per agent:
 * - agents.server_url: the address the agent last said it uses;
 * - agents.move_result / move_result_at: what the agent reported about moving (ok, address, message).
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Moving agents to a new Sentinel address',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('agents', 'server_url', "VARCHAR(255) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('agents', 'move_result', 'TEXT NULL');
        $m->addColumnIfMissing('agents', 'move_result_at', 'DATETIME NULL');
    },
];
