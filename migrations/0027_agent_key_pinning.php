<?php

declare(strict_types=1);

/**
 * Migration 0027: the agent's public key is pinned (1.20.0 review). The first key an agent reports is kept; a different
 * one later waits in box_key_pending until an admin compares its fingerprint (shown on the Agents page and by the
 * agent's status command) and approves it. Until then browsers keep sealing to the pinned key, so someone with an
 * agent's token or write access to the database can't quietly have the next password sealed to a key of theirs.
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent public key pinning (a changed key needs an admin approval)',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('agents', 'box_key_pending', "VARCHAR(255) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('agents', 'box_key_pending_at', 'DATETIME NULL');
    },
];
