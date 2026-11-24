<?php

declare(strict_types=1);

/**
 * Migration 0033: the agent release key managed on the System page (1.24).
 * - agents.release_key_fp: the fingerprint of the release key the agent says it has pinned ('' when none);
 * - agents.key_offered_at: when Sentinel last offered it the current key (at most hourly).
 * The key itself is a setting (release_public_key: the public half only).
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent release keys from the System page',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('agents', 'release_key_fp', "VARCHAR(40) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('agents', 'key_offered_at', 'DATETIME NULL');
    },
];
