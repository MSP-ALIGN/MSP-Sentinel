<?php

declare(strict_types=1);

/**
 * Migration 0034 (1.24.1): the agent release key is one secret setting (release_key, authenticated with the app key),
 * so a database write alone can't plant a key agents would trust. Removes the plain settings 1.24.0 used
 * (release_public_key, release_key_created_at, release_previous_key, release_key_rotation): they are never read again.
 * A key made with 1.24.0 must be made again on Administration, System (1.24.0 was never released).
 *
 * Idempotent: deleting rows that are already gone changes nothing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent release key as an authenticated secret',
    'up' => static function (PDO $db, Migrator $m): void {
        $db->exec("DELETE FROM settings WHERE name IN ('release_public_key', 'release_key_created_at', 'release_previous_key', 'release_key_rotation')");
    },
];
