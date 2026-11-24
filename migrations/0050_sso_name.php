<?php

declare(strict_types=1);

/**
 * Migration 0050 (1.43.2): users.sso_name, the linked Microsoft account's name and address as Microsoft gave them at
 * linking, shown on My profile and the user's page so everyone can see which account is linked (display only; the
 * link itself is users.sso_subject).
 *
 * Idempotent: the column is added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Linked Microsoft account name',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('users', 'sso_name', "VARCHAR(300) NOT NULL DEFAULT '' AFTER sso_subject");
    },
];
