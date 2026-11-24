<?php

declare(strict_types=1);

/**
 * Migration 0049 (1.43): "Sign in with Microsoft".
 *
 * - users.sso_subject: the Microsoft account a user is linked to ("tenant ID:object ID"), set on the first SSO
 *   sign-in; unique, so one Microsoft account is one Sentinel user.
 * - users.password_login: 1 = the password (with Sentinel's two-factor) still works (the default, kept as a fallback),
 *   0 = an admin turned it off for this user: SSO only.
 *
 * Idempotent: columns and key are added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Sign in with Microsoft',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('users', 'sso_subject', 'VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER all_clients');
        $m->addColumnIfMissing('users', 'password_login', 'TINYINT(1) NOT NULL DEFAULT 1 AFTER sso_subject');
        if (!$m->indexExists('users', 'uq_users_sso')) {
            $db->exec('ALTER TABLE users ADD UNIQUE KEY uq_users_sso (sso_subject)');
        }
    },
];
