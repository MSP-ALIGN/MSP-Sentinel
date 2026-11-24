<?php

declare(strict_types=1);

/**
 * Migration 0046 (1.40): roles made of permissions.
 *
 * - roles: the built-in Viewer, Technician and Admin (role_key set; what they hold is defined in code,
 *   Sentinel\Auth\Permissions) and the custom roles admins create (role_key NULL).
 * - role_permissions: what each custom role holds (fixed permission names).
 * - users.role_id: each user's role. Existing users get the built-in role matching their old role, so nobody gains or
 *   loses anything on upgrade. users.role is kept: it mirrors the built-in key, and holds 'viewer' (the least) for a
 *   custom role, so any old code path that still read it could only ever under-grant.
 *
 * Idempotent: tables, column and key are created only when missing, built-in rows are inserted only when missing,
 * and only users without a role_id are filled in. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Roles and permissions',
    'up' => static function (PDO $db, Migrator $m): void {
        $opts = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
        $db->exec("CREATE TABLE IF NOT EXISTS roles (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            role_key VARCHAR(20) NULL,
            name VARCHAR(80) NOT NULL,
            description VARCHAR(300) NOT NULL DEFAULT '',
            created_by INT UNSIGNED NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            UNIQUE KEY uq_roles_key (role_key),
            UNIQUE KEY uq_roles_name (name)
        ) {$opts}");
        $db->exec("CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INT UNSIGNED NOT NULL,
            permission VARCHAR(60) NOT NULL,
            PRIMARY KEY (role_id, permission),
            CONSTRAINT fk_role_perm_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
        ) {$opts}");
        $insert = $db->prepare("INSERT IGNORE INTO roles (role_key, name, description, created_at, updated_at) VALUES (:k, :n, :d, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        foreach ([
            'viewer' => ['Viewer', 'Reads everything; changes nothing.'],
            'technician' => ['Technician', 'Day-to-day work: scans, triage, fixes, reports and pen-test engagements.'],
            'admin' => ['Admin', 'Everything, including users, settings, integrations and the system.'],
        ] as $key => [$name, $description]) {
            $insert->execute(['k' => $key, 'n' => $name, 'd' => $description]);
        }
        $m->addColumnIfMissing('users', 'role_id', 'INT UNSIGNED NULL AFTER role');
        $db->exec("UPDATE users u JOIN roles r ON r.role_key = u.role SET u.role_id = r.id WHERE u.role_id IS NULL");
        if ((int) $db->query("SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
                AND CONSTRAINT_NAME = 'fk_users_role'")->fetchColumn() === 0) {
            $db->exec('ALTER TABLE users ADD CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT');
        }
    },
];
