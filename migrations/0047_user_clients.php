<?php

declare(strict_types=1);

/**
 * Migration 0047 (1.41): which clients each user sees.
 *
 * - users.all_clients: 1 = every client (the default, so nobody loses access on upgrade), 0 = only those listed in
 *   user_clients.
 * - user_clients: the clients of a user limited to a list. Rows go with the user or the client (ON DELETE CASCADE).
 *
 * Idempotent: the column and table are created only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Per-user client lists',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('users', 'all_clients', 'TINYINT(1) NOT NULL DEFAULT 1 AFTER role_id');
        $db->exec("CREATE TABLE IF NOT EXISTS user_clients (
            user_id INT UNSIGNED NOT NULL,
            client_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (user_id, client_id),
            KEY idx_user_clients_client (client_id),
            CONSTRAINT fk_user_clients_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            CONSTRAINT fk_user_clients_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    },
];
