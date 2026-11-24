<?php

declare(strict_types=1);

/**
 * Migration 0011: each user's interface theme (dark by default, or light).
 *
 * Idempotent: addColumnIfMissing. Safe to run twice.
 *
 * Security notes: a fixed list of values (ENUM); only the signed-in user changes their own.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'User interface theme preference',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('users', 'ui_theme', "ENUM('dark','light') NOT NULL DEFAULT 'dark'");
    },
];
