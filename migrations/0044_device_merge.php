<?php

declare(strict_types=1);

/**
 * Migration 0044 (1.38): one device for a machine seen by both the agent and an inventory source (NinjaOne).
 *
 * - devices.merged_into: the inventory device an agent device is the same machine as (NULL: shown on its own).
 * - devices.merge_state: 'auto' (matched by the rules), 'manual' (an admin merged it) or 'split' (an admin said it is
 *   a different machine: the rules leave it alone). NULL: never matched.
 * Nothing is deleted: both rows keep their own data; lists show one row and the device page combines them.
 *
 * Idempotent: columns and index are added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Merged devices (agent and inventory)',
    'up' => static function (PDO $db, Migrator $m): void {
        $has = static fn (string $col): bool => (int) $db->query("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'devices' AND COLUMN_NAME = " . $db->quote($col))->fetchColumn() > 0;
        if (!$has('merged_into')) {
            $db->exec('ALTER TABLE devices ADD COLUMN merged_into INT UNSIGNED NULL');
        }
        if (!$has('merge_state')) {
            $db->exec("ALTER TABLE devices ADD COLUMN merge_state ENUM('auto', 'manual', 'split') NULL");
        }
        if ((int) $db->query("SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'devices' AND INDEX_NAME = 'idx_devices_merged'")->fetchColumn() === 0) {
            $db->exec('ALTER TABLE devices ADD KEY idx_devices_merged (merged_into)');
        }
    },
];
