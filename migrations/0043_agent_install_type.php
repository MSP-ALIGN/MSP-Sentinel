<?php

declare(strict_types=1);

/**
 * Migration 0043 (1.36): how each agent is installed, as it reports at check-in.
 *
 * - agents.install_type: '' (a machine or VM, updated from Sentinel), 'docker' (the official image: updated by pulling a
 *   new image, never handed an in-place update), 'lxc' (an LXC container such as on Proxmox: a normal install).
 *
 * Untrusted: nothing (the value is validated by AgentKernel before it is stored).
 * Idempotent: the column is added only when it is missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent install type (Docker, LXC)',
    'up' => static function (PDO $db, Migrator $m): void {
        $exists = (int) $db->query("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'agents' AND COLUMN_NAME = 'install_type'")->fetchColumn();
        if ($exists === 0) {
            $db->exec("ALTER TABLE agents ADD COLUMN install_type ENUM('', 'docker', 'lxc') NOT NULL DEFAULT ''");
        }
    },
];
