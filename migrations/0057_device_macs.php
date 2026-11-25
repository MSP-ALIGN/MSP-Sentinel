<?php

declare(strict_types=1);

/**
 * Migration 0057 (1.50): devices.mac_addresses, the MAC addresses an inventory source reports for a device (comma-
 * separated, lower case). The agent's devices are matched to them first: a MAC is far better evidence of the same
 * machine than an address another site or an offline PC may share.
 *
 * Idempotent: the column is added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'MAC addresses of inventory devices',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('devices', 'mac_addresses', "VARCHAR(500) NOT NULL DEFAULT ''");
    },
];
