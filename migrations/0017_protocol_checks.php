<?php

declare(strict_types=1);

/**
 * Migration 0017: results of the agent's risky-protocol checks: per open port
 * (SMBv1 and SMB signing, RDP Network Level Authentication) and per device
 * (SNMP default communities).
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice. Values are small
 * JSON objects of true/false/null written by the server from validated data.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Risky protocol check results (agent)',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('device_ports', 'checks', 'VARCHAR(500) NULL');
        $m->addColumnIfMissing('devices', 'checks', 'VARCHAR(500) NULL');
    },
];
