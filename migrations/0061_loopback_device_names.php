<?php

declare(strict_types=1);

/**
 * Migration 0061 (1.57.2): agent devices that reported a loopback name ("localhost", "localhost.localdomain",
 * "ip6-localhost", ...) are named by their address instead, and lose that DNS name, so they and their findings show
 * the address rather than "localhost". The agent no longer stores such names (AgentService::hostname).
 *
 * Idempotent: only devices still carrying a loopback name are changed. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent devices named localhost get their address as name',
    'up' => static function (PDO $db, Migrator $m): void {
        $loop = "'^(localhost|ip6-localhost|ip6-loopback)([.]|$)'";
        $db->exec("UPDATE devices SET name = SUBSTRING_INDEX(ip_addresses, ',', 1)
                   WHERE source = 'agent' AND ip_addresses <> '' AND name REGEXP {$loop}");
        $db->exec("UPDATE devices SET dns_name = '' WHERE source = 'agent' AND dns_name REGEXP {$loop}");
    },
];
