<?php

declare(strict_types=1);

/**
 * Migration 0030: agent update attempts (1.22.0 review). An update request is handed out at most
 * AgentKernel::UPDATE_HANDOUTS times, AgentKernel::UPDATE_RETRY_MINUTES apart, with scans going on in between; after
 * that it ends with "no result from the update helper", so a stuck helper can never stop an agent's scans.
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent update attempts',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('agents', 'update_handed_at', 'DATETIME NULL');
        $m->addColumnIfMissing('agents', 'update_handouts', 'SMALLINT UNSIGNED NOT NULL DEFAULT 0');
    },
];
