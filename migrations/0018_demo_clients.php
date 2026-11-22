<?php

declare(strict_types=1);

/**
 * Migration 0018: marks demo clients (made-up data loaded with bin/demo.php or the System page). Demo clients
 * are never scanned: no port scans, certificate checks, verify-fix rechecks, discovery or agent jobs.
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Demo clients (never scanned)',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('clients', 'is_demo', 'TINYINT(1) NOT NULL DEFAULT 0');
    },
];
