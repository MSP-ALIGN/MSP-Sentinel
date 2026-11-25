<?php

declare(strict_types=1);

/**
 * Migration 0056 (1.49): findings.resolved_reason, why a finding was last resolved: '' = Sentinel's checks no longer
 * see the problem (a fix), 'gone' = its device is no longer reported by its source, 'unlinked' = the client was
 * unlinked from the source. Tickets say "verified fixed" and are resolved only for the first.
 *
 * Idempotent: the column is added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Why a finding was resolved',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('findings', 'resolved_reason', "VARCHAR(20) NOT NULL DEFAULT ''");
    },
];
