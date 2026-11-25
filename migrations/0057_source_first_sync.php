<?php

declare(strict_types=1);

/**
 * Migration 0057 (1.49): source_links.first_synced_at, when a client's link to an inventory source first synced.
 * Findings from the first day after it (the first import, including software CVEs whose data arrives a few hours
 * later) get one summary instead of an alert each, and no tickets. Links that synced before this keep their history:
 * their first sync counts as their last one before the upgrade.
 *
 * Idempotent: the column is added only when missing; the backfill only fills empty values.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'First sync of an inventory link',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('source_links', 'first_synced_at', 'DATETIME NULL DEFAULT NULL');
        $db->exec('UPDATE source_links SET first_synced_at = last_sync_at - INTERVAL 2 DAY WHERE first_synced_at IS NULL AND last_sync_at IS NOT NULL');
    },
];
