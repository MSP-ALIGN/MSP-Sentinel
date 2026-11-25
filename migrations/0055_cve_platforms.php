<?php

declare(strict_types=1);

/**
 * Migration 0055 (1.49): platform limits of CVE matches. cpe_query_cves.platforms lists the operating systems a
 * product is only vulnerable on (e.g. "android,ios"; '' = any), so an Android-only Chrome CVE is not reported on
 * Windows PCs. cpe_queries.platforms_checked = 0 marks answers cached before this, which the feeds job fetches again
 * (meanwhile they are used as before).
 *
 * Idempotent: columns are added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Platform limits of CVE matches',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('cpe_query_cves', 'platforms', "VARCHAR(200) NOT NULL DEFAULT ''");
        $m->addColumnIfMissing('cpe_queries', 'platforms_checked', 'TINYINT(1) NOT NULL DEFAULT 0');
    },
];
