<?php

declare(strict_types=1);

/**
 * Migration 0038 (1.27): pen-test reports and retest letters.
 * - reports.kind gains 'pentest' (an engagement's report) and 'retest' (the retest letter); reports.engagement_id
 *   names the engagement (NULL for the other reports). Both are frozen snapshots like every report.
 * - engagements.retest_of: the earlier engagement this one retests (its own signed authorisation and window); its
 *   letter compares that engagement's report with this one's evidence.
 *
 * Idempotent: the enum is widened only when 'pentest' is missing; addColumnIfMissing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Pen-test reports and retests',
    'up' => static function (PDO $db, Migrator $m): void {
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'reports' AND COLUMN_NAME = 'kind'")->fetchColumn();
        if (!str_contains($type, "'pentest'")) {
            $db->exec("ALTER TABLE reports MODIFY kind ENUM('executive','technical','pentest','retest') NOT NULL");
        }
        $m->addColumnIfMissing('reports', 'engagement_id', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('engagements', 'retest_of', 'INT UNSIGNED NULL');
    },
];
