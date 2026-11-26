<?php

declare(strict_types=1);

/**
 * Migration 0062 (1.62): risk score history.
 * - finding_stats.score: the client's exact risk score that day (0-100, the dashboard's rule), or NULL for days
 *   recorded before 1.62. Those days are estimated when read (ScoreHistory), from their Fail/Warning counts.
 * - finding_stats.level: the level that day ('risk', 'attention', 'good'), or NULL like score.
 *
 * Idempotent: the columns are added only when missing. No data is changed. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Risk score history per client and day',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('finding_stats', 'score', 'TINYINT UNSIGNED NULL');
        $m->addColumnIfMissing('finding_stats', 'level', 'VARCHAR(10) NULL');
    },
];
