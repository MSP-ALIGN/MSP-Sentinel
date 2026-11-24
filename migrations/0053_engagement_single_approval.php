<?php

declare(strict_types=1);

/**
 * Migration 0053 (1.47): engagements.single_approval: 1 when the engagement was created while two-person approval was
 * turned off (Settings, Pen-test engagements). Only such an engagement may be approved by its creator, and only while
 * the setting is still off: turning the setting off never weakens an engagement created under the two-person rule.
 *
 * Idempotent: the column is added only when missing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Single-person approval flag on engagements',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('engagements', 'single_approval', 'TINYINT(1) NOT NULL DEFAULT 0');
    },
];
