<?php

declare(strict_types=1);

/**
 * Migration 0037 (1.27): internal engagement tests through agents.
 * - agent_jobs.kind gains 'engagement'; agent_jobs.engagement_id names the engagement (NULL for other jobs). The job is
 *   signed with the engagement's targets, exclusions, tests and end time; the agent checks them all.
 *
 * Idempotent: the enum is widened only when 'engagement' is missing; addColumnIfMissing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Engagement jobs for agents',
    'up' => static function (PDO $db, Migrator $m): void {
        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'agent_jobs' AND COLUMN_NAME = 'kind'")->fetchColumn();
        if (!str_contains($type, "'engagement'")) {
            $db->exec("ALTER TABLE agent_jobs MODIFY kind ENUM('full','light','engagement') NOT NULL");
        }
        $m->addColumnIfMissing('agent_jobs', 'engagement_id', 'INT UNSIGNED NULL');
    },
];
