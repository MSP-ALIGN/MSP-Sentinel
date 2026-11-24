<?php

declare(strict_types=1);

/**
 * Migration 0014: the fix workflow. Findings get an assignee, a due date
 * (from the severity policy, or set by an admin), the time they last became
 * open, a due-soon reminder marker and the latest "verify fix" request.
 * Scan jobs get the 'verify' type (a recheck of one finding).
 *
 * Idempotent: addColumnIfMissing, indexes and foreign keys only when missing,
 * enum widened only when 'verify' is missing, and the backfill only touches
 * rows without values. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Fix workflow: assignment, due dates, verify fix',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('findings', 'assigned_to', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('findings', 'assigned_by', 'INT UNSIGNED NULL');
        $m->addColumnIfMissing('findings', 'assigned_at', 'DATETIME NULL');
        $m->addColumnIfMissing('findings', 'opened_at', 'DATETIME NULL');
        $m->addColumnIfMissing('findings', 'due_at', 'DATETIME NULL');
        $m->addColumnIfMissing('findings', 'due_custom', 'TINYINT(1) NOT NULL DEFAULT 0');
        $m->addColumnIfMissing('findings', 'verify_requested_at', 'DATETIME NULL');
        $m->addColumnIfMissing('findings', 'verify_job_id', 'INT UNSIGNED NULL');
        if (!$m->indexExists('findings', 'idx_findings_assignee')) {
            $db->exec('ALTER TABLE findings ADD KEY idx_findings_assignee (assigned_to, status)');
        }
        if (!$m->indexExists('findings', 'idx_findings_due')) {
            $db->exec('ALTER TABLE findings ADD KEY idx_findings_due (status, due_at)');
        }
        $fk = (int) $db->query("SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'findings' AND CONSTRAINT_NAME = 'fk_findings_assignee'")->fetchColumn();
        if ($fk === 0) {
            $db->exec('ALTER TABLE findings ADD CONSTRAINT fk_findings_assignee FOREIGN KEY (assigned_to) REFERENCES users (id) ON DELETE SET NULL');
        }
        // Existing findings: open since they were first seen (or last reopened; first_seen is the best known value).
        $db->exec('UPDATE findings SET opened_at = first_seen WHERE opened_at IS NULL');
        // Due dates right away (default policy: known-exploited 7, Fail 14, Warning 30 days), so the overdue
        // views are correct straight after the upgrade. Only rows without one; later refreshes keep them current.
        $db->exec("UPDATE findings f LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
                   SET f.due_at = TIMESTAMP(DATE(f.opened_at) + INTERVAL (CASE WHEN k.cve_id IS NOT NULL THEN 7 WHEN f.severity = 'fail' THEN 14 ELSE 30 END) DAY, '23:59:59')
                   WHERE f.due_at IS NULL AND f.due_custom = 0");

        $type = (string) $db->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scan_jobs' AND COLUMN_NAME = 'job_type'")->fetchColumn();
        if (!str_contains($type, "'verify'")) {
            $db->exec("ALTER TABLE scan_jobs MODIFY job_type ENUM('ports','tls','verify') NOT NULL DEFAULT 'ports'");
        }
    },
];
