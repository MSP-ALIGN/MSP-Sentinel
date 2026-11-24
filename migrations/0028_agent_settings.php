<?php

declare(strict_types=1);

/**
 * Migration 0028: agent settings managed from the web UI.
 * - sites.agent_timing: the nmap timing profile of the site's agent scans (NmapRunner::PROFILES; signed in each job).
 * - sites.agent_poll_seconds: how often the site's agents check in (30-600 seconds).
 * - agents.restart_requested / diagnostics_requested: one-off requests an admin made, handed out at the next check-in.
 * - agents.diagnostics / diagnostics_at: the last diagnostics report (validated, short; no secrets).
 *
 * Idempotent: addColumnIfMissing only. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Agent settings, restart and diagnostics from the web UI',
    'up' => static function (PDO $db, Migrator $m): void {
        $m->addColumnIfMissing('sites', 'agent_timing', "VARCHAR(20) NOT NULL DEFAULT 'gentle'");
        $m->addColumnIfMissing('sites', 'agent_poll_seconds', 'SMALLINT UNSIGNED NOT NULL DEFAULT 60');
        $m->addColumnIfMissing('agents', 'restart_requested', 'TINYINT(1) NOT NULL DEFAULT 0');
        $m->addColumnIfMissing('agents', 'diagnostics_requested', 'TINYINT(1) NOT NULL DEFAULT 0');
        $m->addColumnIfMissing('agents', 'diagnostics', 'TEXT NULL');
        $m->addColumnIfMissing('agents', 'diagnostics_at', 'DATETIME NULL');
    },
];
