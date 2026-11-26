<?php

declare(strict_types=1);

namespace Sentinel\Reports;

use PDO;
use Sentinel\Core\Settings;
use Sentinel\Dashboard\DashboardData;

/**
 * Records today's open Fail/Warning counts per client (finding_stats), so
 * reports can show a trend, and (1.62) the client's exact risk score and level. Called by the worker and the feeds job; one row
 * per client per day, updated in place.
 *
 * Security assumptions: no input; counts come from the findings table.
 */
final class StatsRecorder
{
    /** Uses the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Upsert today's counts for every client that is not archived.
     *
     * @param bool $force Record even if counts were written in the last hour (the worker calls this every minute).
     */
    public function recordToday(bool $force = false): void
    {
        if (!$force && (int) $this->db->query('SELECT COUNT(*) FROM finding_stats WHERE day = UTC_DATE() AND recorded_at > UTC_TIMESTAMP() - INTERVAL 1 HOUR')->fetchColumn() > 0) {
            return;
        }
        $this->db->exec(
            "INSERT INTO finding_stats (client_id, day, fail_open, warn_open, recorded_at)
             SELECT c.id, UTC_DATE(),
                    COALESCE(SUM(f.status = 'open' AND f.severity = 'fail'), 0), COALESCE(SUM(f.status = 'open' AND f.severity = 'warn'), 0), UTC_TIMESTAMP()
             FROM clients c LEFT JOIN findings f ON f.client_id = c.id
             WHERE c.is_archived = 0 GROUP BY c.id
             ON DUPLICATE KEY UPDATE fail_open = VALUES(fail_open), warn_open = VALUES(warn_open), recorded_at = VALUES(recorded_at)"
        );
        // 1.62: today's exact risk score and level, by the dashboard's rule, for the score history.
        $set = $this->db->prepare('UPDATE finding_stats SET score = :s, level = :l WHERE client_id = :c AND day = UTC_DATE()');
        foreach ((new DashboardData($this->db, new Settings($this->db)))->clients() as $c) {
            $set->execute(['s' => $c['score'], 'l' => $c['level'], 'c' => $c['id']]);
        }
    }
}
