<?php

declare(strict_types=1);

namespace Sentinel\Reports;

use PDO;

/**
 * Records today's open Fail/Warning counts per client (finding_stats), so
 * reports can show a trend. Called by the worker and the feeds job; one row
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

    /** Upsert today's counts for every client that is not archived. */
    public function recordToday(): void
    {
        $this->db->exec(
            "INSERT INTO finding_stats (client_id, day, fail_open, warn_open)
             SELECT c.id, UTC_DATE(),
                    COALESCE(SUM(f.status = 'open' AND f.severity = 'fail'), 0), COALESCE(SUM(f.status = 'open' AND f.severity = 'warn'), 0)
             FROM clients c LEFT JOIN findings f ON f.client_id = c.id
             WHERE c.is_archived = 0 GROUP BY c.id
             ON DUPLICATE KEY UPDATE fail_open = VALUES(fail_open), warn_open = VALUES(warn_open)"
        );
    }
}
