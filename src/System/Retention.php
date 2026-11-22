<?php

declare(strict_types=1);

namespace Sentinel\System;

use PDO;
use Sentinel\Core\Audit;
use Sentinel\Core\Settings;

/**
 * Deletes old data an admin chose not to keep (Settings, months; 0 = keep forever):
 * - scan history: finished scan jobs and their scan log;
 * - resolved findings (still resolved after the period) and their history;
 * - reports.
 * The audit log is never deleted. Runs once a day from the worker.
 *
 * Security assumptions: months are validated integers from settings; every
 * delete is bounded (batches) and recorded in the audit log with counts.
 */
final class Retention
{
    private const BATCH = 1000;

    /** Uses the database, settings and the audit log. */
    public function __construct(private readonly PDO $db, private readonly Settings $settings, private readonly Audit $audit)
    {
    }

    /**
     * Run if due (or $force). Returns counts of deleted rows, or null if not due.
     *
     * @return array{scans:int, findings:int, reports:int}|null
     */
    public function run(bool $force = false): ?array
    {
        $last = $this->settings->get('retention_last_run');
        if (!$force && $last !== '' && strtotime($last . ' UTC') > time() - 20 * 3600) {
            return null;
        }
        $this->settings->set('retention_last_run', gmdate('Y-m-d H:i:s'));
        $counts = ['scans' => 0, 'findings' => 0, 'reports' => 0];
        if (($m = $this->months('retention_scans_months')) > 0) {
            $counts['scans'] = $this->batches(
                "SELECT id FROM scan_jobs WHERE status IN ('done','partial','failed','cancelled') AND finished_at < UTC_TIMESTAMP() - INTERVAL {$m} MONTH LIMIT " . self::BATCH,
                ['DELETE FROM scan_log WHERE job_id IN (%s)', 'DELETE FROM scan_jobs WHERE id IN (%s)']
            );
        }
        if (($m = $this->months('retention_findings_months')) > 0) {
            $counts['findings'] = $this->batches(
                "SELECT id FROM findings WHERE status = 'resolved' AND resolved_at < UTC_TIMESTAMP() - INTERVAL {$m} MONTH LIMIT " . self::BATCH,
                ['DELETE FROM finding_events WHERE finding_id IN (%s)', 'DELETE FROM findings WHERE id IN (%s)']
            );
        }
        if (($m = $this->months('retention_reports_months')) > 0) {
            $counts['reports'] = $this->batches(
                "SELECT id FROM reports WHERE generated_at < UTC_TIMESTAMP() - INTERVAL {$m} MONTH LIMIT " . self::BATCH,
                ['DELETE FROM reports WHERE id IN (%s)']
            );
        }
        if (array_sum($counts) > 0) {
            $this->audit->log('retention.deleted', null, 'system', null, null, $counts);
        }
        return $counts;
    }

    /** A retention setting as months (0-120). */
    private function months(string $name): int
    {
        $v = $this->settings->get($name);
        return ctype_digit($v) ? min(120, (int) $v) : 0;
    }

    /**
     * Repeatedly select IDs and run the deletes for them. Returns how many IDs were removed.
     *
     * @param list<string> $deletes Statements with %s for the ID list (integers only).
     */
    private function batches(string $select, array $deletes): int
    {
        $total = 0;
        for ($i = 0; $i < 100; $i++) {
            $ids = array_map('intval', $this->db->query($select)->fetchAll(PDO::FETCH_COLUMN));
            if ($ids === []) {
                break;
            }
            $list = implode(',', $ids);
            $this->db->beginTransaction();
            try {
                foreach ($deletes as $sql) {
                    $this->db->exec(sprintf($sql, $list));
                }
                $this->db->commit();
            } catch (\Throwable $ex) {
                $this->db->rollBack();
                throw $ex;
            }
            $total += count($ids);
        }
        return $total;
    }
}
