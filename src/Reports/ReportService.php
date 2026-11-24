<?php

declare(strict_types=1);

namespace Sentinel\Reports;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use Sentinel\Alerts\AlertService;
use Sentinel\Api\EventPublisher;
use Sentinel\Alerts\SmtpMailer;

/**
 * Creates reports (snapshot, render, store) and runs the monthly schedule.
 *
 * Monthly schedule: for each client with monthly reports turned on and at
 * least one recipient, once the previous calendar month has ended, an
 * Executive summary and a Technical findings report for that month are
 * created (once: report_runs records each finished month, so deleting the
 * reports doesn't recreate them) and
 * emailed to the client's MSP-staff recipients with both attached, for
 * review before anything is forwarded to the client.
 *
 * Security assumptions: client rows come from the database; recipients were
 * validated when saved and are validated again before queueing.
 */
final class ReportService
{
    /** Wires the builder, renderer, store and (for the schedule) the alert queue. */
    public function __construct(
        private readonly PDO $db,
        private readonly ReportBuilder $builder,
        private readonly ReportRenderer $renderer,
        private readonly ReportRepository $reports,
        private readonly ?AlertService $alerts = null,
        private readonly ?EventPublisher $events = null,
    ) {
    }

    /** Largest report (HTML) we store; MEDIUMTEXT holds 16 MB and the snapshot is stored alongside. */
    private const MAX_HTML_BYTES = 12_000_000;
    /** Monthly runs that fail are retried at most hourly, and given up after this many attempts. */
    private const MAX_MONTHLY_ATTEMPTS = 5;

    /**
     * Build, render and store one report. Returns its ID.
     *
     * @param array<string,mixed> $client
     * @throws \RuntimeException with a message for the user if the report is too large.
     */
    public function generate(array $client, string $kind, string $start, string $end, ?int $userId, string $byName, string $source = 'manual'): int
    {
        [$snapshot, $html] = $this->prepare($client, $kind, $start, $end, $byName);
        return $this->store($client, $kind, $start, $end, $userId, $source, $snapshot, $html);
    }

    /**
     * Create and send last month's scheduled reports where they are due.
     *
     * Each client is handled on its own: a failure is recorded (report_runs),
     * reported to admins once, retried at most hourly, and never stops the
     * other clients. Both reports, the "done" record and the email are saved
     * in one transaction, so a month is either complete or not started.
     * Periods are calendar months in UTC. If the worker is down for a whole
     * month, only the latest finished month is created.
     *
     * @return int Number of clients whose reports were created.
     */
    public function runMonthly(?DateTimeImmutable $now = null): int
    {
        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $start = $now->modify('first day of last month')->format('Y-m-d');
        $end = $now->modify('last day of last month')->format('Y-m-d');
        $done = 0;
        // Only clients without a finished run for this month, and not tried in the last hour.
        $stmt = $this->db->prepare(
            "SELECT c.*, r.attempts AS run_attempts FROM clients c
             LEFT JOIN report_runs r ON r.client_id = c.id AND r.period_start = :p
             WHERE c.report_monthly = 1 AND c.is_archived = 0 AND c.is_demo = 0 AND c.report_recipients <> ''
               AND (r.client_id IS NULL OR (r.status = 'failed' AND r.attempts < :max AND r.last_attempt_at < UTC_TIMESTAMP() - INTERVAL 1 HOUR))
             ORDER BY c.id"
        );
        $stmt->execute(['p' => $start, 'max' => self::MAX_MONTHLY_ATTEMPTS]);
        foreach ($stmt->fetchAll() as $client) {
            $cid = (int) $client['id'];
            $lock = $this->db->quote('msp_sentinel_report_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16) . '_' . $cid);
            if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
                continue;
            }
            try {
                $check = $this->db->prepare("SELECT status FROM report_runs WHERE client_id = :c AND period_start = :p");
                $check->execute(['c' => $cid, 'p' => $start]);
                if ($check->fetchColumn() === 'done') {
                    continue; // another process finished it meanwhile
                }
                // Build both documents first (the slow part), then save everything at once.
                $prepared = [];
                foreach (ReportBuilder::KINDS as $kind) {
                    $prepared[$kind] = $this->prepare($client, $kind, $start, $end, __('Monthly schedule'));
                }
                $this->db->beginTransaction();
                try {
                    $ids = [];
                    foreach ($prepared as $kind => [$snapshot, $html]) {
                        $ids[] = $this->store($client, $kind, $start, $end, null, 'scheduled', $snapshot, $html);
                    }
                    $this->db->prepare("INSERT INTO report_runs (client_id, period_start, status, attempts, report_ids, last_error, last_attempt_at)
                                        VALUES (:c, :p, 'done', 1, :ids, '', UTC_TIMESTAMP())
                                        ON DUPLICATE KEY UPDATE status = 'done', attempts = attempts + 1, report_ids = VALUES(report_ids), last_error = '', last_attempt_at = UTC_TIMESTAMP()")
                        ->execute(['c' => $cid, 'p' => $start, 'ids' => implode(',', $ids)]);
                    $to = array_values(array_filter(array_map('trim', explode(',', (string) $client['report_recipients'])), [SmtpMailer::class, 'validAddress']));
                    $this->alerts?->queueEmail($to, '[' . $client['name'] . '] ' . __('Monthly security reports for {month}', ['month' => $now->modify('first day of last month')->format('F Y')]),
                        __("The monthly reports for {client} ({start} to {end}) are attached:\n\n- Executive summary (for the client's management)\n- Technical findings (for IT)\n\nOpen the attachments in a browser to read them, or print them to PDF. Please review them before forwarding to the client.",
                            ['client' => $client['name'], 'start' => $start, 'end' => $end]), implode(',', $ids));
                    $this->db->commit();
                } catch (\Throwable $ex) {
                    $this->db->rollBack();
                    throw $ex;
                }
                $done++;
            } catch (\Throwable $ex) {
                $this->recordFailure($client, $start, $ex);
            } finally {
                $this->db->query("SELECT RELEASE_LOCK({$lock})");
            }
        }
        return $done;
    }

    /**
     * Snapshot and HTML for one report, checked for size.
     *
     * @param array<string,mixed> $client
     * @return array{0:array<string,mixed>, 1:string}
     */
    private function prepare(array $client, string $kind, string $start, string $end, string $byName): array
    {
        if (!in_array($kind, ReportBuilder::KINDS, true)) {
            throw new \InvalidArgumentException('Unknown report kind.');
        }
        $snapshot = $this->builder->build($client, $kind, $start, $end, $byName);
        $html = $this->renderer->render($snapshot);
        if (strlen($html) > self::MAX_HTML_BYTES) {
            throw new \RuntimeException(__('The report is too large to store ({mb} MB). Resolve or triage some findings, or contact support.', ['mb' => round(strlen($html) / 1_000_000, 1)]));
        }
        // The logo is already in the HTML; don't store a second copy in the snapshot.
        $snapshot['brand']['logo'] = $snapshot['brand']['logo'] !== '' ? 'embedded' : '';
        // The snapshot column holds 16 MB: refuse clearly rather than fail on insert.
        if (strlen((string) json_encode($snapshot)) > self::MAX_HTML_BYTES) {
            throw new \RuntimeException(__('The report is too large to store. Resolve or triage some findings, or contact support.'));
        }
        return [$snapshot, $html];
    }

    /**
     * Save a prepared report.
     *
     * @param array<string,mixed> $client
     * @param array<string,mixed> $snapshot
     */
    private function store(array $client, string $kind, string $start, string $end, ?int $userId, string $source, array $snapshot, string $html): int
    {
        $id = $this->reports->create((int) $client['id'], $kind, $source, ReportBuilder::title($kind, (string) $client['name'], $start, $end),
            $start, $end, $userId, $html, $snapshot);
        $this->events?->publish('report.created', ['report_id' => $id, 'client_id' => (int) $client['id'], 'kind' => $kind, 'source' => $source,
            'period_start' => $start, 'period_end' => $end]);
        return $id;
    }

    /**
     * Record a failed monthly run; tell admins on the first failure and when giving up.
     *
     * @param array<string,mixed> $client
     */
    private function recordFailure(array $client, string $start, \Throwable $ex): void
    {
        $message = $ex instanceof \RuntimeException ? $ex->getMessage() : 'Unexpected error while creating the report.';
        error_log('[msp-sentinel] monthly report for client ' . (int) $client['id'] . ' failed: ' . $ex->getMessage());
        $this->db->prepare("INSERT INTO report_runs (client_id, period_start, status, attempts, last_error, last_attempt_at)
                            VALUES (:c, :p, 'failed', 1, :e, UTC_TIMESTAMP())
                            ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_error = VALUES(last_error), last_attempt_at = UTC_TIMESTAMP()")
            ->execute(['c' => (int) $client['id'], 'p' => $start, 'e' => mb_substr($message, 0, 300)]);
        $attempts = (int) ($client['run_attempts'] ?? 0) + 1;
        if ($attempts === 1 || $attempts >= self::MAX_MONTHLY_ATTEMPTS) {
            $this->alerts?->notifyUsers('report_failed', 'warn', __('The monthly reports for {client} could not be created', ['client' => $client['name']]),
                $message . ($attempts >= self::MAX_MONTHLY_ATTEMPTS ? ' ' . __('Sentinel has stopped retrying; create them by hand.') : ' ' . __('Sentinel will try again in an hour.')),
                '/clients/' . (int) $client['id'] . '/reports', 'reports.schedule');
        }
    }
}
