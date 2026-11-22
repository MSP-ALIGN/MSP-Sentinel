<?php

declare(strict_types=1);

namespace Sentinel\Reports;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use Sentinel\Alerts\AlertService;
use Sentinel\Alerts\SmtpMailer;

/**
 * Creates reports (snapshot, render, store) and runs the monthly schedule.
 *
 * Monthly schedule: for each client with monthly reports turned on and at
 * least one recipient, once the previous calendar month has ended, an
 * Executive summary and a Technical findings report for that month are
 * created (once: a scheduled report for the period is never made twice) and
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
    ) {
    }

    /**
     * Build, render and store one report. Returns its ID.
     *
     * @param array<string,mixed> $client
     */
    public function generate(array $client, string $kind, string $start, string $end, ?int $userId, string $byName, string $source = 'manual'): int
    {
        if (!in_array($kind, ReportBuilder::KINDS, true)) {
            throw new \InvalidArgumentException('Unknown report kind.');
        }
        $snapshot = $this->builder->build($client, $kind, $start, $end, $byName);
        $html = $this->renderer->render($snapshot);
        return $this->reports->create((int) $client['id'], $kind, $source, ReportBuilder::title($kind, (string) $client['name'], $start, $end),
            $start, $end, $userId, $html, $snapshot);
    }

    /**
     * Create and send last month's scheduled reports where they are due.
     *
     * @return int Number of clients handled.
     */
    public function runMonthly(?DateTimeImmutable $now = null): int
    {
        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $start = $now->modify('first day of last month')->format('Y-m-d');
        $end = $now->modify('last day of last month')->format('Y-m-d');
        $done = 0;
        $clients = $this->db->query("SELECT * FROM clients WHERE report_monthly = 1 AND is_archived = 0 AND report_recipients <> '' ORDER BY id")->fetchAll();
        foreach ($clients as $client) {
            $cid = (int) $client['id'];
            // Per-client lock, so two processes can't both create this month's reports.
            $lock = $this->db->quote('msp_sentinel_report_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16) . '_' . $cid);
            if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
                continue;
            }
            try {
                if ($this->reports->scheduledExists($cid, $start)) {
                    continue;
                }
                $ids = [];
                foreach (ReportBuilder::KINDS as $kind) {
                    $ids[] = $this->generate($client, $kind, $start, $end, null, __('Monthly schedule'), 'scheduled');
                }
                $to = array_values(array_filter(array_map('trim', explode(',', (string) $client['report_recipients'])), [SmtpMailer::class, 'validAddress']));
                $this->alerts?->queueEmail($to, '[' . $client['name'] . '] ' . __('Monthly security reports for {month}', ['month' => $now->modify('first day of last month')->format('F Y')]),
                    __("The monthly reports for {client} ({start} to {end}) are attached:\n\n- Executive summary (for the client's management)\n- Technical findings (for IT)\n\nOpen the attachments in a browser to read them, or print them to PDF. Please review them before forwarding to the client.",
                        ['client' => $client['name'], 'start' => $start, 'end' => $end]), implode(',', $ids));
                $done++;
            } finally {
                $this->db->query("SELECT RELEASE_LOCK({$lock})");
            }
        }
        return $done;
    }
}
