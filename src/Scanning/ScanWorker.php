<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use PDO;
use Sentinel\Alerts\AlertService;
use Sentinel\Alerts\Outbox;
use Sentinel\Api\EventPublisher;
use Sentinel\System\Housekeeping;
use Sentinel\Web\EmailChecker;
use Sentinel\Web\WebsiteChecker;
use Sentinel\Web\WebsiteRepository;
use Sentinel\Reports\ReportService;
use Sentinel\Reports\StatsRecorder;
use Sentinel\Clients\ClientRepository;
use Sentinel\Discovery\DnsClient;
use Sentinel\Findings\FindingsEngine;
use Sentinel\Findings\FixWorkflow;
use Sentinel\Findings\VerifyOutcome;
use Sentinel\Discovery\DnsException;
use Sentinel\Discovery\DnsMessage;
use Sentinel\Scope\AuthorisationRepository;
use Sentinel\Scope\ScopeService;
use Sentinel\Vulns\VulnMatcher;

/**
 * The scan worker: queues weekly scheduled jobs, then runs at most one job per call.
 * Started by bin/worker.php from cron every minute.
 *
 * For each target address, in order, the worker:
 *  1. stops if the job was cancelled, scanning was paused (globally or for the
 *     client), the client was archived, or the window closed (unless an admin
 *     overrode the window);
 *  2. asks ScopeService::isInScope() right before scanning. If the answer is no,
 *     the address is skipped and the skip is logged;
 *  3. runs nmap on that ONE address (NmapRunner), polling the same stop
 *     conditions every second while it runs;
 *  4. stores open services and writes the outcome to the append-only scan log.
 *
 * Hostnames in scope are resolved at run time, but each resolved address is
 * only scanned if it is ITSELF in scope. A client's DNS record can't point
 * the scanner at a third party.
 *
 * Security assumptions: one worker at a time (a database lock per install),
 * fail closed on any doubt, and every decision about a host is logged.
 */
final class ScanWorker
{
    public const SCHEDULE_DAYS = 7;
    private const MAX_TARGETS = 2048;

    /** @param callable(string):void $log Progress lines (CLI output). */
    public function __construct(
        private readonly PDO $db,
        private readonly ClientRepository $clients,
        private readonly AuthorisationRepository $authorisations,
        private readonly ScanRepository $scans,
        private readonly ScopeService $scope,
        private readonly NmapRunner $nmap,
        private readonly ?DnsClient $dns,
        private $log = null,
        private readonly ?TlsChecker $tls = null,
        private readonly ?HttpProbe $http = null,
        private readonly ?EndpointRepository $endpoints = null,
        private readonly ?VulnMatcher $matcher = null,
        private readonly ?FindingsEngine $findings = null,
        private readonly ?AlertService $alerts = null,
        private readonly ?Outbox $outbox = null,
        private readonly ?ReportService $reports = null,
        private readonly ?StatsRecorder $stats = null,
        private readonly ?EventPublisher $events = null,
        private readonly ?Housekeeping $housekeeping = null,
        private readonly ?WebsiteChecker $website = null,
        private readonly ?WebsiteRepository $websiteStore = null,
        private readonly ?EmailChecker $email = null,
        private readonly ?FixWorkflow $workflow = null,
        private readonly ?\Sentinel\Inventory\InventorySync $inventory = null,
        private readonly ?\Sentinel\Agent\AgentService $agentService = null,
    ) {
        $this->log ??= static function (string $line): void {
        };
    }

    /**
     * One worker cycle: schedule due jobs, then run the next runnable job.
     *
     * @param bool     $schedule  Queue weekly jobs first (false: only run what is queued).
     * @param int|null $onlyJobId Run only this queued job (it must still pass the window and pause checks).
     * @return string Short description of what happened.
     */
    public function tick(bool $schedule = true, ?int $onlyJobId = null): string
    {
        // Heartbeat (proves cron runs, even while a long scan holds the worker lock); daily update check and retention.
        $this->housekeeping?->tick();
        $lock = $this->db->quote('msp_sentinel_worker_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
            return 'Another worker is running.';
        }
        try {
            // We hold the only worker lock, so any job still "running" belongs to a worker that died.
            $died = $this->db->query("SELECT id, client_id, job_type FROM scan_jobs WHERE status = 'running'")->fetchAll();
            $this->db->exec("UPDATE scan_jobs SET status = 'failed', finished_at = UTC_TIMESTAMP(),
                             summary = '{\"messages\":[\"The worker stopped unexpectedly during this job.\"]}' WHERE status = 'running'");
            $this->db->exec("UPDATE scan_log SET result = 'interrupted', finished_at = UTC_TIMESTAMP() WHERE result = 'running' AND finished_at IS NULL");
            foreach ($died as $d) {
                if ($d['job_type'] === 'verify') {
                    // A recheck someone is waiting for: tell them, instead of a scan-failure alert to admins.
                    VerifyOutcome::recordAborted($this->db, $this->scans->find((int) $d['id']) ?? [], __('the worker stopped unexpectedly. Try again.'));
                    continue;
                }
                $this->alerts?->scanFailed((int) $d['client_id'], (int) $d['id'], 'The worker stopped unexpectedly during this job.');
            }
            $queued = $schedule ? $this->scheduleDue() : 0;
            $job = $this->nextRunnable($onlyJobId);
            $result = $job === null ? "Scheduled {$queued} job(s). Nothing to run now." : "Scheduled {$queued} job(s). " . $this->runJob($job);
            // Daily trend counts and due monthly reports (their emails go out in the flush below).
            try {
                $this->stats?->recordToday();
                $monthly = $this->reports?->runMonthly() ?? 0;
                if ($monthly > 0) {
                    $result .= " Monthly reports: {$monthly} client(s).";
                }
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] reports failed: ' . $ex->getMessage());
            }
            // On-premises agents: queue due weekly full scans and daily light sweeps (the agents fetch them).
            try {
                $agentJobs = $this->agentService?->scheduleDue() ?? 0;
                if ($agentJobs > 0) {
                    $result .= " Agent jobs queued: {$agentJobs}.";
                }
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] agent scheduling failed: ' . $ex->getMessage());
            }
            // Internal devices from inventory sources (NinjaOne): a few due clients per tick.
            try {
                $synced = $this->inventory?->syncDue() ?? 0;
                if ($synced > 0) {
                    $result .= " Inventory: {$synced} client(s) synced.";
                }
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] inventory sync failed: ' . $ex->getMessage());
            }
            // Daily fix reminders (overdue and due-soon findings) once a day.
            try {
                if ($this->workflow !== null && $this->alerts !== null && $this->workflow->claimDailyReminders()) {
                    $r = $this->alerts->fixReminders($this->workflow->dueItems());
                    $result .= " Fix reminders: {$r['assignees']} assignee(s).";
                }
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] fix reminders failed: ' . $ex->getMessage());
            }
            // Send queued alerts (also when no job ran, so retries and test messages go out).
            if ($this->outbox !== null) {
                try {
                    $sent = $this->outbox->flush();
                    $this->outbox->prune();
                    if ($sent['sent'] + $sent['failed'] > 0) {
                        $result .= " Alerts: {$sent['sent']} sent, {$sent['failed']} failed.";
                    }
                } catch (\Throwable $ex) {
                    error_log('[msp-sentinel] sending alerts failed: ' . $ex->getMessage());
                }
            }
            return $result;
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /**
     * Queue a weekly scan for each eligible client whose last scheduled scan was SCHEDULE_DAYS or more ago.
     *
     * @return int Number of jobs queued.
     */
    public function scheduleDue(): int
    {
        if ($this->scope->globallyPaused()) {
            return 0;
        }
        $count = 0;
        foreach ($this->clients->all(false) as $client) {
            $id = (int) $client['id'];
            if ((int) $client['scanning_paused'] === 1 || (int) ($client['is_demo'] ?? 0) === 1 || $this->scans->openJob($id) !== null) {
                continue;
            }
            $last = $this->scans->lastScheduledAt($id);
            if ($last !== null && strtotime($last . ' UTC') > time() - self::SCHEDULE_DAYS * 86400) {
                // No port scan due: queue the daily certificate and web page re-check if it's due.
                try {
                    $lastTls = $this->scans->lastScheduledAt($id, 'tls');
                    $recent = max(strtotime($last . ' UTC'), $lastTls === null ? 0 : (int) strtotime($lastTls . ' UTC'));
                    // Only queue it while the window is open (so it never sits in the queue blocking a manual scan)
                    // and while the client still has an active scope.
                    if ($this->endpoints !== null && $recent <= time() - 86400 && ScanWindow::isOpen($client) && $this->payloadFor($client) !== null
                        && ($endpoints = $this->endpoints->checkableEndpoints($id)) !== []) {
                        $this->scans->queue($id, 'scheduled', null, false, null, ['endpoints' => $endpoints], 'tls');
                        $count++;
                    }
                } catch (\Throwable $ex) {
                    ($this->log)("Could not schedule the certificate check for client {$id}: " . $ex->getMessage());
                }
                continue;
            }
            try {
                $payload = $this->payloadFor($client);
                if ($payload === null) {
                    continue;
                }
                $this->scans->queue($id, 'scheduled', null, false, null, $payload);
                $count++;
                continue; // the port scan re-checks certificates too, so no TLS job is needed this time
            } catch (\Throwable $ex) {
                // One client's problem must never stop every other client from being scanned.
                ($this->log)("Could not schedule client {$id}: " . $ex->getMessage());
                error_log('[msp-sentinel] scheduling client ' . $id . ' failed: ' . $ex->getMessage());
            }
        }
        return $count;
    }

    /**
     * Targets and ports for a client from its CURRENT active scope, or null if there is nothing to scan.
     *
     * @param array<string,mixed> $client
     * @return array{ips:list<string>,hostnames:list<string>,ports:list<int>,truncated?:bool}|null
     */
    public function payloadFor(array $client): ?array
    {
        $entries = $this->authorisations->activeEntries((int) $client['id'], ScopeService::today((string) $client['timezone']));
        $ips = [];
        $hosts = [];
        $truncated = false;
        foreach ($entries as $e) {
            if ($e['entry_type'] === 'ip' || $e['entry_type'] === 'cidr') {
                $range = $e['entry_type'] === 'ip' ? [(string) $e['value']] : self::expand((string) $e['range_start'], (string) $e['range_end']);
                foreach ($range as $ip) {
                    if (count($ips) >= self::MAX_TARGETS) {
                        $truncated = true; // stop collecting addresses, but keep collecting hostnames
                        break;
                    }
                    $ips[$ip] = true;
                }
            } elseif ($e['entry_type'] === 'domain' && !str_starts_with((string) $e['value'], '*.')) {
                $hosts[(string) $e['value']] = true; // wildcards can't be enumerated; discovery suggests their names
            }
        }
        $ports = PortProfile::forClient($client);
        if (($ips === [] && $hosts === []) || $ports === []) {
            return null;
        }
        return ['ips' => array_keys($ips), 'hostnames' => array_keys($hosts), 'ports' => $ports] + ($truncated ? ['truncated' => true] : []);
    }

    /**
     * The oldest queued job that may run now (its client's window is open, or an admin overrode it).
     * Jobs for paused or archived clients are cancelled.
     *
     * @return array<string,mixed>|null
     */
    private function nextRunnable(?int $onlyJobId = null): ?array
    {
        $verify = null;
        $regular = null;
        foreach ($this->scans->queuedJobs() as $job) {
            if ($onlyJobId !== null && (int) $job['id'] !== $onlyJobId) {
                continue;
            }
            $client = $this->clients->find((int) $job['client_id']);
            if ($client === null || (int) $client['is_archived'] === 1 || (int) $client['scanning_paused'] === 1 || $this->scope->globallyPaused()) {
                $this->scans->cancel((int) $job['id']);
                $this->scans->finish((int) $job['id'], 'cancelled', ['message' => __('Cancelled because scanning was paused or the client was archived.')]);
                VerifyOutcome::recordAborted($this->db, $job, __('scanning was paused or the client was archived.'));
                continue;
            }
            if ((int) $job['outside_window'] === 1 || ScanWindow::isOpen($client)) {
                if ($job['job_type'] === 'verify') {
                    $verify ??= $job;
                } else {
                    $regular ??= $job;
                }
                if ($verify !== null && $regular !== null) {
                    break;
                }
            }
        }
        // Rechecks go first (someone is waiting), but never more than 3 in a row while a scan is waiting,
        // so a burst of rechecks can't push a scan out of its window.
        if ($verify !== null && $regular !== null) {
            $recent = $this->db->query("SELECT job_type FROM scan_jobs WHERE started_at IS NOT NULL ORDER BY started_at DESC, id DESC LIMIT 3")->fetchAll(PDO::FETCH_COLUMN);
            return count($recent) === 3 && array_unique($recent) === ['verify'] ? $regular : $verify;
        }
        return $verify ?? $regular;
    }

    /**
     * Run one job to the end (or until it must stop).
     *
     * @param array<string,mixed> $job
     */
    public function runJob(array $job): string
    {
        $jobId = (int) $job['id'];
        $clientId = (int) $job['client_id'];
        if (!$this->scans->claim($jobId)) {
            return "Job {$jobId} was taken or cancelled.";
        }
        if (($job['job_type'] ?? 'ports') === 'tls') {
            return $this->runTlsJob($job);
        }
        if (($job['job_type'] ?? 'ports') === 'verify' && isset($job['payload']['email_domain'])) {
            return $this->runEmailVerify($job);
        }
        // A "verify fix" recheck of one address and port runs like a port scan of just that port,
        // with the host names already known for the address (for certificates and Host headers).
        $isVerify = ($job['job_type'] ?? 'ports') === 'verify';
        $ports = array_values(array_filter((array) ($job['payload']['ports'] ?? []), 'is_int'));
        if ($isVerify) {
            // The port must still be in the client's scan profile when the recheck runs (it may have changed while queued).
            $client = $this->clients->find($clientId);
            $ports = $client === null ? [] : array_values(array_intersect($ports, PortProfile::forClient($client)));
        }
        $portText = PortProfile::toNmapArg($ports);
        $overrideWindow = (int) $job['outside_window'] === 1;
        $summary = ['hosts_scanned' => 0, 'hosts_skipped' => 0, 'hosts_failed' => 0, 'open_ports' => 0, 'messages' => []];
        if ($isVerify) {
            $summary['verify_probe'] = []; // what this recheck proved, per "ip:port" (see VerifyOutcome)
            if ($ports === []) {
                $summary['messages'][] = __('This port is no longer in the client\'s scan profile.');
                $this->refreshFindings($clientId, $summary);
                $this->recordVerification($job, 'partial', $summary);
                $this->scans->finish($jobId, 'partial', $summary);
                return "Verify job {$jobId} partial: port not in profile.";
            }
        }
        $siteId = null;
        foreach ($this->clients->sites($clientId) as $site) {
            if ((int) $site['is_default'] === 1) {
                $siteId = (int) $site['id'];
            }
        }

        // Targets: listed IPs, plus the addresses of in-scope hostnames resolved now.
        $targets = [];
        foreach ((array) ($job['payload']['ips'] ?? []) as $ip) {
            $canonical = ScopeService::canonicalTarget((string) $ip);
            if ($canonical !== null && filter_var($canonical, FILTER_VALIDATE_IP) !== false) {
                $targets[$canonical] ??= array_values(array_filter((array) ($job['payload']['names'][$canonical] ?? []), 'is_string'));
            }
        }
        foreach ((array) ($job['payload']['hostnames'] ?? []) as $host) {
            foreach ($this->resolve((string) $host, $summary) as $ip) {
                $targets[$ip][] = (string) $host;
            }
        }
        if (count($targets) > self::MAX_TARGETS || !empty($job['payload']['truncated'])) {
            $summary['messages'][] = __('This client has more than {n} addresses in scope. Only the first {n} were scanned in this job.', ['n' => self::MAX_TARGETS]);
        }
        $targets = array_slice($targets, 0, self::MAX_TARGETS, true);
        ($this->log)("Job {$jobId}: " . count($targets) . " address(es), ports {$portText}");

        $status = 'done';
        $stopReason = null;     // stops the whole job (cancel, pause, window)
        $hostOutOfScope = false; // stops only the current host
        $shouldStop = function (?string $ip = null) use ($jobId, $clientId, $overrideWindow, &$stopReason, &$hostOutOfScope): bool {
            $stopReason = $this->stopReason($jobId, $clientId, $overrideWindow);
            if ($stopReason !== null) {
                return true;
            }
            if ($ip !== null && !$this->scope->isInScope($clientId, $ip)) {
                $hostOutOfScope = true;
                return true;
            }
            return false;
        };

        $remaining = array_keys($targets);
        foreach ($targets as $ip => $hostnames) {
            $hostLabel = $hostnames === [] ? null : mb_substr(implode(',', array_unique($hostnames)), 0, 260);
            if ($shouldStop()) {
                break;
            }
            array_shift($remaining);
            $hostOutOfScope = false;
            if (!$this->scope->isInScope($clientId, (string) $ip)) {
                $why = $hostnames === []
                    ? __('Not in an active authorisation.')
                    : __('Address of {host}, but this address is not in an active authorisation. Add it to the scope if the client owns it.', ['host' => $hostLabel]);
                $this->scans->logStart($jobId, $clientId, (string) $ip, $hostLabel, $portText, 'skipped_out_of_scope', $why);
                $summary['hosts_skipped']++;
                continue;
            }
            $logId = $this->scans->logStart($jobId, $clientId, (string) $ip, $hostLabel, $portText, 'running');
            try {
                $result = $this->nmap->scan((string) $ip, $ports, fn (): bool => $shouldStop((string) $ip));
            } catch (\Throwable $ex) {
                $this->scans->logFinish($logId, 'error', mb_substr($ex->getMessage(), 0, 300));
                $summary['hosts_failed']++;
                $summary['messages'][] = __('Could not run nmap: {e}', ['e' => $ex->getMessage()]);
                $status = 'failed';
                break;
            }
            if ($result['stopped'] && $hostOutOfScope && $stopReason === null) {
                // This address left the scope while it was being scanned (authorisation revoked or changed).
                $this->scans->logFinish($logId, 'stopped', __('Stopped because this address is no longer in scope.'));
                $summary['hosts_skipped']++;
                continue;
            }
            if ($result['stopped']) {
                $this->scans->logFinish($logId, 'stopped', (string) ($stopReason ?? __('Stopped.')));
                array_unshift($remaining, (string) $ip); // not finished: part of the resumed job
                break;
            }
            if ($result['overflow']) {
                $this->scans->logFinish($logId, 'error', __('nmap produced far too much output for one host and was stopped.'));
                $summary['hosts_failed']++;
                continue;
            }
            if ($result['timed_out']) {
                $this->scans->logFinish($logId, 'timeout', __('The host took too long and was stopped.'));
                $summary['hosts_failed']++;
                continue;
            }
            try {
                $parsed = NmapXmlParser::parse($result['xml'], (string) $ip);
            } catch (\RuntimeException $ex) {
                $firstLine = strtok($result['stderr'], "\n") ?: '';
                $this->scans->logFinish($logId, 'error', trim($ex->getMessage() . ' ' . mb_substr($firstLine, 0, 200)) . ' (exit ' . $result['exit'] . ')');
                $summary['hosts_failed']++;
                continue;
            }
            $this->scans->recordHost($clientId, $siteId, (string) $ip, array_values(array_unique($hostnames)), $ports, $parsed['open'], $parsed['complete'] && $result['exit'] === 0, $jobId);
            if (isset($summary['verify_probe'])) {
                $openPorts = array_column($parsed['open'], 'port');
                foreach ($ports as $p) {
                    // Only a complete scan proves a port open or no longer reachable.
                    $summary['verify_probe'][$ip . ':' . $p] = ['state' => $parsed['complete'] && $result['exit'] === 0 ? (in_array($p, $openPorts, true) ? 'open' : 'closed') : 'unknown'];
                }
            }
            $this->scans->logFinish($logId, 'scanned', __('{n} open port(s)', ['n' => count($parsed['open'])]) . ($parsed['complete'] ? '' : ' ' . __('(incomplete)')));
            $summary['hosts_scanned']++;
            $summary['open_ports'] += count($parsed['open']);
            // Certificates and web pages on the open ports just found (same scope and stop rules).
            $services = array_map(static fn (array $s): array => ['port' => $s['port'], 'service' => $s['service']], $parsed['open']);
            $this->checkEndpoints($jobId, $clientId, (string) $ip, array_values(array_unique($hostnames)), $services, $shouldStop, $summary);
        }

        if ($stopReason !== null) {
            $status = $this->scans->cancelRequested($jobId) ? 'cancelled' : 'partial';
            $summary['messages'][] = $stopReason;
            if ($stopReason === self::windowClosedMessage() && $remaining !== []) {
                // Resume in the next window: queue a follow-up job with the addresses not scanned yet.
                // (They are checked against the live scope again when it runs.)
                $followUp = $this->scans->queue($clientId, (string) $job['trigger_type'], $job['requested_by'] === null ? null : (int) $job['requested_by'], false, null,
                    ['ips' => $remaining, 'hostnames' => [], 'ports' => $ports, 'resumes' => $jobId]);
                $summary['messages'][] = __('{n} address(es) not scanned yet will be scanned in the next window (scan #{id}).', ['n' => count($remaining), 'id' => $followUp]);
            }
        } elseif ($status === 'done' && $summary['hosts_failed'] > 0) {
            $status = 'partial';
        }
        // Match what was found against vulnerability data (cached; up to 3 new products fetched now).
        if ($this->matcher !== null && $summary['hosts_scanned'] > 0) {
            try {
                // A few new products, at most ~20 seconds; everything else is left to the daily feeds job.
                $m = $this->matcher->matchClient($clientId, 3, 20.0);
                $summary['vulnerability_matches_for_client'] = $m['matches'];
                if ($this->websiteStore !== null) {
                    $wm = $this->matcher->matchComponents($this->websiteStore, $clientId, 2);
                    $m['pending'] += $wm['pending'];
                }
                $summary['vuln_pending'] = (int) $m['pending'];
                if ($m['pending'] > 0) {
                    $summary['messages'][] = __('{n} product(s) are waiting for vulnerability data; the daily feeds job will fetch it.', ['n' => $m['pending']]);
                }
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] vulnerability matching failed for client ' . $clientId . ': ' . $ex->getMessage());
            }
        }
        if (!$isVerify) {
            $this->checkEmail($clientId, $summary);
        }
        $this->refreshFindings($clientId, $summary);
        if ($isVerify) {
            $this->recordVerification($job, $status, $summary);
        }
        $this->scans->finish($jobId, $status, $summary);
        $this->publishFinished($jobId, $clientId, $isVerify ? 'verify' : 'ports', $status);
        if ($status === 'failed') {
            try {
                $this->alerts?->scanFailed($clientId, $jobId, implode(' ', array_slice((array) $summary['messages'], 0, 3)));
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] scan failure alert failed: ' . $ex->getMessage());
            }
        }
        return "Job {$jobId} {$status}: {$summary['hosts_scanned']} scanned, {$summary['hosts_skipped']} skipped, {$summary['hosts_failed']} failed.";
    }

    /**
     * "Verify fix" for an email finding: check that one domain's records again (DNS only), if it is still in scope.
     *
     * @param array<string,mixed> $job Already claimed.
     */
    private function runEmailVerify(array $job): string
    {
        $jobId = (int) $job['id'];
        $clientId = (int) $job['client_id'];
        $domain = strtolower((string) $job['payload']['email_domain']);
        $summary = ['hosts_scanned' => 0, 'hosts_skipped' => 0, 'hosts_failed' => 0, 'open_ports' => 0, 'messages' => []];
        $status = 'done';
        $stop = $this->stopReason($jobId, $clientId, true);
        if ($stop !== null) {
            $status = $this->scans->cancelRequested($jobId) ? 'cancelled' : 'partial';
            $summary['messages'][] = $stop;
        } elseif (!$this->scope->isInScope($clientId, $domain)) {
            $this->scans->logStart($jobId, $clientId, 'dns', mb_substr($domain, 0, 260), '', 'skipped_out_of_scope', __('Not in an active authorisation.'));
            $summary['hosts_skipped']++;
            $status = 'partial';
            $summary['messages'][] = __('{domain} is no longer in an active authorisation.', ['domain' => $domain]);
        } else {
            $logId = $this->scans->logStart($jobId, $clientId, 'dns', mb_substr($domain, 0, 260), '', 'running');
            $this->checkEmail($clientId, $summary, $domain);
            $ok = (int) ($summary['email_domains_checked'] ?? 0) === 1 && !isset($summary['email_error']);
            $this->scans->logFinish($logId, $ok ? 'checked' : 'error', $ok ? __('Email records checked (DNS only).') : __('The DNS lookups failed: {e}', ['e' => (string) ($summary['email_error'] ?? '?')]));
            $summary['hosts_scanned'] = $ok ? 1 : 0;
            $summary['verify_probe'] = ['email' => $ok ? 'ok' : 'failed'];
            $summary['hosts_failed'] = $ok ? 0 : 1;
            $status = $ok ? 'done' : 'partial';
        }
        $this->refreshFindings($clientId, $summary);
        $this->recordVerification($job, $status, $summary);
        $this->scans->finish($jobId, $status, $summary);
        $this->publishFinished($jobId, $clientId, 'verify', $status);
        return "Verify job {$jobId} {$status}.";
    }

    /**
     * Record the honest outcome of a "verify fix" recheck (VerifyOutcome) on the finding and tell the person who asked.
     *
     * @param array<string,mixed> $job
     * @param array<string,mixed> $summary Gets verify_result.
     */
    private function recordVerification(array $job, string $status, array &$summary): void
    {
        $findingId = (int) ($job['payload']['finding_id'] ?? 0);
        try {
            $stmt = $this->db->prepare('SELECT f.finding_key, f.status, f.resolved_at, j.started_at FROM findings f JOIN scan_jobs j ON j.id = :j WHERE f.id = :id AND f.client_id = :c');
            $stmt->execute(['j' => (int) $job['id'], 'id' => $findingId, 'c' => (int) $job['client_id']]);
            $f = $stmt->fetch();
            if ($f === false) {
                return;
            }
            $outcome = VerifyOutcome::decide($f, $status, $f['started_at'] === null ? null : (string) $f['started_at'], $summary);
            $summary['verify_result'] = $outcome['result'];
            VerifyOutcome::record($this->db, $findingId, $job['requested_by'] === null ? null : (int) $job['requested_by'], $outcome['result'], $outcome['note']);
        } catch (\Throwable $ex) {
            error_log('[msp-sentinel] recording verification failed for finding ' . $findingId . ': ' . $ex->getMessage());
        }
    }

    /**
     * Daily re-check of known TLS endpoints and web pages (no port scan).
     *
     * @param array<string,mixed> $job Already claimed.
     */
    private function runTlsJob(array $job): string
    {
        $jobId = (int) $job['id'];
        $clientId = (int) $job['client_id'];
        $overrideWindow = (int) $job['outside_window'] === 1;
        $summary = ['hosts_scanned' => 0, 'hosts_skipped' => 0, 'hosts_failed' => 0, 'open_ports' => 0, 'endpoints_checked' => 0, 'messages' => []];
        $stopReason = null;
        $shouldStop = function (?string $ip = null) use ($jobId, $clientId, $overrideWindow, &$stopReason): bool {
            $stopReason = $this->stopReason($jobId, $clientId, $overrideWindow);
            return $stopReason !== null || ($ip !== null && !$this->scope->isInScope($clientId, $ip));
        };
        $byIp = [];
        foreach ((array) ($job['payload']['endpoints'] ?? []) as $ep) {
            $ip = ScopeService::canonicalTarget((string) ($ep['ip'] ?? ''));
            if ($ip === null || filter_var($ip, FILTER_VALIDATE_IP) === false || !is_int($ep['port'] ?? null)) {
                continue;
            }
            $byIp[$ip]['services'][] = ['port' => $ep['port'], 'service' => (string) ($ep['service'] ?? '')];
            $byIp[$ip]['hostnames'] = (array) ($ep['hostnames'] ?? []);
        }
        foreach ($byIp as $ip => $data) {
            if ($shouldStop()) {
                break;
            }
            if (!$this->scope->isInScope($clientId, (string) $ip)) {
                $this->scans->logStart($jobId, $clientId, (string) $ip, null, '', 'skipped_out_of_scope', __('Not in an active authorisation.'));
                $summary['hosts_skipped']++;
                continue;
            }
            $this->checkEndpoints($jobId, $clientId, (string) $ip, $data['hostnames'], $data['services'], $shouldStop, $summary);
            $summary['hosts_scanned']++;
        }
        $status = $stopReason !== null ? ($this->scans->cancelRequested($jobId) ? 'cancelled' : 'partial') : 'done';
        if ($stopReason !== null) {
            $summary['messages'][] = $stopReason;
        }
        $this->checkEmail($clientId, $summary);
        $this->refreshFindings($clientId, $summary);
        $this->scans->finish($jobId, $status, $summary);
        $this->publishFinished($jobId, $clientId, 'tls', $status);
        return "TLS job {$jobId} {$status}: {$summary['endpoints_checked']} endpoint(s) checked.";
    }

    /**
     * Check certificates and web pages on one host's open ports.
     * Logs one scan-log row for the host's endpoint checks.
     *
     * @param list<string>                            $hostnames Names that resolved to this IP (only in-scope ones are used).
     * @param list<array{port:int,service:string}>    $services
     * @param callable(?string):bool                  $shouldStop
     * @param array<string,mixed>                     $summary
     */
    private function checkEndpoints(int $jobId, int $clientId, string $ip, array $hostnames, array $services, callable $shouldStop, array &$summary): void
    {
        if ($this->tls === null || $this->http === null || $this->endpoints === null) {
            return;
        }
        $assetId = $this->endpoints->assetId($clientId, $ip);
        if ($assetId === null) {
            return;
        }
        // The same names in every job (port scan, resumed scan, daily check): this job's names plus
        // the names stored on the asset, in-scope only, sorted, at most 3. Otherwise certificate rows
        // and findings would flip between "with name" and "without name".
        $all = array_unique(array_merge($hostnames, $this->endpoints->assetHostnames($assetId)));
        sort($all);
        $names = array_values(array_slice(array_filter($all, fn (string $h): bool => $h !== '' && $this->scope->isInScope($clientId, $h)), 0, 3));
        $checked = ['tls' => 0, 'web' => 0];
        $logId = null;
        $portList = implode(',', array_map(static fn (array $s): string => (string) $s['port'], array_filter($services,
            static fn (array $s): bool => EndpointRepository::isTls((int) $s['port'], (string) $s['service']) || EndpointRepository::isWeb((int) $s['port'], (string) $s['service']))));
        try {
        foreach ($services as $svc) {
            $port = (int) $svc['port'];
            $isTls = EndpointRepository::isTls($port, (string) $svc['service']);
            $isWeb = EndpointRepository::isWeb($port, (string) $svc['service']);
            if (!$isTls && !$isWeb) {
                continue;
            }
            $logId ??= $this->scans->logStart($jobId, $clientId, $ip, $names === [] ? null : implode(',', $names), $portList, 'running', __('Certificate and web page checks'));
            if ($isTls) {
                $snis = $names === [] ? [null] : $names;
                $allOk = true;
                foreach ($snis as $i => $sni) {
                    if ($shouldStop($ip)) {
                        $this->scans->logFinish($logId, 'stopped', __('Stopped during certificate checks.'));
                        return;
                    }
                    $result = $this->tls->check($ip, $port, $sni, fn (): bool => $shouldStop($ip));
                    if (!empty($result['stopped'])) {
                        $this->scans->logFinish($logId, 'stopped', __('Stopped during certificate checks.'));
                        return;
                    }
                    if ($i === 0 && $result['ok']) {
                        if ($shouldStop($ip)) {
                            $this->scans->logFinish($logId, 'stopped', __('Stopped during certificate checks.'));
                            return;
                        }
                        $result += $this->tls->probeProtocols($ip, $port, $sni);
                    }
                    $this->endpoints->saveTls($assetId, $port, (string) $sni, $result);
                    $allOk = $allOk && $result['ok'];
                    $checked['tls']++;
                }
                // Remove rows for names no longer used, but only when every check succeeded:
                // a failed check must never make an old certificate (and its findings) disappear.
                if ($allOk) {
                    $this->endpoints->pruneTls($assetId, $port, array_map(static fn (?string $n): string => (string) $n, $snis));
                }
                if (isset($summary['verify_probe'])) {
                    $summary['verify_probe'][$ip . ':' . $port]['tls_ok'] = $allOk;
                    $summary['verify_probe'][$ip . ':' . $port]['snis'] = array_map(static fn (?string $n): string => (string) $n, $snis);
                }
            }
            if ($isWeb) {
                if ($shouldStop($ip)) {
                    $this->scans->logFinish($logId, 'stopped', __('Stopped during web page checks.'));
                    return;
                }
                $scheme = $isTls ? 'https' : 'http';
                $page = $this->http->fetch($ip, $port, $scheme, $names[0] ?? null);
                $this->endpoints->saveWeb($assetId, $port, $page);
                $checked['web']++;
                if (isset($summary['verify_probe'])) {
                    $summary['verify_probe'][$ip . ':' . $port]['web_ok'] = !empty($page['ok']);
                    $summary['verify_probe'][$ip . ':' . $port]['site_complete'] = false;
                }
                // Website checks: headers, cookies, components from the page just fetched, then the short
                // fixed list of exposed-file requests (each one re-checks scope, window and kill switch).
                if ($this->website !== null && $this->websiteStore !== null && !empty($page['ok']) && isset($page['_response'])) {
                    $checks = WebsiteChecker::analyse($page['_response'], $scheme);
                    $exposed = $this->website->exposedFiles($ip, $port, $scheme, $names[0] ?? null, fn (): bool => $shouldStop($ip));
                    // A partial run (stopped, or a request without answer) keeps earlier results only for files
                    // without a conclusive answer this time: a file that now answers "not there" is fixed.
                    $kept = $exposed['complete'] ? [] : array_diff((array) ($this->websiteStore->previousChecks($assetId, $port)['exposed'] ?? []), $exposed['checked']);
                    $checks['exposed'] = array_values(array_unique(array_merge($exposed['codes'], $kept)));
                    $this->websiteStore->saveChecks($assetId, $port, $checks);
                    if (isset($summary['verify_probe'])) {
                        $summary['verify_probe'][$ip . ':' . $port]['site_complete'] = $exposed['complete'];
                    }
                }
            }
        }
        } catch (\Throwable $ex) {
            // A problem with one host's checks (e.g. a database hiccup while saving) must not abort the whole job.
            error_log('[msp-sentinel] endpoint checks failed for ' . $ip . ': ' . $ex->getMessage());
            if ($logId !== null) {
                $this->scans->logFinish($logId, 'error', __('Certificate and web page checks failed: {e}', ['e' => mb_substr($ex->getMessage(), 0, 200)]));
            }
            $summary['hosts_failed']++;
            return;
        }
        if ($logId !== null) {
            $this->scans->logFinish($logId, 'checked', __('{t} certificate check(s), {w} web page(s)', ['t' => $checked['tls'], 'w' => $checked['web']]));
        }
        $summary['endpoints_checked'] = ($summary['endpoints_checked'] ?? 0) + $checked['tls'] + $checked['web'];
    }

    /**
     * Update the client's findings after a job (errors are logged, never fatal to the job).
     *
     * @param array<string,mixed> $summary Receives the new and resolved counts.
     */
    private function refreshFindings(int $clientId, array &$summary): void
    {
        if ($this->findings === null) {
            return;
        }
        try {
            $f = $this->findings->refreshClient($clientId);
            $summary['refresh_ok'] = true;
            $summary['findings_opened'] = $f['opened'] + $f['reopened'];
            $summary['findings_resolved'] = $f['resolved'];
            $this->alerts?->findingsChanged($clientId, $f, true);
        } catch (\Throwable $ex) {
            $summary['refresh_ok'] ??= false; // alerts failing after a good refresh doesn't undo the refresh
            error_log('[msp-sentinel] findings refresh or alerts failed for client ' . $clientId . ': ' . $ex->getMessage());
        }
    }

    /** The message used when the window closes (also used to recognise that case). */
    private static function windowClosedMessage(): string
    {
        return __('Stopped because the scan window closed.');
    }

    /** Why the whole job must stop now (cancel, pause, archive, window), or null to carry on. */
    private function stopReason(int $jobId, int $clientId, bool $overrideWindow): ?string
    {
        if ($this->scans->cancelRequested($jobId)) {
            return __('Cancelled by a user.');
        }
        $client = $this->clients->find($clientId);
        if ($client === null || (int) $client['is_archived'] === 1 || (int) $client['scanning_paused'] === 1 || $this->scope->globallyPaused()) {
            return __('Stopped because scanning was paused.');
        }
        if (!$overrideWindow && !ScanWindow::isOpen($client)) {
            return self::windowClosedMessage();
        }
        return null;
    }

    /**
     * Resolve an in-scope hostname to canonical addresses (A and AAAA).
     *
     * @param array<string,mixed> $summary Messages are added for lookup failures.
     * @return list<string>
     */
    private function resolve(string $host, array &$summary): array
    {
        if ($this->dns === null || ScopeService::canonicalTarget($host) !== $host) {
            return [];
        }
        $ips = [];
        foreach ([DnsMessage::A, DnsMessage::AAAA] as $type) {
            try {
                foreach ($this->dns->query($host, $type) as $answer) {
                    if ($answer['type'] === $type && ($c = ScopeService::canonicalTarget($answer['data'])) !== null) {
                        $ips[$c] = true;
                    }
                }
            } catch (DnsException $ex) {
                $summary['messages'][] = __('Could not resolve {host}: {e}', ['host' => $host, 'e' => $ex->getMessage()]);
            }
        }
        return array_keys($ips);
    }

    /**
     * All addresses in a range (packed start/end, at most 256 by scope rules).
     *
     * @return list<string>
     */
    private static function expand(string $start, string $end): array
    {
        $out = [];
        $cur = $start;
        for ($i = 0; $i < 4096; $i++) {
            $out[] = (string) inet_ntop($cur);
            if ($cur === $end) {
                break;
            }
            // increment the packed address by one (big-endian)
            for ($b = strlen($cur) - 1; $b >= 0; $b--) {
                $byte = (ord($cur[$b]) + 1) & 0xff;
                $cur[$b] = chr($byte);
                if ($byte !== 0) {
                    break;
                }
            }
        }
        return $out;
    }

    /** Queue a scan.finished event (never lets an event problem affect the scan). */
    private function publishFinished(int $jobId, int $clientId, string $type, string $status): void
    {
        try {
            $this->events?->publish('scan.finished', ['scan_id' => $jobId, 'client_id' => $clientId, 'job_type' => $type, 'status' => $status]);
        } catch (\Throwable $ex) {
            error_log('[msp-sentinel] event failed: ' . $ex->getMessage());
        }
    }

    /**
     * Email security records (SPF, DMARC, DKIM) for the client's in-scope domains. Each domain is
     * checked at most every 20 hours; new domains and domains whose DNS failed are checked on the next
     * job, and domains that left the scope are removed on every job. DNS lookups only: nothing is sent
     * to the client's servers. Never fatal to the job.
     *
     * @param string|null $force Check only this domain, now ("verify fix"); nothing if it isn't in scope.
     *
     * @param array<string,mixed> $summary
     */
    private function checkEmail(int $clientId, array &$summary, ?string $force = null): void
    {
        if ($this->email === null || $this->websiteStore === null) {
            return;
        }
        try {
            $client = $this->clients->find($clientId);
            if ($client === null || (int) $client['scanning_paused'] === 1 || (int) $client['is_archived'] === 1 || $this->scope->globallyPaused()) {
                return; // paused means paused, even for DNS-only checks
            }
            $domains = [];
            foreach ($this->authorisations->activeEntries($clientId, ScopeService::today((string) $client['timezone'])) as $e) {
                if ($e['entry_type'] !== 'domain') {
                    continue;
                }
                $value = strtolower((string) $e['value']);
                $d = (string) preg_replace('/^\*\./', '', $value);
                // "*.client.example" does not authorise client.example itself: only check names in scope.
                if ($d === $value || $this->scope->isInScope($clientId, $d)) {
                    $domains[$d] = true;
                }
                if (str_starts_with($d, 'www.') && $this->scope->isInScope($clientId, substr($d, 4))) {
                    $domains[substr($d, 4)] = true;
                }
            }
            $inScope = array_slice(array_keys($domains), 0, 20);
            $times = $this->websiteStore->emailCheckedTimes($clientId);
            $results = [];
            foreach ($inScope as $d) {
                if ($force !== null ? $d !== $force : (isset($times[$d]) && strtotime($times[$d] . ' UTC') > time() - 20 * 3600)) {
                    continue; // checked recently (or a "verify fix" of another domain)
                }
                // Receivers fall back to the organisational domain's DMARC record; only looked up when that domain is in scope too.
                $parent = substr($d, (int) strpos($d, '.') + 1);
                $org = str_contains($parent, '.') && $this->scope->isInScope($clientId, $parent) ? $parent : null;
                $results[] = $r = $this->email->check($d, $org);
                if ($r['error'] !== '') {
                    $summary['email_error'] = $r['error'];
                }
            }
            $this->websiteStore->saveEmail($clientId, $results, $inScope);
            $summary['email_domains_checked'] = count($results);
        } catch (\Throwable $ex) {
            error_log('[msp-sentinel] email checks failed for client ' . $clientId . ': ' . $ex->getMessage());
        }
    }
}
