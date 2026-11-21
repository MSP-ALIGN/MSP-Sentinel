<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use PDO;
use Sentinel\Clients\ClientRepository;
use Sentinel\Discovery\DnsClient;
use Sentinel\Discovery\DnsException;
use Sentinel\Discovery\DnsMessage;
use Sentinel\Scope\AuthorisationRepository;
use Sentinel\Scope\ScopeService;

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
        $lock = $this->db->quote('msp_sentinel_worker_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
            return 'Another worker is running.';
        }
        try {
            // We hold the only worker lock, so any job still "running" belongs to a worker that died.
            $this->db->exec("UPDATE scan_jobs SET status = 'failed', finished_at = UTC_TIMESTAMP(),
                             summary = '{\"messages\":[\"The worker stopped unexpectedly during this job.\"]}' WHERE status = 'running'");
            $this->db->exec("UPDATE scan_log SET result = 'interrupted', finished_at = UTC_TIMESTAMP() WHERE result = 'running' AND finished_at IS NULL");
            $queued = $schedule ? $this->scheduleDue() : 0;
            $job = $this->nextRunnable($onlyJobId);
            if ($job === null) {
                return "Scheduled {$queued} job(s). Nothing to run now.";
            }
            return "Scheduled {$queued} job(s). " . $this->runJob($job);
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
            if ((int) $client['scanning_paused'] === 1 || $this->scans->openJob($id) !== null) {
                continue;
            }
            $last = $this->scans->lastScheduledAt($id);
            if ($last !== null && strtotime($last . ' UTC') > time() - self::SCHEDULE_DAYS * 86400) {
                continue;
            }
            try {
                $payload = $this->payloadFor($client);
                if ($payload === null) {
                    continue;
                }
                $this->scans->queue($id, 'scheduled', null, false, null, $payload);
                $count++;
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
        foreach ($this->scans->queuedJobs() as $job) {
            if ($onlyJobId !== null && (int) $job['id'] !== $onlyJobId) {
                continue;
            }
            $client = $this->clients->find((int) $job['client_id']);
            if ($client === null || (int) $client['is_archived'] === 1 || (int) $client['scanning_paused'] === 1 || $this->scope->globallyPaused()) {
                $this->scans->cancel((int) $job['id']);
                $this->scans->finish((int) $job['id'], 'cancelled', ['message' => __('Cancelled because scanning was paused or the client was archived.')]);
                continue;
            }
            if ((int) $job['outside_window'] === 1 || ScanWindow::isOpen($client)) {
                return $job;
            }
        }
        return null;
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
        $ports = array_values(array_filter((array) ($job['payload']['ports'] ?? []), 'is_int'));
        $portText = PortProfile::toNmapArg($ports);
        $overrideWindow = (int) $job['outside_window'] === 1;
        $summary = ['hosts_scanned' => 0, 'hosts_skipped' => 0, 'hosts_failed' => 0, 'open_ports' => 0, 'messages' => []];
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
                $targets[$canonical] ??= [];
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
            $this->scans->logFinish($logId, 'scanned', __('{n} open port(s)', ['n' => count($parsed['open'])]) . ($parsed['complete'] ? '' : ' ' . __('(incomplete)')));
            $summary['hosts_scanned']++;
            $summary['open_ports'] += count($parsed['open']);
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
        $this->scans->finish($jobId, $status, $summary);
        return "Job {$jobId} {$status}: {$summary['hosts_scanned']} scanned, {$summary['hosts_skipped']} skipped, {$summary['hosts_failed']} failed.";
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
}
