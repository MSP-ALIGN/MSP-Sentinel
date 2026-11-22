<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

use Sentinel\Agent\InternalRanges;
use Sentinel\Scanning\EndpointRepository;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Scanning\NmapRunner;
use Sentinel\Scanning\NmapXmlParser;
use Sentinel\Scanning\TlsChecker;

/**
 * The agent's work loop: check in with Sentinel, verify each job (JobVerifier),
 * run it, and send the results.
 *
 * - light job: a discovery sweep of the signed networks (which devices are up);
 * - full job: the sweep, then on each device found a gentle port scan of the
 *   job's ports (TCP connect, service versions), then the certificate and
 *   start-page check on its TLS and web ports.
 * Every device is checked against the signed ranges again before it is
 * touched. While a job runs, the agent checks in every 30 seconds and stops
 * at once if Sentinel says so (kill switch, pause, cancelled job).
 *
 * Untrusted: everything from the network (jobs, scan output, devices).
 */
final class Runner
{
    /** The release version (VERSION file), reported to Sentinel at each check-in. */
    public static function version(): string
    {
        $v = trim((string) @file_get_contents(dirname(__DIR__, 2) . '/VERSION'));
        return preg_match('/^\d+\.\d+\.\d+$/', $v) === 1 ? $v : 'unknown';
    }

    private const MAX_HOSTS = 20000;
    private const CHECK_IN = 30;

    /** @var callable(string):void */
    private $log;
    private float $lastCheck = 0.0;
    private bool $stopNow = false;

    /** @param callable(string):void $log Progress lines (journal). */
    public function __construct(
        private readonly Http $http,
        private readonly JobVerifier $verifier,
        private readonly State $state,
        private readonly NmapRunner $nmap,
        private readonly TlsChecker $tls,
        private readonly HttpProbe $web,
        callable $log,
        private readonly string $arpFile = '/proc/net/arp',
    ) {
        $this->log = $log;
    }

    /**
     * One check-in: fetch jobs, run each valid one, send results.
     *
     * @return int Seconds until the next check-in.
     */
    public function pollOnce(): int
    {
        $res = $this->http->post('/agent/v1/poll', ['hostname' => (string) gethostname(), 'version' => self::version(), 'running' => []]);
        if ($res['status'] === 401) {
            ($this->log)('Sentinel no longer accepts this agent (revoked?). Stopping.');
            return -1;
        }
        if ($res['status'] !== 200) {
            ($this->log)('Check-in failed (HTTP ' . $res['status'] . ').');
            return 60;
        }
        foreach ((array) ($res['data']['jobs'] ?? []) as $signed) {
            if (!is_array($signed) || !is_string($signed['payload'] ?? null) || !is_string($signed['signature'] ?? null)) {
                continue;
            }
            $job = $this->verifier->verify($signed['payload'], $signed['signature'], $this->state->doneIds());
            if (is_string($job)) {
                ($this->log)('Refused a job: ' . $job . '.');
                continue;
            }
            $this->state->markDone($job['job_id']); // before running: a crash never leads to running it twice
            $results = $this->run($job);
            $up = $this->http->post('/agent/v1/jobs/' . $job['job_id'] . '/results', $results, 300);
            ($this->log)('Job ' . $job['job_id'] . ' ' . $results['status'] . ': ' . count($results['hosts']) . ' device(s); upload HTTP ' . $up['status'] . '.');
        }
        return max(30, min(600, (int) ($res['data']['poll_seconds'] ?? 60)));
    }

    /**
     * Run one verified job.
     *
     * @param array{job_id:int, kind:string, targets:list<string>, ports:list<int>, ranges:list<string>} $job
     * @return array{status:string, messages:list<string>, hosts:list<array<string,mixed>>}
     */
    public function run(array $job): array
    {
        $this->stopNow = false;
        $this->lastCheck = microtime(true);
        $shouldStop = fn (): bool => $this->shouldStop($job['job_id']);
        $messages = [];
        $found = [];
        $byFamily = [];
        foreach ($job['targets'] as $t) {
            $byFamily[str_contains($t, ':') ? 6 : 4][] = $t;
        }
        foreach ($byFamily as $cidrs) {
            if ($shouldStop()) {
                break;
            }
            $r = $this->nmap->discover($cidrs, $shouldStop);
            if ($r['stopped']) {
                break;
            }
            try {
                foreach (NmapXmlParser::parseDiscovery($r['xml'], self::MAX_HOSTS) as $h) {
                    // Never trust the scanner's output either: only addresses inside the signed ranges.
                    if (InternalRanges::allWithin([$h['ip']], $job['ranges']) && InternalRanges::allWithin([$h['ip']], $job['targets'])) {
                        $found[$h['ip']] = ['ip' => $h['ip'], 'mac' => $h['mac'], 'hostname' => '', 'ports' => []];
                    }
                }
            } catch (\RuntimeException $ex) {
                $messages[] = 'Discovery failed: ' . $ex->getMessage();
            }
        }
        foreach ($this->arp() as $ip => $mac) {
            if (isset($found[$ip]) && $found[$ip]['mac'] === '') {
                $found[$ip]['mac'] = $mac;
            }
        }
        $complete = !$this->stopNow && $messages === [];
        if ($job['kind'] === 'full') {
            foreach ($found as $ip => $host) {
                if ($shouldStop()) {
                    $complete = false;
                    break;
                }
                try {
                    $scan = $this->nmap->scan((string) $ip, $job['ports'], $shouldStop);
                    if ($scan['stopped'] || $scan['timed_out'] || $scan['overflow']) {
                        $complete = false;
                        continue;
                    }
                    $parsed = NmapXmlParser::parse($scan['xml'], (string) $ip);
                } catch (\Throwable $ex) {
                    $messages[] = $ip . ': ' . mb_substr($ex->getMessage(), 0, 200);
                    $complete = false;
                    continue;
                }
                foreach ($parsed['open'] as $svc) {
                    $port = ['port' => (int) $svc['port'], 'service' => (string) $svc['service'], 'product' => (string) $svc['product'], 'version' => (string) $svc['version'],
                             'extra' => (string) $svc['extra'], 'cpe' => (string) $svc['cpe']];
                    $isTls = EndpointRepository::isTls((int) $svc['port'], (string) $svc['service']);
                    if ($isTls && !$shouldStop()) {
                        $t = $this->tls->check((string) $ip, (int) $svc['port'], null, $shouldStop);
                        if (!empty($t['ok'])) {
                            $t += $this->tls->probeProtocols((string) $ip, (int) $svc['port'], null);
                            $found[$ip]['hostname'] = $found[$ip]['hostname'] !== '' ? $found[$ip]['hostname'] : self::hostFromCert((string) ($t['subject_cn'] ?? ''));
                        }
                        $port['tls'] = $t;
                    }
                    if (EndpointRepository::isWeb((int) $svc['port'], (string) $svc['service']) && !$shouldStop()) {
                        $w = $this->web->fetch((string) $ip, (int) $svc['port'], $isTls ? 'https' : 'http', null);
                        unset($w['_response']);
                        $port['web'] = ['ok' => !empty($w['ok']), 'status' => (int) ($w['status_code'] ?? 0), 'title' => (string) ($w['title'] ?? ''),
                                        'category' => (string) ($w['category'] ?? 'other') ?: 'other', 'scheme' => $isTls ? 'https' : 'http'];
                    }
                    $found[$ip]['ports'][] = $port;
                }
            }
        }
        $status = $this->stopNow ? 'cancelled' : ($complete ? 'done' : 'partial');
        return ['status' => $status, 'messages' => array_slice($messages, 0, 20), 'hosts' => array_values($found)];
    }

    /** Check in every 30 seconds while a job runs; true when Sentinel says this job must stop. */
    private function shouldStop(int $jobId): bool
    {
        if ($this->stopNow) {
            return true;
        }
        if (microtime(true) - $this->lastCheck < self::CHECK_IN) {
            return false;
        }
        $this->lastCheck = microtime(true);
        try {
            $res = $this->http->post('/agent/v1/poll', ['hostname' => (string) gethostname(), 'version' => self::version(), 'running' => [$jobId]]);
        } catch (\Throwable) {
            return false; // Sentinel briefly unreachable: carry on (the job's own limits still apply)
        }
        if ($res['status'] === 401 || ($res['data']['paused'] ?? false) === true || in_array($jobId, (array) ($res['data']['stop'] ?? []), true)) {
            ($this->log)('Sentinel asked to stop job ' . $jobId . '.');
            $this->stopNow = true;
        }
        return $this->stopNow;
    }

    /**
     * MAC addresses the agent's own ARP table knows (Linux), by IP.
     *
     * @return array<string,string>
     */
    private function arp(): array
    {
        $out = [];
        $lines = is_readable($this->arpFile) ? (array) file($this->arpFile, FILE_IGNORE_NEW_LINES) : [];
        foreach (array_slice($lines, 1) as $line) {
            $cols = preg_split('/\s+/', trim((string) $line)) ?: [];
            if (count($cols) >= 4 && filter_var($cols[0], FILTER_VALIDATE_IP) && preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i', $cols[3]) && $cols[3] !== '00:00:00:00:00:00') {
                $out[$cols[0]] = strtolower($cols[3]);
            }
        }
        return $out;
    }

    /** A host name from a certificate's common name (only a plain DNS name, no wildcards). */
    private static function hostFromCert(string $cn): string
    {
        return preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i', $cn) === 1 ? strtolower($cn) : '';
    }
}
