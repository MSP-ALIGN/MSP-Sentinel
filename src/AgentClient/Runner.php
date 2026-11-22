<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

use Sentinel\Agent\InternalRanges;
use Sentinel\Scanning\EndpointRepository;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Scanning\NmapRunner;
use Sentinel\Scanning\NmapXmlParser;
use Sentinel\Scanning\ProtocolProbes;
use Sentinel\Scanning\TlsChecker;
use Sentinel\Web\WebsiteChecker;

/**
 * The agent's work loop: check in with Sentinel, verify each job (JobVerifier),
 * run it, and send the results.
 *
 * - light job: a discovery sweep of the signed networks (which devices are up);
 * - full job: the sweep, then on each device found a gentle port scan of the
 *   job's ports (TCP connect, service versions), then the certificate and
 *   start-page check on its TLS and web ports, and the read-only checks of
 *   risky protocols (SMBv1 and SMB signing on 445, NLA on 3389, default SNMP
 *   communities on 161/udp, login pages over plain HTTP).
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
        private readonly ?ProtocolProbes $probes = null,
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
        $this->sendPending();
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
            try {
                $results = $this->run($job);
            } catch (\Throwable $ex) {
                $results = ['status' => 'failed', 'messages' => ['The agent could not run the job: ' . mb_substr($ex->getMessage(), 0, 200)], 'hosts' => [], 'unscanned' => []];
            }
            // Kept on disk until Sentinel accepts it, so a network problem never loses a scan.
            $this->state->savePending($job['job_id'], $results);
            ($this->log)('Job ' . $job['job_id'] . ' ' . $results['status'] . ': ' . count($results['hosts']) . ' device(s).');
            $this->sendPending();
        }
        return max(30, min(600, (int) ($res['data']['poll_seconds'] ?? 60)));
    }

    /** Send finished results that Sentinel hasn't accepted yet (2xx accepted; 404/409: it no longer wants them). */
    private function sendPending(): void
    {
        foreach ($this->state->pending() as $jobId => $results) {
            try {
                $up = $this->http->post('/agent/v1/jobs/' . $jobId . '/results', $results, 600);
            } catch (\Throwable $ex) {
                ($this->log)('Upload of job ' . $jobId . ' failed (will retry): ' . mb_substr($ex->getMessage(), 0, 200));
                return;
            }
            if (($up['status'] >= 200 && $up['status'] < 300) || in_array($up['status'], [404, 409], true)) {
                $this->state->clearPending($jobId);
                ($this->log)('Results of job ' . $jobId . ' sent (HTTP ' . $up['status'] . ').');
            } else {
                ($this->log)('Upload of job ' . $jobId . ' refused (HTTP ' . $up['status'] . '); will retry.');
                return;
            }
        }
    }

    /**
     * Run one verified job.
     *
     * @param array{job_id:int, kind:string, targets:list<string>, ports:list<int>, udp_ports?:list<int>, ranges:list<string>} $job
     * @return array{status:string, messages:list<string>, hosts:list<array<string,mixed>>, unscanned:list<string>}
     *         Hosts carry "scanned": true only when their port scan finished; unscanned lists hosts found but not scanned.
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
            if ($r['stopped'] || $r['timed_out'] || $r['overflow']) {
                // Use what the sweep found so far (complete host entries only), but the job is not complete.
                $messages[] = $r['stopped'] ? 'Discovery stopped.' : ($r['timed_out'] ? 'Discovery took too long and was stopped.' : 'Discovery output too large; stopped.');
            }
            try {
                foreach (NmapXmlParser::parseDiscovery($r['xml'], self::MAX_HOSTS) as $h) {
                    // Never trust the scanner's output either: only addresses inside the signed ranges.
                    if (InternalRanges::allWithin([$h['ip']], $job['ranges']) && InternalRanges::allWithin([$h['ip']], $job['targets'])) {
                        $found[$h['ip']] = ['ip' => $h['ip'], 'mac' => $h['mac'], 'hostname' => '', 'scanned' => false, 'ports' => []];
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
                        // A login form served over plain HTTP (passwords readable on the network).
                        $loginOverHttp = !$isTls && !empty($w['ok']) && isset($w['_response'])
                            && in_array('login_over_http', WebsiteChecker::analyse($w['_response'], 'http')['issues'], true);
                        unset($w['_response']);
                        $port['web'] = ['ok' => !empty($w['ok']), 'status' => (int) ($w['status_code'] ?? 0), 'title' => (string) ($w['title'] ?? ''),
                                        'category' => (string) ($w['category'] ?? 'other') ?: 'other', 'scheme' => $isTls ? 'https' : 'http', 'login_over_http' => $loginOverHttp];
                    }
                    if ($this->probes !== null && !$shouldStop()) {
                        if ((int) $svc['port'] === 445) {
                            $port['checks'] = $this->probes->smb((string) $ip);
                        } elseif ((int) $svc['port'] === 3389) {
                            $port['checks'] = $this->probes->rdp((string) $ip);
                        }
                    }
                    $found[$ip]['ports'][] = $port;
                }
                if ($this->probes !== null && in_array(161, $job['udp_ports'] ?? [], true) && !$shouldStop()) {
                    $found[$ip]['snmp'] = $this->probes->snmp((string) $ip); // UDP 161, listed in the signed job
                }
                $found[$ip]['scanned'] = true;
            }
        }
        $unscanned = [];
        foreach ($found as $ip => $h) {
            if ($job['kind'] === 'full' && $h['scanned'] !== true) {
                $unscanned[] = (string) $ip;
                unset($found[$ip]['ports']); // nothing known about its ports this time: Sentinel keeps what it had
            }
        }
        $status = $this->stopNow ? ($unscanned === [] && $complete ? 'done' : 'partial') : ($complete ? 'done' : 'partial');
        return ['status' => $status, 'messages' => array_slice($messages, 0, 20), 'hosts' => array_values($found), 'unscanned' => $unscanned];
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
