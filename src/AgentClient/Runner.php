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
 *   communities on 161/udp, login pages over plain HTTP); then, when the
 *   signed job asks for them, the Active Directory checks (DirectoryChecks:
 *   the password is opened only for that sign-in, and only once the domain
 *   controller's certificate matches the trusted one) and listening for
 *   LLMNR/NetBIOS name requests (NameListener: it never answers).
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
    /** @var array<string,mixed>|null the update result sent with the last idle check-in */
    private ?array $reportedResult = null;
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
        private readonly ?Platform $platform = null,
        private readonly ?ProtocolProbes $probes = null,
        private readonly ?AgentKey $key = null,
        private readonly ?Credentials $credentials = null,
        private readonly ?\Sentinel\Directory\DirectoryChecks $directory = null,
        private readonly ?\Sentinel\Directory\NameListener $listener = null,
        private readonly ?Updater $updater = null,
        private readonly ?Mover $mover = null,
        private readonly ?\Sentinel\Scanning\DefaultCredentials $creds = null,
        private readonly ?\Sentinel\Scanning\SmbShares $smb = null,
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
        $moved = $this->mover?->override() !== null;
        if ($moved && $this->mover->recallDue() && $this->mover->recall()) {
            return -2; // Sentinel (at the configured address) recalled this agent
        }
        try {
            $res = $this->http->post('/agent/v1/poll', $this->pollBody([], true));
        } catch (\Throwable $ex) {
            // Right after a move, a new address that keeps failing sends the agent back to its configured one.
            if ($moved && $this->mover->checkInFailed()) {
                return -2;
            }
            throw $ex;
        }
        if ($moved && $res['status'] === 401) {
            // Refused at the moved-to address: never wipe or stop because of THAT address (during probation: go back).
            return $this->mover->refusedAtNewAddress() ? -2 : 60;
        }
        // Any other non-answer (an error page, a 404, a 200 that isn't Sentinel's) is a failed check-in at a new address:
        // never also counted as a good one.
        if ($moved && ($res['status'] !== 200 || !is_array($res['data']['jobs'] ?? null) || !is_int($res['data']['poll_seconds'] ?? null))) {
            ($this->log)('Check-in at the new address failed (HTTP ' . $res['status'] . ').');
            return $this->mover->checkInFailed() ? -2 : 60;
        }
        if ($res['status'] === 401) {
            ($this->log)('Sentinel no longer accepts this agent (revoked?). Deleting the directory password and stopping.');
            $this->credentials?->wipe();
            return -1;
        }
        if ($res['status'] !== 200) {
            ($this->log)('Check-in failed (HTTP ' . $res['status'] . ').');
            return 60;
        }
        if ($moved) {
            $this->mover->checkInWorked();
        }
        $this->takeSecrets((array) $res['data']);
        if (($res['data']['diagnostics'] ?? false) === true) {
            $this->sendDiagnostics();
        }
        if (($res['data']['restart'] ?? false) === true) {
            ($this->log)('Sentinel asked for a restart. Exiting; the service starts the agent again.');
            return -2;
        }
        if ($this->updater !== null && is_array($res['data']['release_key'] ?? null)) {
            $this->updater->stagePin($res['data']['release_key']);
        }
        if ($this->mover !== null && is_array($res['data']['move'] ?? null)) {
            $move = $this->mover->requested($res['data']['move']);
            if ($move !== null && $move['server'] !== $this->http->server() && $this->mover->tryMove($move['server'], $move['ca_pem'], $this->http, $move['move_id']) === '') {
                return -2; // restart: the agent program starts on the new address
            }
        }
        if ($this->updater !== null && $this->reportedResult !== null) {
            $this->updater->markReported($this->reportedResult); // Sentinel has the helper's result now
            $this->reportedResult = null;
        }
        if ($this->updater !== null && is_array($res['data']['update'] ?? null) && !$this->updater->pending()) {
            $asked = $this->updater->requested($res['data']['update']);
            if ($asked !== null) {
                [$version, $request] = $asked;
                try {
                    $why = $this->updater->stage($version, self::version(), $request);
                } catch (\Throwable $ex) {
                    $why = 'The update could not be prepared: ' . mb_substr($ex->getMessage(), 0, 200);
                }
                if ($why !== '') {
                    ($this->log)('Update to ' . $version . ' not staged: ' . $why);
                    try {
                        $this->http->post('/agent/v1/update/result', ['version' => $version, 'ok' => false, 'message' => $why, 'request' => $request]);
                    } catch (\Throwable) {
                        // reported again if Sentinel asks again
                    }
                }
            }
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

    /**
     * What every check-in sends: name, version, running jobs, this agent's public key (for sealed passwords) and
     * whether it holds a directory password.
     *
     * "idle": true only from the main loop, which acts on jobs and one-off requests; check-ins during a scan say false,
     * so the server keeps those for later instead of handing them to a check-in that ignores them.
     *
     * @param list<int> $running
     * @return array<string,mixed>
     */
    private function pollBody(array $running, bool $idle): array
    {
        $holds = $this->credentials?->holds() ?? false;
        $result = $idle ? $this->updater?->unreportedResult() : null; // the update helper's last result, until Sentinel has it
        $this->reportedResult = $result;
        return ['hostname' => (string) gethostname(), 'version' => self::version(), 'running' => $running, 'idle' => $idle, 'server' => $this->http->server()]
            + ($result !== null ? ['update_result' => $result] : [])
            + ($this->updater !== null ? ['release_key_fp' => \Sentinel\System\ReleaseManifest::keyFingerprint($this->updater->releaseKey())] : [])
            + ($this->key !== null ? ['box_public_key' => $this->key->publicKey(), 'holds_directory' => $holds,
                                      'directory_username' => $holds ? $this->credentials?->username() : ''] : []);
    }

    /**
     * Sealed directory passwords and "forget it" instructions from a check-in answer (both signed; Credentials checks
     * them). Each drop is answered: kept, or refused and why. The password itself is never logged or sent anywhere.
     *
     * @param array<string,mixed> $data
     */
    private function takeSecrets(array $data): void
    {
        if ($this->credentials === null) {
            return;
        }
        foreach (array_slice((array) ($data['secrets'] ?? []), 0, 5) as $s) {
            if (!is_array($s) || !is_string($s['payload'] ?? null) || !is_string($s['signature'] ?? null)) {
                continue;
            }
            $r = $this->credentials->accept($s['payload'], $s['signature']);
            if ($r === null) {
                ($this->log)('Ignored a directory password that is not signed for this agent.');
                continue;
            }
            ($this->log)($r['ok'] ? 'Directory password received and kept (sealed).' : 'Directory password refused: ' . $r['error']);
            try {
                $ack = $this->http->post('/agent/v1/secrets/' . $r['drop_id'] . '/ack', ['ok' => $r['ok'], 'error' => $r['error']]);
                if ($ack['status'] < 200 || $ack['status'] > 299) {
                    ($this->log)('Sentinel did not accept the confirmation (HTTP ' . $ack['status'] . '); it will send the password again and get the same answer.');
                }
            } catch (\Throwable $ex) {
                ($this->log)('Could not confirm the directory password (will be sent again): ' . mb_substr($ex->getMessage(), 0, 200));
            }
        }
        $f = $data['forget'] ?? null;
        if (is_array($f) && is_string($f['payload'] ?? null) && is_string($f['signature'] ?? null) && $this->credentials->forget($f['payload'], $f['signature'])) {
            ($this->log)('Directory password deleted, as Sentinel asked.');
        }
    }

    /**
     * A diagnostics report for the Agents page: versions, disk, memory, load, uptime, clock, the key fingerprint and
     * whether a directory password is held (never the password or the token).
     */
    private function sendDiagnostics(): void
    {
        ['uptime' => $uptime, 'memory_mb' => $mem] = ($this->platform ?? Platform::detect())->systemInfo();
        $free = @disk_free_space($this->state->directory());
        $load = function_exists('sys_getloadavg') ? (sys_getloadavg()[0] ?? null) : null;
        try {
            $this->http->post('/agent/v1/diagnostics', [
                'version' => self::version(), 'php' => PHP_VERSION, 'os' => php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m'), 'nmap' => $this->nmap->version(),
                'disk_free_mb' => $free === false ? null : (int) ($free / 1048576), 'uptime_seconds' => $uptime, 'memory_mb' => $mem, 'load' => $load,
                'pending_results' => count($this->state->pending()), 'time' => gmdate('Y-m-d\TH:i:s\Z'),
                'key_fingerprint' => $this->key !== null ? AgentKey::fingerprint($this->key->publicKey()) : '', 'holds_directory' => $this->credentials?->holds() ?? false,
                'name_listening' => $this->listener === null ? (($this->platform ?? Platform::detect())->namesListener() ? 'off' : 'not on Windows (the system owns those ports)') : 'on (LLMNR UDP 5355, NetBIOS UDP 137)',
            ]);
            ($this->log)('Diagnostics sent.');
        } catch (\Throwable $ex) {
            ($this->log)('Could not send diagnostics: ' . mb_substr($ex->getMessage(), 0, 200));
        }
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
     * @return array<string,mixed> status, messages, hosts, unscanned (and directory, names when the job asked for them).
     *         Hosts carry "scanned": true only when their port scan finished; unscanned lists hosts found but not scanned.
     */
    public function run(array $job): array
    {
        $this->stopNow = false;
        $this->lastCheck = microtime(true);
        $engagement = $job['engagement'] ?? null;
        // An engagement stops at its signed end time on the agent's own clock, even if Sentinel can't be reached.
        $shouldStop = fn (): bool => $this->shouldStop($job['job_id']) || ($engagement !== null && time() >= (int) $engagement['ends_at'] && ($this->stopNow = true));
        $messages = [];
        $found = [];
        $byFamily = [];
        foreach ($job['targets'] as $t) {
            $byFamily[str_contains($t, ':') ? 6 : 4][] = $t;
        }
        $nmap = $this->nmap->withProfile($job['timing'] ?? 'gentle'); // the site's gentleness, from the signed job
        foreach ($byFamily as $cidrs) {
            if ($shouldStop()) {
                break;
            }
            // An engagement's exclusions are left out of the sweep too: never touched at all.
            $r = $nmap->discover($cidrs, $shouldStop, 57600, $engagement['exclusions'] ?? []);
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
        if ($engagement !== null) {
            return $this->runEngagement($job, $engagement, $found, $nmap, $shouldStop, $messages, $complete);
        }
        if ($job['kind'] === 'full') {
            foreach ($found as $ip => $host) {
                if ($shouldStop()) {
                    $complete = false;
                    break;
                }
                try {
                    $scan = $nmap->scan((string) $ip, $job['ports'], $shouldStop);
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
        $extra = [];
        if ($job['kind'] === 'full' && ($job['directory'] ?? null) !== null && $this->directory !== null && !$shouldStop()) {
            // The password is opened here, used for one sign-in (only after the certificate check) and dropped.
            $password = $this->credentials?->password();
            $extra['directory'] = $this->directory->run($job['directory'], $this->credentials?->username() ?? '', $password);
            $password = null;
        }
        if ($job['kind'] === 'full' && ($job['listen'] ?? 0) > 0 && $this->listener !== null && !$shouldStop()) {
            $extra['names'] = $this->listener->listen($job['listen'], static fn (string $ip): bool => InternalRanges::allWithin([$ip], $job['ranges']), $shouldStop);
        }
        $unscanned = [];
        foreach ($found as $ip => $h) {
            if ($job['kind'] === 'full' && $h['scanned'] !== true) {
                $unscanned[] = (string) $ip;
                unset($found[$ip]['ports']); // nothing known about its ports this time: Sentinel keeps what it had
            }
        }
        $status = $this->stopNow ? ($unscanned === [] && $complete ? 'done' : 'partial') : ($complete ? 'done' : 'partial');
        return ['status' => $status, 'messages' => array_slice($messages, 0, 20), 'hosts' => array_values($found), 'unscanned' => $unscanned] + $extra;
    }

    /**
     * A pen-test engagement's internal tests on the hosts discovery found: excluded hosts are left alone; every other
     * host gets the deeper scan (all ports or the job's list, the signed tests' script selections, the signed timing),
     * and SNMP's default communities when the UDP test is signed. Results are evidence only (Sentinel keeps them with
     * the engagement).
     *
     * @param array<string,mixed> $job
     * @param array{id:int, tests:list<string>, exclusions:list<string>, ends_at:int, creds_done?:array<string,true>, creds_retest?:?array<string,array<string,string>>} $engagement
     * @param array<string,array<string,mixed>> $found
     * @param callable():bool $shouldStop
     * @param list<string> $messages
     * @return array<string,mixed>
     */
    private function runEngagement(array $job, array $engagement, array $found, NmapRunner $nmap, callable $shouldStop, array $messages, bool $complete): array
    {
        $tests = $engagement['tests'];
        $scripts = array_values(array_filter([in_array('nse_safe', $tests, true) ? NmapRunner::SAFE_SCRIPTS : null, in_array('anon_access', $tests, true) ? NmapRunner::ANON_SCRIPTS : null]));
        $ports = in_array('tcp_full', $tests, true) && $job['ports'] === [] ? null : $job['ports'];
        $hosts = [];
        foreach ($found as $ip => $host) {
            foreach ($engagement['exclusions'] as $x) {
                if (InternalRanges::within((string) $ip, $x)) {
                    continue 2; // excluded (the sweep left it out too; this guards against anything it still reported)
                }
            }
            if ($shouldStop()) {
                $complete = false;
                break;
            }
            $h = ['ip' => (string) $ip, 'mac' => $host['mac'], 'hostname' => '', 'scanned' => false, 'ports' => [], 'hostscripts' => []];
            try {
                $scan = $nmap->deepScan((string) $ip, $ports, $scripts, $shouldStop);
                if ($scan['stopped'] || $scan['timed_out'] || $scan['overflow']) {
                    $complete = false;
                    $hosts[] = $h;
                    continue;
                }
                $parsed = NmapXmlParser::parse($scan['xml'], (string) $ip, 20_000_000);
                $h['ports'] = $parsed['open'];
                $h['hostscripts'] = $parsed['hostscripts'];
                $h['scanned'] = $parsed['complete'] && $scan['exit'] === 0;
            } catch (\Throwable $ex) {
                $messages[] = $ip . ': ' . mb_substr($ex->getMessage(), 0, 200);
                $complete = false;
            }
            if ($this->probes !== null && in_array('udp_common', $tests, true) && in_array(161, $job['udp_ports'] ?? [], true) && !$shouldStop()) {
                $h['udp'] = $this->probes->udpChecks((string) $ip); // SNMP, NTP, SSDP: signed in the job
            }
            // Open file shares (anonymous access test, 1.30): anonymous session, read-only, top folders only.
            if ($this->smb !== null && in_array('anon_access', $tests, true) && in_array(445, array_column($h['ports'], 'port'), true) && !$shouldStop()) {
                $h['smb_shares'] = $this->smb->check((string) $ip, $shouldStop);
            }
            // Vendor default passwords: only when signed in the job's tests, on the services found on this host.
            if ($this->creds !== null && in_array('default_creds', $tests, true) && $h['ports'] !== [] && !$shouldStop()
                && !isset($engagement['creds_done'][(string) $ip])) { // already tested in this engagement: never again
                $retest = $engagement['creds_retest'] ?? null;
                $h['creds'] = $this->creds->check((string) $ip, $h['ports'], $shouldStop, $retest === null ? null : ($retest[(string) $ip] ?? []));
            }
            $hosts[] = $h;
        }
        return ['status' => $complete && !$this->stopNow ? 'done' : 'partial', 'messages' => array_slice($messages, 0, 20), 'hosts' => $hosts, 'unscanned' => []];
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
            $res = $this->http->post('/agent/v1/poll', $this->pollBody([$jobId], false));
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
     * MAC addresses the system's ARP table knows, by IP (Linux /proc/net/arp, Windows `arp -a`: see Platform).
     *
     * @return array<string,string>
     */
    private function arp(): array
    {
        return ($this->platform ?? Platform::detect())->arpTable();
    }

    /** A host name from a certificate's common name (only a plain DNS name, no wildcards). */
    private static function hostFromCert(string $cn): string
    {
        return preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i', $cn) === 1 ? strtolower($cn) : '';
    }
}
