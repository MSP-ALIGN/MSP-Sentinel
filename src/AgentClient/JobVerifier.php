<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

use Sentinel\Agent\InternalRanges;
use Sentinel\Agent\Signer;

/**
 * Runs on the agent: decides whether a job from Sentinel may run. The agent
 * trusts only the server public key it pinned at enrolment, never the data
 * the server sends with a job.
 *
 * A job runs only if ALL of these hold:
 * - the job is signed by the pinned key, is an agent job for THIS agent and
 *   for the site and client it was enrolled for, was not run before (no
 *   replays) and has not expired;
 * - it carries an internal authorisation, also signed by the pinned key, for
 *   that same site and client, valid today in the client's time zone;
 * - every target is a private network inside the authorisation's ranges, and
 *   the ports are plain port numbers;
 * - full jobs only: Active Directory checks name a domain and a domain controller address inside the signed ranges
 *   (and a trusted certificate fingerprint, or none yet); listening for name requests lasts at most MAX_LISTEN seconds.
 * - engagement jobs only (a pen-test engagement's internal tests): the engagement's id, tests from the fixed list,
 *   exclusions (private networks) and its end time are signed; no ports means all 65,535 (only with the full-port
 *   test); the agent stops on its own at the end time, even if Sentinel can't be reached.
 *
 * Untrusted: everything in the job (it arrives over the network).
 */
final class JobVerifier
{
    public const MAX_PORTS = 1000;
    public const MAX_LISTEN = 300;
    /** Engagement tests an agent runs (the same fixed list as the server's EngagementRepository::TESTS). */
    public const ENGAGEMENT_TESTS = ['tcp_full', 'udp_common', 'nse_safe', 'anon_access', 'default_creds'];

    /**
     * @param string $publicKey Pinned server public key (base64).
     * @param int    $siteId    The site and client this agent was enrolled for (pinned at enrolment): jobs for
     * @param int    $clientId  any other site or client are refused, whatever the server sends.
     */
    public function __construct(private readonly string $publicKey, private readonly int $agentId, private readonly int $siteId, private readonly int $clientId)
    {
    }

    /**
     * Check a signed job.
     *
     * @param list<int> $doneIds Jobs this agent already ran.
     * @return array{job_id:int, kind:string, targets:list<string>, ports:list<int>, udp_ports:list<int>, ranges:list<string>,
     *               directory:?array{domain:string, dc_ip:string, cert_trusted:string}, listen:int, timing:string,
     *               engagement:?array{id:int, tests:list<string>, exclusions:list<string>, ends_at:int, creds_done:array<string,true>, creds_retest:?array<string,array<string,string>>}}|string The job, or why it was refused.
     */
    public function verify(string $payload, string $signature, array $doneIds, ?int $now = null): array|string
    {
        $now ??= time();
        if (!Signer::verify($payload, $signature, $this->publicKey)) {
            return 'bad signature';
        }
        $job = json_decode($payload, true);
        if (!is_array($job) || ($job['v'] ?? null) !== 1 || ($job['type'] ?? null) !== 'agent_job') {
            return 'not an agent job';
        }
        if (($job['agent_id'] ?? null) !== $this->agentId) {
            return 'job is for another agent';
        }
        if (($job['site_id'] ?? null) !== $this->siteId || ($job['client_id'] ?? null) !== $this->clientId) {
            return 'job is for another site or client';
        }
        $jobId = $job['job_id'] ?? null;
        if (!is_int($jobId) || $jobId < 1) {
            return 'no job id';
        }
        if (in_array($jobId, $doneIds, true)) {
            return 'job already ran (replay)';
        }
        $expires = strtotime((string) ($job['expires_at'] ?? ''));
        $issued = strtotime((string) ($job['issued_at'] ?? ''));
        if ($expires === false || $expires < $now) {
            return 'job expired';
        }
        if ($issued === false || $issued > $now + 300) {
            return 'job issued in the future (check the clock)';
        }
        if (!in_array($job['kind'] ?? null, ['full', 'light', 'engagement'], true)) {
            return 'unknown job kind';
        }
        $auth = $job['authorisation'] ?? null;
        if (!is_array($auth) || !is_string($auth['payload'] ?? null) || !is_string($auth['signature'] ?? null) || !Signer::verify($auth['payload'], $auth['signature'], $this->publicKey)) {
            return 'authorisation not signed by the server';
        }
        $a = json_decode($auth['payload'], true);
        if (!is_array($a) || ($a['type'] ?? null) !== 'internal_authorisation' || ($a['v'] ?? null) !== 1 || ($a['site_id'] ?? null) !== $this->siteId || ($a['client_id'] ?? null) !== $this->clientId) {
            return 'authorisation is not for this site';
        }
        try {
            $today = (new \DateTimeImmutable('@' . $now))->setTimezone(new \DateTimeZone((string) ($a['timezone'] ?? 'UTC')))->format('Y-m-d');
        } catch (\Throwable) {
            return 'authorisation has an invalid time zone';
        }
        if (!is_string($a['valid_from'] ?? null) || !is_string($a['valid_until'] ?? null) || $today < $a['valid_from'] || $today > $a['valid_until']) {
            return 'authorisation is not valid today';
        }
        $ranges = [];
        foreach ((array) ($a['ranges'] ?? []) as $r) {
            $p = is_string($r) ? InternalRanges::parse($r) : ['error' => 'x'];
            if (!isset($p['cidr']) || $p['cidr'] !== $r) {
                return 'authorisation contains a range that is not a private network';
            }
            $ranges[] = $r;
        }
        $targets = array_values(array_filter((array) ($job['targets'] ?? []), 'is_string'));
        if ($ranges === [] || $targets === [] || count($targets) !== count((array) ($job['targets'] ?? [])) || !InternalRanges::allWithin($targets, $ranges)) {
            return 'targets outside the signed authorisation';
        }
        foreach ($targets as $t) {
            if (!isset(InternalRanges::parse($t)['cidr'])) {
                return 'target is not a private network';
            }
        }
        $ports = (array) ($job['ports'] ?? []);
        if (count($ports) > self::MAX_PORTS) {
            return 'too many ports';
        }
        foreach ($ports as $p) {
            if (!is_int($p) || $p < 1 || $p > 65535) {
                return 'invalid port';
            }
        }
        if ($job['kind'] === 'full' && $ports === []) {
            return 'full scan without ports';
        }
        $engagement = null;
        if ($job['kind'] === 'engagement') {
            $g = $job['engagement'] ?? null;
            $tests = is_array($g) ? (array) ($g['tests'] ?? []) : [];
            $ends = is_array($g) && is_string($g['ends_at'] ?? null) ? strtotime($g['ends_at']) : false;
            if (!is_array($g) || !is_int($g['id'] ?? null) || $g['id'] < 1 || $tests === [] || array_diff($tests, self::ENGAGEMENT_TESTS) !== []
                || $ends === false || $ends <= $now || !in_array($job['timing'] ?? '', ['gentle', 'normal'], true)) {
                return 'invalid engagement';
            }
            if ($ports === [] && !in_array('tcp_full', $tests, true)) {
                return 'engagement without ports';
            }
            $exclusions = [];
            foreach ((array) ($g['exclusions'] ?? []) as $x) {
                $p = is_string($x) ? InternalRanges::parse($x) : ['error' => 'x'];
                if (!isset($p['cidr'])) {
                    return 'invalid engagement exclusion';
                }
                $exclusions[] = $p['cidr'];
            }
            // Default-credential re-run plan (1.29.1): hosts already tested (skip) and, for a retest, the logins to re-check.
            $credsDone = [];
            foreach ((array) ($g['creds_done'] ?? []) as $ip) {
                if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false || count($credsDone) >= 4096) {
                    return 'invalid engagement credential plan';
                }
                $credsDone[$ip] = true;
            }
            $credsRetest = null;
            if (isset($g['creds_retest'])) {
                if (!is_array($g['creds_retest'])) {
                    return 'invalid engagement credential plan';
                }
                $credsRetest = [];
                foreach ($g['creds_retest'] as $ip => $logins) {
                    if (filter_var((string) $ip, FILTER_VALIDATE_IP) === false || !is_array($logins)) {
                        return 'invalid engagement credential plan';
                    }
                    foreach ($logins as $key => $user) {
                        $kind = explode(':', (string) $key)[0];
                        if (preg_match('/^[a-z_]+:\d{1,5}$/', (string) $key) !== 1 || !is_string($user)
                            || !in_array($user, array_column(\Sentinel\Scanning\DefaultCredentials::LIST[$kind] ?? [], 0), true)) {
                            return 'invalid engagement credential plan';
                        }
                        $credsRetest[(string) $ip][(string) $key] = $user;
                    }
                }
            }
            $engagement = ['id' => $g['id'], 'tests' => array_values(array_unique($tests)), 'exclusions' => $exclusions, 'ends_at' => $ends,
                'creds_done' => $credsDone, 'creds_retest' => $credsRetest];
        } elseif (isset($job['engagement'])) {
            return 'engagement settings on another job kind';
        }
        $udp = (array) ($job['udp_ports'] ?? []);
        foreach ($udp as $p) {
            if (!is_int($p) || $p < 1 || $p > 65535) {
                return 'invalid UDP port';
            }
        }
        $directory = null;
        if (isset($job['directory'])) {
            $d = $job['directory'];
            if ($job['kind'] !== 'full' || !is_array($d) || !is_string($d['domain'] ?? null) || !is_string($d['dc_ip'] ?? null) || !is_string($d['cert_trusted'] ?? null)
                || preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/', $d['domain']) !== 1
                || preg_match('/^([0-9a-f]{64})?$/', $d['cert_trusted']) !== 1) {
                return 'invalid directory settings';
            }
            if (filter_var($d['dc_ip'], FILTER_VALIDATE_IP) === false || !isset(InternalRanges::parse($d['dc_ip'])['cidr']) || !InternalRanges::allWithin([$d['dc_ip']], $ranges)) {
                return 'domain controller outside the signed authorisation';
            }
            $directory = ['domain' => $d['domain'], 'dc_ip' => $d['dc_ip'], 'cert_trusted' => $d['cert_trusted']];
        }
        $timing = $job['timing'] ?? 'gentle';
        if (!is_string($timing) || !isset(\Sentinel\Scanning\NmapRunner::PROFILES[$timing])) {
            return 'unknown scan timing'; // only the built-in gentle profiles, never anything faster than -T3
        }
        $listen = $job['listen'] ?? 0;
        if (!is_int($listen) || $listen < 0 || $listen > self::MAX_LISTEN || ($listen > 0 && $job['kind'] !== 'full')) {
            return 'invalid listening time';
        }
        return ['job_id' => $jobId, 'kind' => (string) $job['kind'], 'targets' => $targets, 'ports' => array_values($ports), 'udp_ports' => array_values($udp), 'ranges' => $ranges,
                'directory' => $directory, 'listen' => $listen, 'timing' => $timing, 'engagement' => $engagement];
    }
}
