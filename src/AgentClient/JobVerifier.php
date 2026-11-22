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
 *   the ports are plain port numbers.
 *
 * Untrusted: everything in the job (it arrives over the network).
 */
final class JobVerifier
{
    public const MAX_PORTS = 1000;

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
     * @return array{job_id:int, kind:string, targets:list<string>, ports:list<int>, ranges:list<string>}|string The job, or why it was refused.
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
        if (!in_array($job['kind'] ?? null, ['full', 'light'], true)) {
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
        return ['job_id' => $jobId, 'kind' => (string) $job['kind'], 'targets' => $targets, 'ports' => array_values($ports), 'ranges' => $ranges];
    }
}
