<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use Sentinel\Api\ApiKernel;
use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;

/**
 * The agent API (/agent/v1), used only by on-premises agents. Agents always
 * connect out to Sentinel; Sentinel never connects to them.
 *
 * - POST /agent/v1/enrol   {code, hostname, version} -> agent ID, token (once), server public key
 * - POST /agent/v1/poll    {hostname, version, running[]} -> signed jobs to run, job IDs to stop
 * - POST /agent/v1/jobs/{id}/results  results of one job
 *
 * Security assumptions: no session or cookies; poll and results need the
 * agent's bearer token (revocable); enrolment is limited per address and
 * needs a one-time code. Jobs are signed (AgentService) and the agent checks
 * them itself. Request bodies are size- and depth-limited JSON. Errors never
 * reveal internals.
 */
final class AgentKernel
{
    /** Largest results body (bytes) and JSON depth. */
    private const MAX_RESULTS = 8388608;
    private const MAX_DEPTH = 12;
    public const POLL_SECONDS = 60;

    /** Handle one agent API request. */
    public static function handle(Request $request): Response
    {
        try {
            if ($request->method !== 'POST') {
                return ApiKernel::error(405, 'Method not allowed.');
            }
            if ($request->path === '/agent/v1/enrol') {
                return self::enrol($request);
            }
            $agent = App::agents()->authenticate($request->header('Authorization'));
            if ($agent === null) {
                return ApiKernel::error(401, 'Unknown or revoked agent token.')->header('WWW-Authenticate', 'Bearer');
            }
            $limiter = App::limiter();
            if ($limiter->tooMany('agent:' . (int) $agent['id'], 120, 60)) {
                return ApiKernel::error(429, 'Too many requests.')->header('Retry-After', '60');
            }
            $limiter->hit('agent:' . (int) $agent['id']);
            if ($request->path === '/agent/v1/poll') {
                return self::poll($request, $agent);
            }
            if (preg_match('#^/agent/v1/jobs/([1-9][0-9]{0,9})/results$#', $request->path, $m)) {
                return self::results($request, $agent, (int) $m[1]);
            }
            return ApiKernel::error(404, 'Not found.');
        } catch (\Throwable $ex) {
            error_log('[msp-sentinel] agent API ' . get_class($ex) . ': ' . $ex->getMessage() . ' in ' . $ex->getFile() . ':' . $ex->getLine());
            return ApiKernel::error(500, 'Internal error. It has been logged for the administrator.');
        }
    }

    /** POST /agent/v1/enrol */
    private static function enrol(Request $request): Response
    {
        $limiter = App::limiter();
        $bucket = 'agent-enrol:' . $request->ip();
        if ($limiter->tooMany($bucket, 10, 3600)) {
            return ApiKernel::error(429, 'Too many enrolment attempts. Try again later.')->header('Retry-After', '3600');
        }
        $body = self::body(65536);
        if ($body === null || !is_string($body['code'] ?? null)) {
            return ApiKernel::error(400, 'Send {"code": "..."} as JSON.');
        }
        $result = App::agents()->enrol($body['code'], self::short($body['hostname'] ?? '', 255), self::short($body['version'] ?? '', 20), $request->ip());
        if ($result === null) {
            $limiter->hit($bucket);
            return ApiKernel::error(403, 'The enrolment code is unknown, already used or expired. Create a new one in Sentinel.');
        }
        App::audit()->log('agent.enrolled', null, null, 'agent', $result['agent_id'], ['client_id' => $result['client_id'], 'site_id' => $result['site_id']], $request->ip());
        // The agent pins the key, its site and its client: it refuses jobs for any other site or client.
        return ApiKernel::json(['agent_id' => $result['agent_id'], 'site_id' => $result['site_id'], 'client_id' => $result['client_id'], 'token' => $result['token'],
                                'server_public_key' => App::agentSigner()->publicKey(), 'poll_seconds' => self::POLL_SECONDS], 201);
    }

    /**
     * POST /agent/v1/poll
     *
     * @param array<string,mixed> $agent
     */
    private static function poll(Request $request, array $agent): Response
    {
        $body = self::body(65536) ?? [];
        App::agents()->touch((int) $agent['id'], $request->ip(), self::short($body['hostname'] ?? $agent['hostname'], 255), self::short($body['version'] ?? $agent['version'], 20));
        $paused = (int) $agent['is_archived'] === 1 || (int) $agent['client_paused'] === 1 || (int) $agent['site_paused'] === 1 || App::scope()->globallyPaused();
        $running = array_values(array_filter((array) ($body['running'] ?? []), static fn ($id): bool => is_int($id) && $id > 0));
        $stop = App::agents()->jobsToStop((int) $agent['id']);
        $jobs = [];
        foreach ($running as $id) {
            $job = App::agents()->job((int) $agent['id'], $id);
            // Kill switch, or a scheduled scan whose window closed: stop (it resumes in the next window).
            if ($paused || $job === null || !AgentService::inWindow($job, $agent)) {
                $stop[] = $id;
            }
        }
        // Still working on the rest: keep them alive.
        App::agents()->extendLease((int) $agent['id'], array_values(array_diff($running, $stop)));
        if (!$paused) {
            foreach (App::agents()->jobsFor((int) $agent['id']) as $job) {
                if (!AgentService::inWindow($job, $agent)) {
                    continue; // scheduled jobs start only inside the scan window
                }
                $signed = App::agentService()->signedJob($job, $agent);
                if ($signed === null) {
                    App::agents()->finishJob((int) $job['id'], 'cancelled', ['messages' => [__('Cancelled: the site has no valid internal authorisation any more.')]]);
                    continue;
                }
                App::agents()->markSent((int) $job['id']);
                $jobs[] = $signed;
            }
        }
        return ApiKernel::json(['jobs' => $jobs, 'stop' => array_values(array_unique($stop)), 'paused' => $paused, 'poll_seconds' => self::POLL_SECONDS]);
    }

    /**
     * POST /agent/v1/jobs/{id}/results
     *
     * @param array<string,mixed> $agent
     */
    private static function results(Request $request, array $agent, int $jobId): Response
    {
        $job = App::agents()->job((int) $agent['id'], $jobId);
        if ($job === null) {
            return ApiKernel::error(404, 'Not found.');
        }
        $body = self::body(self::MAX_RESULTS);
        if ($body === null) {
            return ApiKernel::error(400, 'Send the results as a JSON object (at most 8 MB).');
        }
        // Claim the job first: a second upload of the same results (a retry) is answered 409 and not processed twice.
        if (!App::agents()->claimIngest($jobId)) {
            return ApiKernel::error(409, 'This job is already finished, cancelled or expired.');
        }
        set_time_limit(900);
        try {
            $stats = App::agentService()->ingest($job, $agent, $body);
        } catch (\Throwable $ex) {
            App::agents()->finishJob($jobId, 'failed', ['messages' => [__('The results could not be saved. It has been logged for the administrator.')]]);
            throw $ex;
        }
        return ApiKernel::json(['ok' => true] + $stats);
    }

    /**
     * The request body as a JSON object, or null (too large, too deep, not an object).
     *
     * @return array<string,mixed>|null
     */
    private static function body(int $max): ?array
    {
        $raw = (string) file_get_contents('php://input', false, null, 0, $max + 1);
        if ($raw === '' || strlen($raw) > $max) {
            return null;
        }
        try {
            $data = json_decode($raw, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        return is_array($data) && !array_is_list($data) ? $data : null;
    }

    /** A scalar from the body as a short clean string. */
    private static function short(mixed $v, int $max): string
    {
        return \Sentinel\Inventory\InventoryRepository::clean($v, $max);
    }
}
