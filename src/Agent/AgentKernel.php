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
 * - POST /agent/v1/secrets/{id}/ack   {ok, error}: the agent opened and kept (or refused) a sealed directory password
 * - POST /agent/v1/diagnostics        the agent's diagnostics report, when an admin asked for one
 * - POST /agent/v1/update/manifest    {version}: the signed agent release manifest (only to an agent asked to update)
 * - POST /agent/v1/update/file        {version, path}: one file of that release, base64
 * - POST /agent/v1/update/result      {version, ok, message}: the agent couldn't stage the update
 *   (Sentinel only relays the release; the agent and its root helper accept it only when it is signed with the
 *   maintainer's release key they pinned at install.)
 *
 * The poll answer also carries the site's check-in interval and one-off requests from the Agents page ("restart":
 * the agent exits and its service starts it again; "diagnostics": send a report). Neither can make the agent scan or
 * run anything, so they need no signature.
 *
 * Sealed passwords: the poll body carries the agent's public key (box_public_key) and whether it holds a directory
 * password (holds_directory). The answer carries, signed with the server key, the sealed passwords waiting for it
 * (DirectoryRepository; Sentinel can't open them) and, when the site no longer wants it to keep one, an instruction
 * to delete it.
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
            if (preg_match('#^/agent/v1/secrets/([1-9][0-9]{0,9})/ack$#', $request->path, $m)) {
                return self::ackSecret($agent, (int) $m[1]);
            }
            if (in_array($request->path, ['/agent/v1/update/manifest', '/agent/v1/update/file', '/agent/v1/update/result'], true)) {
                return self::update($request->path, $agent);
            }
            if ($request->path === '/agent/v1/diagnostics') {
                $body = self::body(65536);
                if ($body === null) {
                    return ApiKernel::error(400, 'Send the diagnostics as a JSON object.');
                }
                App::agents()->saveDiagnostics((int) $agent['id'], $body);
                return ApiKernel::json(['ok' => true]);
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
        if (is_string($body['box_public_key'] ?? null)
            && App::agents()->setBoxKey((int) $agent['id'], (string) $agent['box_public_key'], (string) $agent['box_key_pending'], $body['box_public_key']) === 'pending') {
            // Not used until an admin approves it on the Agents page (compare the fingerprint with the agent's status).
            App::audit()->log('agent.key_change_pending', null, null, 'agent', (int) $agent['id'], ['client_id' => (int) $agent['client_id'],
                'fingerprint' => \Sentinel\AgentClient\AgentKey::fingerprint($body['box_public_key'])], $request->ip());
        }
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
        // Only a check-in that can act on them gets jobs and one-off requests: the agent says "idle" from its main loop,
        // and "not idle" from check-ins during a scan and from its status command (both ignore jobs and requests, so
        // anything handed to them would be lost). Older agents don't say: they get jobs when not running one, never
        // requests (they can't act on them).
        $idle = $body['idle'] ?? null;
        $requests = $idle === true ? App::agents()->takeRequests((int) $agent['id']) : [];
        if ($requests !== []) {
            App::audit()->log('agent.requests_handed_out', null, null, 'agent', (int) $agent['id'], ['client_id' => (int) $agent['client_id'], 'requests' => array_keys($requests)], $request->ip());
        }
        // An update request the agent reports back on: the helper's result (what it installed, or why not).
        if (is_array($body['update_result'] ?? null) && is_string($body['update_result']['version'] ?? null)) {
            $r = $body['update_result'];
            App::agents()->saveUpdateResult((int) $agent['id'], self::short($r['version'], 20), ($r['ok'] ?? false) === true, self::short($r['message'] ?? '', 300),
                self::short($body['version'] ?? '', 20), self::short($r['request'] ?? '', 30));
        }
        // Update: at an idle check-in, when an admin asked and the agent isn't on that version yet (signed by Sentinel's
        // key only to say "this server asks"; the code itself must carry the release key's signature). Alone, like a restart.
        $update = null;
        // Read again: the result just reported may have ended the request.
        $now = App::db()->query('SELECT update_to, update_requested_at FROM agents WHERE id = ' . (int) $agent['id'])->fetch();
        $updateTo = (string) ($now['update_to'] ?? '');
        if ($idle === true && !isset($requests['restart']) && $updateTo !== '' && $updateTo !== (string) ($body['version'] ?? '')) {
            $update = App::agentSigner()->sign(['v' => 1, 'type' => 'agent_update', 'agent_id' => (int) $agent['id'], 'site_id' => (int) $agent['site_id'],
                'client_id' => (int) $agent['client_id'], 'version' => $updateTo, 'request' => (string) $now['update_requested_at'], 'issued_at' => gmdate('Y-m-d\TH:i:s\Z')]);
        }
        // A restart or an update goes out alone: jobs in the same answer would be marked sent and never run.
        $giveJobs = !$paused && !isset($requests['restart']) && $update === null && ($idle === true || ($idle === null && $running === []));
        if ($giveJobs) {
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
        return ApiKernel::json(['jobs' => $jobs, 'stop' => array_values(array_unique($stop)), 'paused' => $paused,
                                'poll_seconds' => max(30, min(600, (int) ($agent['agent_poll_seconds'] ?? self::POLL_SECONDS)))] + $requests + ($update !== null ? ['update' => $update] : [])
            + self::secrets($agent, ($body['holds_directory'] ?? false) === true, is_string($body['directory_username'] ?? null) ? $body['directory_username'] : null));
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
     * Sealed directory passwords for this agent (signed, so the agent can tell they came through its pinned server),
     * and a signed instruction to delete the one it holds when its site no longer wants that.
     *
     * @param array<string,mixed> $agent
     * @return array<string,mixed>
     */
    private static function secrets(array $agent, bool $holds, ?string $heldUser): array
    {
        $out = [];
        $signer = App::agentSigner();
        foreach (App::directory()->dropsFor((int) $agent['id']) as $d) {
            $out['secrets'][] = $signer->sign(['v' => 1, 'type' => 'agent_secret', 'purpose' => 'directory_password', 'drop_id' => (int) $d['id'],
                'agent_id' => (int) $agent['id'], 'site_id' => (int) $agent['site_id'], 'client_id' => (int) $agent['client_id'],
                'nonce' => (string) $d['nonce'], 'username' => (string) $d['username'], 'sealed' => (string) $d['sealed'],
                'expires_at' => str_replace(' ', 'T', (string) $d['expires_at']) . 'Z']);
        }
        if ($holds && !isset($out['secrets']) && App::directory()->shouldForget((int) $agent['id'], (int) $agent['site_id'], $heldUser)) {
            $out['forget'] = $signer->sign(['v' => 1, 'type' => 'agent_forget', 'purpose' => 'directory_password', 'agent_id' => (int) $agent['id'],
                'site_id' => (int) $agent['site_id'], 'client_id' => (int) $agent['client_id'], 'issued_at' => gmdate('Y-m-d\TH:i:s\Z')]);
        }
        return $out;
    }

    /**
     * The update endpoints. Only an agent an admin asked to update gets the release, and only that version.
     *
     * @param array<string,mixed> $agent
     */
    private static function update(string $path, array $agent): Response
    {
        $body = self::body(8192) ?? [];
        $version = is_string($body['version'] ?? null) ? $body['version'] : '';
        if ($path === '/agent/v1/update/result') {
            App::agents()->saveUpdateResult((int) $agent['id'], self::short($version, 20), ($body['ok'] ?? false) === true, self::short($body['message'] ?? '', 300),
                (string) $agent['version'], self::short($body['request'] ?? '', 30));
            App::audit()->log('agent.update_reported', null, null, 'agent', (int) $agent['id'], ['client_id' => (int) $agent['client_id'], 'version' => self::short($version, 20), 'ok' => ($body['ok'] ?? false) === true]);
            return ApiKernel::json(['ok' => true]);
        }
        if ($version === '' || $version !== (string) ($agent['update_to'] ?? '')) {
            return ApiKernel::error(404, 'No update was asked for this agent.');
        }
        $release = App::agentRelease();
        if ($path === '/agent/v1/update/manifest') {
            $m = $release->manifestFor($version);
            return $m === null ? ApiKernel::error(404, 'No signed release of that version here.') : ApiKernel::json($m);
        }
        $file = is_string($body['path'] ?? null) ? $release->file($version, $body['path']) : null;
        return $file === null ? ApiKernel::error(404, 'Not part of the signed release.') : ApiKernel::json(['content' => base64_encode($file)]);
    }

    /**
     * POST /agent/v1/secrets/{id}/ack: the agent opened and kept a sealed password (ok true), or couldn't (error).
     *
     * @param array<string,mixed> $agent
     */
    private static function ackSecret(array $agent, int $dropId): Response
    {
        $body = self::body(4096) ?? [];
        $ok = ($body['ok'] ?? false) === true;
        if (!App::directory()->acknowledge((int) $agent['id'], $dropId, $ok, self::short($body['error'] ?? '', 200))) {
            return ApiKernel::error(404, 'Not found.');
        }
        App::audit()->log($ok ? 'agent.directory_password_received' : 'agent.directory_password_refused', null, null, 'agent', (int) $agent['id'], ['client_id' => (int) $agent['client_id'], 'site_id' => (int) $agent['site_id']]);
        return ApiKernel::json(['ok' => true]);
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
