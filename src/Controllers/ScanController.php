<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\Role;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Scanning\NmapRunner;

/**
 * Queue and cancel port scans. The web request NEVER runs nmap itself: it
 * only adds a job to the queue, and the CLI worker (cron) runs it.
 *
 * Access (enforced by the routes): technicians and admins. Only admins may
 * tick "run outside the scan window", and they must give a reason, which is audited.
 *
 * Untrusted: {id} path parameters, the override checkbox and the reason.
 *
 * Security assumptions: a job is only queued when the client has an active
 * scope and scanning isn't paused. The worker re-checks everything right
 * before each host anyway.
 */
final class ScanController extends Controller
{
    /** POST /clients/{id}/scan */
    public function queue(Request $request, array $params): Response
    {
        $client = App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $clientId = (int) $client['id'];
        $back = Response::redirect('/clients/' . $clientId . '#scans');
        $user = $this->user();

        if ((int) $client['is_archived'] === 1 || (int) $client['scanning_paused'] === 1 || App::scope()->globallyPaused()) {
            Session::flash('danger', __('Scanning is paused or the client is archived, so no scan can be queued.'));
            return $back;
        }
        if (!NmapRunner::fromConfig(App::config())->available()) {
            Session::flash('danger', __('nmap is not installed (or scanner.nmap_path is wrong). Ask the server administrator to install it.'));
            return $back;
        }
        $outside = $request->input('outside_window') === '1';
        $reason = $request->input('reason');
        if ($outside) {
            if (!Role::atLeast((string) $user['role'], Role::ADMIN)) {
                throw new HttpException(403);
            }
            if ($reason === '' || mb_strlen($reason) > 300) {
                Session::flash('danger', __('Give a reason (up to 300 characters) for scanning outside the client\'s window.'));
                return $back;
            }
        }
        if ((int) ($client['is_demo'] ?? 0) === 1) {
            Session::flash('info', __('This is a demo client with made-up data: it is never scanned.'));
            return $back;
        }
        $payload = App::scanWorker()->payloadFor($client);
        if ($payload === null) {
            Session::flash('danger', __('There is nothing to scan: the client has no active authorisation with IP addresses or exact hostnames.'));
            return $back;
        }
        // Check-and-insert under a row lock on the client, so two quick clicks can't queue two scans.
        $db = App::db();
        $db->beginTransaction();
        try {
            $db->prepare('SELECT id FROM clients WHERE id = :id FOR UPDATE')->execute(['id' => $clientId]);
            App::scans()->cancelQueuedTlsJobs($clientId); // a port scan includes the certificate checks
            if (App::scans()->openJob($clientId) !== null) {
                $db->rollBack();
                Session::flash('info', __('A scan for this client is already queued or running.'));
                return $back;
            }
            $jobId = App::scans()->queue($clientId, 'manual', (int) $user['id'], $outside, $outside ? $reason : null, $payload);
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $ex;
        }
        $this->audit($request, 'scan.queued', 'scan_job', $jobId, [
            'client_id' => $clientId, 'targets' => count($payload['ips']) + count($payload['hostnames']),
            'outside_window' => $outside, 'reason' => $outside ? $reason : null,
        ]);
        Session::flash('success', $outside
            ? __('Scan queued to run as soon as the worker picks it up (outside the window).')
            : __('Scan queued. It will run in the client\'s scan window.'));
        return $back;
    }

    /** POST /scans/{id}/cancel */
    public function cancel(Request $request, array $params): Response
    {
        $job = App::scans()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $result = App::scans()->cancel((int) $job['id']);
        if ($result === 'cancelled') {
            \Sentinel\Findings\VerifyOutcome::recordAborted(App::db(), $job, __('the recheck was cancelled by a user.'));
        }
        if ($result !== 'not_open') {
            $this->audit($request, 'scan.cancelled', 'scan_job', (int) $job['id'], ['client_id' => (int) $job['client_id'], 'was' => $job['status']]);
        }
        Session::flash($result === 'not_open' ? 'info' : 'warning', match ($result) {
            'cancelled' => __('Queued scan cancelled.'),
            'requested' => __('The running scan will stop within a few seconds.'),
            default => __('This scan is no longer running.'),
        });
        return Response::redirect('/clients/' . (int) $job['client_id'] . '#scans');
    }
}
