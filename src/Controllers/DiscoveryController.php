<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Discovery\DnsException;

/**
 * Target discovery actions: run discovery now, dismiss or restore a suggestion.
 *
 * Access (enforced by the routes): technicians and admins. Turning
 * suggestions into scope needs an admin (AuthorisationController).
 *
 * Untrusted: {id} path parameters.
 *
 * Security assumptions: discovery is passive (DNS and certificate logs) and
 * refuses to run for archived or paused clients, when scanning is paused
 * globally, or when there is no active authorisation. Manual runs have a time
 * budget, so a web request can't hang for minutes.
 */
final class DiscoveryController extends Controller
{
    /** POST /clients/{id}/discover */
    public function run(Request $request, array $params): Response
    {
        $client = App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $clientId = (int) $client['id'];
        try {
            $service = App::discovery();
        } catch (DnsException | \InvalidArgumentException $ex) {
            // Missing or invalid dns.resolver / crtsh.base_url in the config file.
            Session::flash('danger', __('Discovery is not configured correctly: {e}', ['e' => $ex->getMessage()]));
            return Response::redirect('/clients/' . $clientId . '/discovery');
        }
        @set_time_limit(60);
        $budget = (float) App::config()->get('discovery.manual_budget', 25);
        $result = $service->run($clientId, 'manual', (int) $this->user()['id'], $budget);
        if ($result['status'] !== 'refused') {
            $this->audit($request, 'discovery.run', 'client', $clientId, ['status' => $result['status'], 'new' => $result['new'], 'run_id' => $result['run_id']]);
        }
        $type = match ($result['status']) {
            'ok' => 'success',
            'partial' => 'warning',
            default => 'danger',
        };
        Session::flash($type, $result['message']);
        return Response::redirect('/clients/' . $clientId . '/discovery');
    }

    /** POST /suggestions/{id}/dismiss */
    public function dismiss(Request $request, array $params): Response
    {
        return $this->setStatus($request, $params, 'dismissed');
    }

    /** POST /suggestions/{id}/restore */
    public function restore(Request $request, array $params): Response
    {
        return $this->setStatus($request, $params, 'pending');
    }

    /** Dismiss or restore one suggestion (accepted ones can't be changed here). */
    private function setStatus(Request $request, array $params, string $status): Response
    {
        $suggestion = App::suggestions()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $clientId = (int) $suggestion['client_id'];
        $client = App::clients()->find($clientId);
        if ($client === null || (int) $client['is_archived'] === 1) {
            Session::flash('info', __('Restore the client first.'));
            return Response::redirect('/clients/' . $clientId . '/discovery');
        }
        if ($suggestion['status'] === 'accepted') {
            Session::flash('info', __('This suggestion is already part of an authorization.'));
            return Response::redirect('/clients/' . $clientId . '/discovery');
        }
        App::suggestions()->setStatus((int) $suggestion['id'], $status, (int) $this->user()['id']);
        $this->audit($request, $status === 'dismissed' ? 'suggestion.dismissed' : 'suggestion.restored', 'suggestion', (int) $suggestion['id'],
            ['client_id' => $clientId, 'value' => $suggestion['value']]);
        return Response::redirect('/clients/' . $clientId . '/discovery');
    }
}
