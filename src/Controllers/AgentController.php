<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use DateTimeImmutable;
use Sentinel\Agent\AgentService;
use Sentinel\Agent\InternalRanges;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Scope\ScopeService;

/**
 * On-premises agents on the client page: internal authorisations per site,
 * enrolment codes, revoking agents, a kill switch per site, and "scan now".
 *
 * Access (enforced by the routes): technicians may pause a site; admins do
 * everything else (record and revoke authorisations, enrol and revoke
 * agents, resume, scan now).
 *
 * Untrusted: {id}, {site}, {auth}, {agent} (each checked to belong to the
 * client), and form values (validated like external authorisations; ranges
 * must be private networks of limited size).
 *
 * Security assumptions: internal authorisations are signed when recorded
 * and can only be revoked, never edited. An enrolment code is shown once,
 * on a page that is never cached, and works once for 24 hours. Every change
 * is in the audit log.
 */
final class AgentController extends Controller
{
    /** GET /clients/{id}/sites/{site}/internal-authorisations/new */
    public function authorisationForm(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        $today = ScopeService::today((string) $client['timezone']);
        return $this->page('agents/authorisation', __('Internal authorisation for {site}', ['site' => $site['name']]), [
            'client' => $client, 'site' => $site, 'errors' => [],
            'values' => ['approved_by_name' => '', 'approved_by_role' => '', 'approved_on' => $today, 'valid_from' => $today,
                         'valid_until' => (new DateTimeImmutable($today))->modify('+1 year')->format('Y-m-d'), 'document_ref' => '', 'notes' => '', 'ranges' => '', 'confirm' => ''],
        ]);
    }

    /** POST /clients/{id}/sites/{site}/internal-authorisations */
    public function storeAuthorisation(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        if ((int) $client['is_archived'] === 1) {
            Session::flash('danger', __('Restore the client before recording a new authorisation.'));
            return Response::redirect('/clients/' . (int) $client['id']);
        }
        $today = ScopeService::today((string) $client['timezone']);
        $values = [];
        foreach (['approved_by_name', 'approved_by_role', 'approved_on', 'valid_from', 'valid_until', 'document_ref', 'notes', 'confirm'] as $f) {
            $values[$f] = $request->input($f);
        }
        $values['ranges'] = $request->raw('ranges');
        $errors = [];
        foreach (['approved_by_name' => __('Enter the name of the person at the client who approved scanning.'), 'approved_by_role' => __('Enter their role, e.g. Managing Director or IT Manager.')] as $f => $msg) {
            if ($values[$f] === '' || mb_strlen($values[$f]) > 150 || preg_match('/[\x00-\x1F\x7F]/u', $values[$f])) {
                $errors[$f] = $msg;
            }
        }
        foreach (['approved_on', 'valid_from', 'valid_until'] as $f) {
            $d = DateTimeImmutable::createFromFormat('!Y-m-d', $values[$f]);
            if ($d === false || $d->format('Y-m-d') !== $values[$f]) {
                $errors[$f] = __('Enter a date (YYYY-MM-DD).');
            }
        }
        if (!isset($errors['approved_on']) && $values['approved_on'] > $today) {
            $errors['approved_on'] = __('The approval date cannot be in the future.');
        }
        if (!isset($errors['valid_from']) && !isset($errors['valid_until'])) {
            if ($values['valid_until'] < $values['valid_from']) {
                $errors['valid_until'] = __('The end date must be on or after the start date.');
            } elseif ($values['valid_until'] > (new DateTimeImmutable($values['valid_from']))->modify('+2 years')->format('Y-m-d')) {
                $errors['valid_until'] = __('An authorisation can be valid for at most 2 years. Ask the client to renew it after that.');
            } elseif ($values['valid_until'] < $today) {
                $errors['valid_until'] = __('The end date is in the past.');
            }
        }
        if (mb_strlen($values['document_ref']) > 190) {
            $errors['document_ref'] = __('At most 190 characters.');
        }
        if (mb_strlen($values['notes']) > 2000) {
            $errors['notes'] = __('Notes can be at most 2000 characters.');
        }
        $parsed = InternalRanges::parseLines(mb_substr($values['ranges'], 0, 20000));
        if ($parsed['errors'] !== []) {
            $errors['ranges'] = implode("\n", array_slice($parsed['errors'], 0, 20));
        } elseif ($parsed['ranges'] === []) {
            $errors['ranges'] = __('Enter at least one internal network or address.');
        }
        if ($values['confirm'] !== '1') {
            $errors['confirm'] = __('Confirm that the client approved scanning these internal networks.');
        }
        if ($errors !== []) {
            return $this->page('agents/authorisation', __('Internal authorisation for {site}', ['site' => $site['name']]), ['client' => $client, 'site' => $site, 'errors' => $errors, 'values' => $values], 422);
        }
        $id = App::agents()->createAuthorisation((int) $client['id'], (int) $site['id'], (string) $client['timezone'], $values, $parsed['ranges'], (int) $this->user()['id']);
        $this->audit($request, 'internal_authorisation.created', 'internal_authorisation', $id, ['client_id' => (int) $client['id'], 'site_id' => (int) $site['id'],
            'ranges' => $parsed['ranges'], 'valid_from' => $values['valid_from'], 'valid_until' => $values['valid_until'], 'approved_by' => $values['approved_by_name']]);
        Session::flash('success', __('Internal authorisation recorded and signed. Agents at this site may now scan these networks.'));
        return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
    }

    /** POST /clients/{id}/internal-authorisations/{auth}/revoke */
    public function revokeAuthorisation(Request $request, array $params): Response
    {
        $client = $this->client($params);
        $stmt = App::db()->prepare('SELECT id FROM internal_authorisations WHERE id = :a AND client_id = :c AND revoked_at IS NULL');
        $stmt->execute(['a' => (int) ($params['auth'] ?? 0), 'c' => (int) $client['id']]);
        $id = (int) $stmt->fetchColumn();
        $reason = $request->input('reason');
        if ($id === 0) {
            throw new HttpException(404);
        }
        if ($reason === '' || mb_strlen($reason) > 500) {
            Session::flash('danger', __('Give a reason for revoking (up to 500 characters).'));
            return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
        }
        App::agents()->revokeAuthorisation($id, (int) $this->user()['id'], $reason);
        $this->audit($request, 'internal_authorisation.revoked', 'internal_authorisation', $id, ['client_id' => (int) $client['id'], 'reason' => mb_substr($reason, 0, 300)]);
        Session::flash('warning', __('Authorisation revoked. Running agent scans under it stop at their next check-in.'));
        return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
    }

    /** POST /clients/{id}/sites/{site}/enrol: a one-time enrolment code, shown once. */
    public function enrol(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        if ((int) $client['is_archived'] === 1) {
            throw new HttpException(400, __('This client is archived.'));
        }
        $code = App::agents()->createEnrolment((int) $client['id'], (int) $site['id'], (int) $this->user()['id']);
        $this->audit($request, 'agent.enrolment_created', 'site', (int) $site['id'], ['client_id' => (int) $client['id']]);
        $url = rtrim((string) App::config()->get('app.public_url', ''), '/');
        return $this->page('agents/enrolment', __('Enrol an agent for {site}', ['site' => $site['name']]), [
            'client' => $client, 'site' => $site, 'code' => $code, 'serverUrl' => $url,
        ])->header('Cache-Control', 'no-store');
    }

    /** POST /clients/{id}/agents/{agent}/revoke */
    public function revokeAgent(Request $request, array $params): Response
    {
        $client = $this->client($params);
        $stmt = App::db()->prepare("SELECT id FROM agents WHERE id = :a AND client_id = :c AND status = 'active'");
        $stmt->execute(['a' => (int) ($params['agent'] ?? 0), 'c' => (int) $client['id']]);
        $id = (int) $stmt->fetchColumn();
        if ($id === 0) {
            throw new HttpException(404);
        }
        App::agents()->revokeAgent($id, (int) $this->user()['id']);
        $this->audit($request, 'agent.revoked', 'agent', $id, ['client_id' => (int) $client['id']]);
        Session::flash('warning', __('Agent revoked. Its token no longer works; uninstall it from the device.'));
        return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
    }

    /** POST /clients/{id}/sites/{site}/pause (technicians and admins): stop agent scans at this site now. */
    public function pause(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        App::agents()->pauseSite((int) $site['id']);
        $this->audit($request, 'site.paused', 'site', (int) $site['id'], ['client_id' => (int) $client['id']]);
        Session::flash('warning', __('Agent scans at {site} are paused. Running scans stop at the agent\'s next check-in (within a minute).', ['site' => $site['name']]));
        return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
    }

    /** POST /clients/{id}/sites/{site}/resume (admins). */
    public function resume(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        App::db()->prepare('UPDATE sites SET scanning_paused = 0, updated_at = UTC_TIMESTAMP() WHERE id = :s')->execute(['s' => (int) $site['id']]);
        $this->audit($request, 'site.resumed', 'site', (int) $site['id'], ['client_id' => (int) $client['id']]);
        Session::flash('success', __('Agent scans at {site} resumed.', ['site' => $site['name']]));
        return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
    }

    /** POST /clients/{id}/sites/{site}/scan (admins): a full agent scan now, outside the window too, with a reason. */
    public function scan(Request $request, array $params): Response
    {
        [$client, $site] = $this->clientSite($params);
        $reason = $request->input('reason');
        $agent = App::db()->prepare("SELECT id FROM agents WHERE site_id = :s AND status = 'active' ORDER BY id DESC LIMIT 1");
        $agent->execute(['s' => (int) $site['id']]);
        $agentId = (int) $agent->fetchColumn();
        $auth = App::agents()->activeAuthorisation((int) $site['id'], ScopeService::today((string) $client['timezone']));
        $error = match (true) {
            (int) $client['is_archived'] === 1 => __('This client is archived.'),
            (int) $client['scanning_paused'] === 1 || (int) $site['scanning_paused'] === 1 || App::scope()->globallyPaused() => __('Scanning is paused.'),
            $agentId === 0 => __('This site has no active agent.'),
            $auth === null => __('This site has no valid internal authorisation.'),
            App::agents()->openJobs((int) $site['id']) > 0 => __('An agent scan for this site is already waiting or running.'),
            $reason === '' || mb_strlen($reason) > 300 => __('Give a reason (up to 300 characters).'),
            default => null,
        };
        if ($error !== null) {
            Session::flash('warning', $error);
            return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
        }
        $jobId = App::agents()->queueJob($agentId, (int) $client['id'], (int) $site['id'], (int) $auth['id'], 'full', 'manual', (int) $this->user()['id'], AgentService::PORTS, AgentService::JOB_HOURS);
        $this->audit($request, 'agent.scan_requested', 'agent_job', $jobId, ['client_id' => (int) $client['id'], 'site_id' => (int) $site['id'], 'reason' => mb_substr($reason, 0, 300)]);
        Session::flash('success', __('Scan queued. The agent picks it up at its next check-in (within a minute).'));
        return Response::redirect('/clients/' . (int) $client['id'] . '#agents');
    }

    /**
     * The client from {id}.
     *
     * @return array<string,mixed>
     */
    private function client(array $params): array
    {
        return App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }

    /**
     * The client and one of its sites ({site} must belong to {id}).
     *
     * @return array{0:array<string,mixed>, 1:array<string,mixed>}
     */
    private function clientSite(array $params): array
    {
        $client = $this->client($params);
        $stmt = App::db()->prepare('SELECT * FROM sites WHERE id = :s AND client_id = :c');
        $stmt->execute(['s' => (int) ($params['site'] ?? 0), 'c' => (int) $client['id']]);
        $site = $stmt->fetch();
        if ($site === false) {
            throw new HttpException(404);
        }
        return [$client, $site];
    }
}
