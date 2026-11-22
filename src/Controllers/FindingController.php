<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Findings\FindingRepository;

/**
 * Findings: the all-clients list, one finding with its history, and triage.
 *
 * Access (enforced by the routes): everyone signed in can view; technicians
 * and admins can triage (accepted risk, false positive, or back to open).
 *
 * Untrusted: filter query parameters (checked against fixed lists), {id},
 * the triage status and note.
 *
 * Security assumptions: triage always needs a note, is recorded in the
 * finding's history and the audit log, and never deletes anything.
 */
final class FindingController extends Controller
{
    /** GET /findings */
    public function index(Request $request): Response
    {
        $filters = [
            'client' => ctype_digit($request->query('client')) ? (int) $request->query('client') : 0,
            'status' => in_array($request->query('status'), FindingRepository::STATUSES, true) ? $request->query('status') : ($request->query('status') === 'all' ? '' : 'open'),
            'severity' => in_array($request->query('severity'), FindingRepository::SEVERITIES, true) ? $request->query('severity') : '',
            'type' => in_array($request->query('type'), FindingRepository::TYPES, true) ? $request->query('type') : '',
        ];
        $page = max(1, min(10000, (int) $request->query('page')));
        $repo = App::findings();
        $result = $repo->search($filters, $page);
        return $this->page('findings/index', __('Findings'), [
            'filters' => $filters,
            'rows' => $result['rows'],
            'total' => $result['total'],
            'page' => $page,
            'pages' => max(1, (int) ceil($result['total'] / FindingRepository::PAGE_SIZE)),
            'clients' => $repo->clientsWithFindings(),
            'counts' => $repo->counts(),
        ]);
    }

    /** GET /findings/{id} */
    public function show(Request $request, array $params): Response
    {
        $finding = App::findings()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        return $this->page('findings/show', __('Finding #{id}', ['id' => $finding['id']]), [
            'finding' => $finding,
            'events' => App::findings()->events((int) $finding['id']),
            'errors' => [],
        ]);
    }

    /** POST /findings/{id}/triage */
    public function triage(Request $request, array $params): Response
    {
        $finding = App::findings()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $id = (int) $finding['id'];
        $status = $request->input('status');
        $note = $request->input('note');
        $errors = [];
        if (!in_array($status, ['accepted', 'false_positive', 'open'], true)) {
            $errors['status'] = __('Choose what to do with this finding.');
        }
        if ($note === '' || mb_strlen($note) > 2000) {
            $errors['note'] = __('A note is required (up to 2000 characters): explain why.');
        }
        if ($finding['status'] === 'resolved') {
            $errors['status'] = __('This finding is resolved: the latest checks no longer see it, so there is nothing to triage.');
        }
        if ((int) $finding['client_archived'] === 1) {
            $errors['status'] = __('This client is archived. Restore it before changing its findings.');
        }
        if ($errors !== []) {
            return $this->page('findings/show', __('Finding #{id}', ['id' => $id]), [
                'finding' => $finding, 'events' => App::findings()->events($id), 'errors' => $errors, 'values' => ['status' => $status, 'note' => $note],
            ], 422);
        }
        $previous = App::findings()->triage($id, $status, $note, (int) $this->user()['id']);
        if ($previous === null) {
            Session::flash('info', __('Nothing changed: the finding already has that status, or it was resolved meanwhile.'));
            return Response::redirect('/findings/' . $id);
        }
        $this->audit($request, 'finding.triaged', 'finding', $id, ['client_id' => (int) $finding['client_id'], 'from' => $previous, 'to' => $status, 'note' => mb_substr($note, 0, 300)]);
        App::events()->publish('finding.triaged', (App::events()->finding($id) ?? []) + ['previous_status' => $previous]);
        Session::flash('success', match ($status) {
            'accepted' => __('Marked as accepted risk.'),
            'false_positive' => __('Marked as false positive. It reopens automatically if the evidence changes.'),
            default => __('Finding reopened.'),
        });
        return Response::redirect('/findings/' . $id);
    }
}
