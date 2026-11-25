<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Findings\FindingRepository;
use Sentinel\Findings\FixWorkflow;
use Sentinel\Findings\VerifyTarget;
use Sentinel\Scanning\PortProfile;

/**
 * Findings: the all-clients list (grouped by issue by default, 1.31: the same problem on several targets is one row),
 * one finding with its history, triage and the fix workflow (owner, due date, verify fix), and the same actions for a
 * whole group at once (bulk).
 *
 * Access (enforced by the routes): everyone signed in can view; technicians
 * and admins can triage, assign (to active technicians and admins) and
 * request a "verify fix" recheck; only admins set a finding's own due date.
 *
 * Untrusted: filter query parameters (checked against fixed lists), {id},
 * the triage status and note, the assignee, the due date and its note, the bulk list of finding IDs (each checked
 * exactly as a single action would be: a bulk action can't do anything one click at a time couldn't).
 *
 * Security assumptions: every change is recorded in the finding's history
 * and the audit log, and never deletes anything. A verify recheck touches
 * only the finding's own address and port (or domain), only while it is in
 * the client's active authorisation and scanning isn't paused; the worker
 * checks scope, pause and the kill switch again before it runs. At most one
 * verify per finding every 10 minutes, and a few queued per client.
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
            // "me" is turned into the signed-in user's ID; otherwise "none" or a user ID.
            'assignee' => match (true) {
                $request->query('assignee') === 'me' => (string) (int) $this->user()['id'],
                $request->query('assignee') === 'none' => 'none',
                ctype_digit($request->query('assignee')) && strlen($request->query('assignee')) < 10 => $request->query('assignee'),
                default => '',
            },
            'due' => in_array($request->query('due'), ['overdue', 'soon'], true) ? $request->query('due') : '',
            'source' => in_array($request->query('source'), FindingRepository::SOURCES, true) ? $request->query('source') : '',
            'group' => preg_match('/^[0-9a-f]{40}$/', $request->query('group')) === 1 ? $request->query('group') : '',
            'q' => \Sentinel\Search\SearchService::normalise($request->query('q')),
            'client_ids' => App::auth()->clientIds(), // only the user's clients (1.41)
        ];
        // Grouped by issue unless asked for one row per target (or showing one whole group).
        $grouped = $request->query('view') !== 'flat' && $filters['group'] === '';
        if ($filters['due'] !== '' && $request->query('status') === '') {
            $filters['status'] = 'open'; // only open findings are ever due
        }
        $page = max(1, min(10000, (int) $request->query('page')));
        $repo = App::findings();
        $result = $grouped ? $repo->searchGrouped($filters, $page) : $repo->search($filters, $page);
        return $this->page('findings/index', __('Findings'), [
            'filters' => $filters,
            'grouped' => $grouped,
            'rows' => $result['rows'] ?? [],
            'groups' => $result['groups'] ?? [],
            'total' => $result['total'],
            'page' => $page,
            'pages' => max(1, (int) ceil($result['total'] / ($grouped ? FindingRepository::GROUPS_PER_PAGE : FindingRepository::PAGE_SIZE))),
            'clients' => $repo->clientsWithFindings(App::auth()->clientIds()),
            'counts' => $repo->counts(null, App::auth()->clientIds()),
            'fixCounts' => App::fixWorkflow()->counts((int) $this->user()['id'], App::auth()->clientIds()),
            'assignable' => App::fixWorkflow()->assignableUsers(null, App::auth()->clientIds()),
        ]);
    }

    /** GET /findings/{id} */
    public function show(Request $request, array $params): Response
    {
        $finding = App::findings()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        return $this->showPage($finding, []);
    }

    /**
     * The finding page with its data (also used to show form errors).
     *
     * @param array<string,mixed> $finding
     * @param array<string,string> $errors
     * @param array<string,string> $values
     */
    private function showPage(array $finding, array $errors, array $values = [], int $status = 200): Response
    {
        // A breached address is shown in full only with 'breach.addresses' (1.40.1); others see it masked, as on the
        // client's Website & email page. The detail starts with the address (FindingsEngine).
        if ((string) $finding['finding_type'] === 'breach' && !App::auth()->can('breach.addresses')) {
            $finding['detail'] = (string) preg_replace_callback('/[^\s:;,]+@[^\s:;,]+/u',
                static fn (array $m): string => \Sentinel\Breach\BreachMonitor::masked($m[0]), (string) $finding['detail']);
        }
        return $this->page('findings/show', __('Finding #{id}', ['id' => $finding['id']]), [
            'finding' => $finding,
            'events' => App::findings()->events((int) $finding['id']),
            'errors' => $errors,
            'values' => $values + ['status' => '', 'note' => ''],
            'assignable' => App::fixWorkflow()->assignableUsers((int) $finding['client_id']),
            'verifiable' => VerifyTarget::fromKey((string) $finding['finding_key']) !== null,
            // The same "Why it matters / How to fix" text the client report shows (1.34).
            'guidance' => (static function (array $f): array {
                $vuln = [];
                if ((string) ($f['cve_id'] ?? '') !== '') {
                    $k = App::db()->prepare('SELECT required_action FROM kev_catalog WHERE cve_id = :c');
                    $k->execute(['c' => $f['cve_id']]);
                    $action = $k->fetchColumn();
                    $vuln = ['in_kev' => $action !== false ? 1 : 0, 'kev_action' => $action !== false ? (string) $action : ''];
                }
                return \Sentinel\Reports\Guidance::for($f, $vuln + $f);
            })($finding),
            // This finding's ITFlow tickets (the current one first, then ones it replaced), with a link to ITFlow's
            // agent view built from the ticket number (never ITFlow's guest link, which holds a secret key).
            'itflowTickets' => (static function (int $id): array {
                // A member shows its shared ticket's state (the leading row follows the ticket).
                $t = App::db()->prepare("SELECT t.reference, t.itflow_ticket_id, t.created_at,
                                                CASE WHEN t.kind = 'member' AND t.state = 'open' AND p.id IS NOT NULL THEN p.state ELSE t.state END AS state,
                                                CASE WHEN t.kind = 'member' AND p.id IS NOT NULL THEN p.itflow_status ELSE t.itflow_status END AS itflow_status,
                                                t.last_error, t.finding_id, c.itflow_client_id
                                         FROM itflow_tickets t JOIN clients c ON c.id = t.client_id LEFT JOIN itflow_tickets p ON p.id = t.parent_id
                                         WHERE t.kind IN ('finding', 'member') AND (t.finding_id = :f OR t.history_finding_id = :h) ORDER BY t.finding_id IS NULL, t.id DESC LIMIT 10");
                $t->execute(['f' => $id, 'h' => $id]);
                $base = App::settings()->get('itflow_url');
                $http = App::webhookTestMode();
                return array_map(static fn (array $r): array => $r + ['link' => (int) $r['itflow_ticket_id'] > 0 && $r['itflow_client_id'] !== null
                    ? \Sentinel\Itflow\ItflowClient::ticketUrl($base, (int) $r['itflow_client_id'], (int) $r['itflow_ticket_id'], $http) : ''], $t->fetchAll());
            })((int) $finding['id']),
        ], $status);
    }

    /** POST /findings/{id}/assign: assignee = a user ID, "me", or "" to unassign. */
    public function assign(Request $request, array $params): Response
    {
        $finding = App::findings()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $id = (int) $finding['id'];
        $me = (int) $this->user()['id'];
        $raw = $request->input('assignee');
        $assignee = $raw === 'me' ? $me : ($raw === '' ? null : (ctype_digit($raw) && strlen($raw) < 10 ? (int) $raw : -1));
        $note = $request->input('note');
        if ((int) $finding['client_archived'] === 1) {
            return $this->showPage($finding, ['assign' => __('This client is archived. Restore it before changing its findings.')], [], 422);
        }
        if ($finding['status'] === 'resolved') {
            return $this->showPage($finding, ['assign' => __('This finding is resolved: there is nothing to fix.')], [], 422);
        }
        if ($assignee !== null && ($assignee < 1 || !App::fixWorkflow()->isAssignable($assignee, (int) $finding['client_id']))) {
            return $this->showPage($finding, ['assign' => __('Choose an active user who can work on this client\'s findings.')], [], 422);
        }
        if (mb_strlen($note) > 500) {
            return $this->showPage($finding, ['assign' => __('The note can be up to 500 characters.')], [], 422);
        }
        $change = App::fixWorkflow()->assign($id, $assignee, $me, $note);
        if ($change === null) {
            Session::flash('info', __('Nothing changed.'));
            return Response::redirect('/findings/' . $id);
        }
        $this->audit($request, 'finding.assigned', 'finding', $id, ['client_id' => (int) $finding['client_id'], 'from' => $change['from'], 'to' => $change['to']]);
        if ($assignee !== null) {
            try {
                App::alerts()->findingAssigned($id, $assignee, $me);
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] assignment alert failed: ' . $ex->getMessage());
            }
        }
        Session::flash('success', $assignee === null ? __('Finding unassigned.') : ($assignee === $me ? __('You own this finding now.') : __('Finding assigned.')));
        return Response::redirect((string) $request->input('return') === 'list' ? '/findings?assignee=none' : '/findings/' . $id);
    }

    /** POST /findings/{id}/due (admins): a date (Y-m-d) for this finding, or reset=1 to follow the policy. */
    public function due(Request $request, array $params): Response
    {
        $finding = App::findings()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $id = (int) $finding['id'];
        $reset = $request->input('reset') === '1';
        $date = $request->input('due_date');
        $note = $request->input('due_note');
        $errors = [];
        if ((int) $finding['client_archived'] === 1) {
            $errors['due'] = __('This client is archived. Restore it before changing its findings.');
        } elseif (!$reset && !FixWorkflow::validDate($date)) {
            $errors['due'] = __('Enter a date (YYYY-MM-DD) within the next two years.');
        } elseif ($note === '' || mb_strlen($note) > 500) {
            $errors['due'] = __('A reason is required (up to 500 characters).');
        }
        if ($errors !== []) {
            return $this->showPage($finding, $errors, [], 422);
        }
        App::fixWorkflow()->setDue($id, $reset ? null : $date, (int) $this->user()['id'], $note);
        $this->audit($request, 'finding.due_changed', 'finding', $id, ['client_id' => (int) $finding['client_id'], 'from' => $finding['due_at'], 'to' => $reset ? 'policy' : $date, 'note' => mb_substr($note, 0, 300)]);
        Session::flash('success', $reset ? __('The due date follows the policy again.') : __('Due date set.'));
        return Response::redirect('/findings/' . $id);
    }

    /** Minimum time between two verify rechecks of the same finding. */
    private const VERIFY_INTERVAL = 600;
    /** Most verify rechecks queued or running at once for one client, and for the whole install. */
    private const VERIFY_MAX_QUEUED = 10;
    private const VERIFY_MAX_QUEUED_TOTAL = 50;

    /** POST /findings/{id}/verify: recheck just this finding now (outside the scan window too). */
    public function verify(Request $request, array $params): Response
    {
        $finding = App::findings()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $id = (int) $finding['id'];
        $clientId = (int) $finding['client_id'];
        $db = App::db();
        // Lock the client row, so two quick clicks (or two tabs) can't both pass the limits below.
        $db->beginTransaction();
        try {
            $lock = $db->prepare('SELECT id FROM clients WHERE id = :c FOR UPDATE');
            $lock->execute(['c' => $clientId]);
            $finding = App::findings()->find($id) ?? throw new HttpException(404);
            $result = $this->queueVerify($request, $finding);
            $db->commit();
        } catch (\Throwable $ex) {
            $db->rollBack();
            throw $ex;
        }
        if ($result !== null) {
            Session::flash('warning', $result);
        } else {
            Session::flash('success', App::auth()->can('scans.outside_window')
                ? __('Recheck queued. It runs within a minute (after any scan already running), and the result appears in the history.')
                : __('Recheck queued. It runs in the client\'s scan window (now, if the window is open), and the result appears in the history.'));
        }
        return Response::redirect('/findings/' . $id);
    }

    /**
     * Check the limits and queue a verify job (caller holds the client row lock).
     *
     * @param array<string,mixed> $finding Fresh, read under the lock.
     * @return string|null Why it can't be queued, or null when queued.
     */
    private function queueVerify(Request $request, array $finding): ?string
    {
        $id = (int) $finding['id'];
        $clientId = (int) $finding['client_id'];
        $client = App::clients()->find($clientId) ?? throw new HttpException(404);
        $target = VerifyTarget::fromKey((string) $finding['finding_key']);
        $db = App::db();
        $error = match (true) {
            $finding['status'] === 'resolved' => __('This finding is already resolved.'),
            (int) $client['is_archived'] === 1 => __('This client is archived.'),
            (int) ($client['is_demo'] ?? 0) === 1 => __('This is a demo client with made-up data: it is never scanned.'),
            (int) $client['scanning_paused'] === 1 || App::scope()->globallyPaused() => __('Scanning is paused, so nothing can be rechecked.'),
            $target === null => __('This finding can\'t be rechecked on its own. Run a scan of the client instead.'),
            !App::scope()->isInScope($clientId, $target['kind'] === 'email' ? $target['domain'] : $target['ip']) => __('This target is no longer in an active authorization, so it can\'t be rechecked.'),
            $target['kind'] === 'endpoint' && !in_array($target['port'], PortProfile::forClient($client), true) => __('Port {port} is no longer in this client\'s scan profile, so it can\'t be rechecked.', ['port' => $target['port']]),
            $finding['verify_status'] !== null && in_array($finding['verify_status'], ['queued', 'running'], true) => __('A recheck of this finding is already waiting or running.'),
            $finding['verify_requested_at'] !== null && strtotime($finding['verify_requested_at'] . ' UTC') > time() - self::VERIFY_INTERVAL => __('This finding was rechecked less than 10 minutes ago. Try again later.'),
            (int) $db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$clientId} AND job_type = 'verify' AND status IN ('queued','running')")->fetchColumn() >= self::VERIFY_MAX_QUEUED,
            (int) $db->query("SELECT COUNT(*) FROM scan_jobs WHERE job_type = 'verify' AND status IN ('queued','running')")->fetchColumn() >= self::VERIFY_MAX_QUEUED_TOTAL => __('Too many rechecks are waiting. Try again in a few minutes.'),
            default => null,
        };
        if ($error !== null) {
            return $error;
        }
        if ($target['kind'] === 'email') {
            $payload = ['finding_id' => $id, 'email_domain' => $target['domain']];
        } else {
            // Host names already known for this address (certificates and Host headers); the worker uses only in-scope ones.
            $stmt = $db->prepare('SELECT hostnames FROM assets WHERE client_id = :c AND ip = :ip');
            $stmt->execute(['c' => $clientId, 'ip' => $target['ip']]);
            $names = array_values(array_filter(explode(',', (string) $stmt->fetchColumn())));
            $payload = ['finding_id' => $id, 'ips' => [$target['ip']], 'hostnames' => [], 'ports' => [$target['port']], 'names' => [$target['ip'] => array_slice($names, 0, 20)]];
        }
        // Outside the client's scan window only with that permission (as for manual scans); otherwise it waits for the window.
        $outside = App::auth()->can('scans.outside_window');
        $jobId = App::scans()->queue($clientId, 'manual', (int) $this->user()['id'], $outside, __('Verify fix for finding #{id}', ['id' => $id]), $payload, 'verify');
        $db->prepare('UPDATE findings SET verify_requested_at = UTC_TIMESTAMP(), verify_job_id = :j WHERE id = :id')->execute(['j' => $jobId, 'id' => $id]);
        $db->prepare("INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, 'verify_requested', :u, :n, UTC_TIMESTAMP())")
            ->execute(['f' => $id, 'u' => (int) $this->user()['id'], 'n' => $target['kind'] === 'email' ? $target['domain'] : $target['ip'] . ' port ' . $target['port']]);
        $this->audit($request, 'finding.verify_requested', 'finding', $id, ['client_id' => $clientId, 'job_id' => $jobId]);
        return null;
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
            return $this->showPage($finding, $errors, ['status' => $status, 'note' => $note], 422);
        }
        $previous = App::findings()->triage($id, $status, $note, (int) $this->user()['id']);
        if ($previous === null) {
            Session::flash('info', __('Nothing changed: the finding already has that status, or it was resolved meanwhile.'));
            return Response::redirect('/findings/' . $id);
        }
        if ($status === 'open') {
            App::fixWorkflow()->recomputeDue((int) $finding['client_id']); // a reopened finding is due again (same deadline)
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

    /** Most findings one bulk action may touch. */
    private const BULK_MAX = 500;

    /**
     * POST /findings/bulk: the same action on several findings (a group in the list). action: assign | due (admins) |
     * triage | verify, with the same fields as the single actions. Each finding is checked exactly as a single action
     * would check it (archived client, resolved, limits), changed in its own transaction, and audited on its own (with
     * bulk: true); findings that can't be changed are skipped and counted.
     */
    public function bulk(Request $request, array $params): Response
    {
        $back = self::safeReturn($request->input('return'));
        $ids = array_values(array_unique(array_filter(array_map(static fn ($v): int => is_string($v) && ctype_digit($v) && strlen($v) < 10 ? (int) $v : 0,
            $request->postList('ids')), static fn (int $i): bool => $i > 0)));
        $action = $request->input('action');
        if ($ids === [] || count($ids) > self::BULK_MAX || !in_array($action, ['assign', 'due', 'triage', 'verify'], true)) {
            Session::flash('danger', __('Choose findings and an action (at most {n} findings at once).', ['n' => self::BULK_MAX]));
            return Response::redirect($back);
        }
        // Each action needs its own permission (the route lets in anyone holding one of them, 1.40).
        $need = ['assign' => 'findings.assign', 'due' => 'findings.due', 'triage' => 'findings.triage', 'verify' => 'findings.verify'][$action];
        if (!App::auth()->can($need)) {
            throw new HttpException(403, __('Your role does not allow this action.'));
        }
        $me = (int) $this->user()['id'];
        $note = $request->input('note');
        $done = 0;
        $skipped = 0;
        $reasons = [];
        // Validate the action's own fields once.
        if ($action === 'assign') {
            $raw = $request->input('assignee');
            $assignee = $raw === 'me' ? $me : ($raw === '' ? null : (ctype_digit($raw) && strlen($raw) < 10 ? (int) $raw : -1));
            if (($assignee !== null && ($assignee < 1 || !App::fixWorkflow()->isAssignable($assignee))) || mb_strlen($note) > 500) {
                Session::flash('danger', __('Choose an active user who can work on findings (and a note of up to 500 characters).'));
                return Response::redirect($back);
            }
        } elseif ($action === 'due') {
            $reset = $request->input('reset') === '1';
            $date = $request->input('due_date');
            if ((!$reset && !FixWorkflow::validDate($date)) || $note === '' || mb_strlen($note) > 500) {
                Session::flash('danger', __('Enter a date (YYYY-MM-DD) within the next two years, or reset it, and a reason (up to 500 characters).'));
                return Response::redirect($back);
            }
        } elseif ($action === 'triage') {
            $status = $request->input('status');
            if (!in_array($status, ['accepted', 'false_positive', 'open'], true) || $note === '' || mb_strlen($note) > 2000) {
                Session::flash('danger', __('Choose what to do and write a note (up to 2000 characters): explain why.'));
                return Response::redirect($back);
            }
        }
        $assignedFirst = null;
        $assignedCount = 0;
        $clientsTouched = [];
        foreach ($ids as $id) {
            $finding = App::findings()->find($id);
            // A finding of a client the user doesn't see is treated as missing (1.41).
            if ($finding === null || (int) $finding['client_archived'] === 1 || !App::auth()->canSeeClient((int) $finding['client_id'])) {
                $skipped++;
                continue;
            }
            $cid = (int) $finding['client_id'];
            if ($action === 'verify') {
                $db = App::db();
                $db->beginTransaction();
                try {
                    $lock = $db->prepare('SELECT id FROM clients WHERE id = :c FOR UPDATE');
                    $lock->execute(['c' => $cid]);
                    $fresh = App::findings()->find($id);
                    $why = $fresh === null ? __('This finding no longer exists.') : $this->queueVerify($request, $fresh);
                    $db->commit();
                } catch (\Throwable $ex) {
                    $db->rollBack();
                    // One finding that can't be queued never stops the rest (the earlier ones are already queued).
                    error_log('[msp-sentinel] bulk verify of finding ' . $id . ' failed: ' . $ex->getMessage());
                    $why = __('Not possible for this finding.');
                }
                if ($why === null) {
                    $done++;
                } else {
                    $skipped++;
                    $reasons[$why] = ($reasons[$why] ?? 0) + 1;
                }
                continue;
            }
            if ($finding['status'] === 'resolved') {
                $skipped++;
                continue;
            }
            if ($action === 'assign') {
                if ($assignee !== null && !App::fixWorkflow()->isAssignable($assignee, $cid)) {
                    $skipped++; // the chosen owner doesn't see this client
                    continue;
                }
                $change = App::fixWorkflow()->assign($id, $assignee, $me, $note);
                if ($change === null) {
                    $skipped++;
                    continue;
                }
                $this->audit($request, 'finding.assigned', 'finding', $id, ['client_id' => $cid, 'from' => $change['from'], 'to' => $change['to'], 'bulk' => true]);
                $assignedFirst ??= $id;
                $assignedCount++;
            } elseif ($action === 'due') {
                App::fixWorkflow()->setDue($id, $reset ? null : $date, $me, $note, !$reset);
                $clientsTouched[$cid] = true;
                $this->audit($request, 'finding.due_changed', 'finding', $id, ['client_id' => $cid, 'from' => $finding['due_at'], 'to' => $reset ? 'policy' : $date,
                    'note' => mb_substr($note, 0, 300), 'bulk' => true]);
            } else {
                $previous = App::findings()->triage($id, $status, $note, $me);
                if ($previous === null) {
                    $skipped++;
                    continue;
                }
                $clientsTouched[$cid] = true;
                $this->audit($request, 'finding.triaged', 'finding', $id, ['client_id' => $cid, 'from' => $previous, 'to' => $status, 'note' => mb_substr($note, 0, 300), 'bulk' => true]);
                App::events()->publish('finding.triaged', (App::events()->finding($id) ?? []) + ['previous_status' => $previous]);
            }
            $done++;
        }
        if ($action === 'due' && $reset) {
            foreach (array_keys($clientsTouched) as $cid) {
                App::fixWorkflow()->recomputeDue($cid); // once per client, not once per finding
            }
        }
        if ($action === 'triage' && $status === 'open') {
            foreach (array_keys($clientsTouched) as $cid) {
                App::fixWorkflow()->recomputeDue($cid); // reopened findings are due again
            }
        }
        // One email for the whole group, not one per finding.
        if ($action === 'assign' && $assignee !== null && $assignedFirst !== null) {
            try {
                App::alerts()->findingAssigned($assignedFirst, $assignee, $me, $assignedCount - 1);
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] assignment alert failed: ' . $ex->getMessage());
            }
        }
        $msg = __('{n} finding(s) updated.', ['n' => $done]) . ($skipped > 0 ? ' ' . __('{n} skipped (resolved, archived, unchanged or not possible).', ['n' => $skipped]) : '');
        foreach (array_slice($reasons, 0, 3, true) as $why => $n) {
            $msg .= ' ' . $why . ' (' . $n . ')';
        }
        Session::flash($done > 0 ? 'success' : 'warning', $msg);
        return Response::redirect($back);
    }

    /** Where to go back after a bulk action: only the findings list, with its own query string. */
    private static function safeReturn(string $raw): string
    {
        return preg_match('#^/findings(\?[A-Za-z0-9_=&%.\-]*)?$#D', $raw) === 1 ? $raw : '/findings';
    }
}
