<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use DateTimeImmutable;
use DateTimeZone;
use Sentinel\Agent\InternalRanges;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Engagements\EngagementRepository;
use Sentinel\Scope\IpRange;
use Sentinel\Scope\ScopeService;

/**
 * Pen-test engagements: create (with the client's signed authorisation), approve (a different admin), stop (kill
 * switch), cancel (before approval), and the signed document.
 *
 * Access (enforced by the routes): technicians and admins create, stop, cancel and download the document; only admins
 * approve, and never their own (two-person rule, also enforced in the UPDATE); everyone signed in can view.
 *
 * Untrusted: every form field, the uploaded file (only a PDF up to 10 MB is kept, by its SHA-256, never served
 * inline), {id}. Targets are parsed strictly and must lie inside the client's ACTIVE authorised scope (external) and
 * the site's active internal authorisation (internal): an engagement never widens what may be tested.
 *
 * Security assumptions: an approved engagement can't be edited, only stopped; every action is audited; the window is
 * entered in the client's timezone and stored in UTC.
 */
final class EngagementController extends Controller
{
    public const MAX_DOC_BYTES = 10485760;

    /** Labels for the test types (EngagementRepository::TESTS). @return array<string,string> */
    public static function testLabels(): array
    {
        return [
            'tcp_full' => __('All 65,535 TCP ports (instead of the usual list)'),
            'udp_common' => __('Common UDP services: one read-only request each to SNMP (default communities), NTP and SSDP/UPnP'),
            'nse_safe' => __('nmap\'s "safe" service scripts (details of each service; no vulnerability or intrusive checks)'),
            'anon_access' => __('Anonymous access checks (anonymous FTP login, NFS exports, SMB file shares through an anonymous session: share list and top-folder item counts; read only)'),
            'default_creds' => __('Vendor default passwords: at most 3 per service (FTP, web admin pages with Basic login, MySQL/MariaDB, PostgreSQL), each a different account, 5 seconds apart, stopping at any lockout; and databases open without a password (Redis, MongoDB, Elasticsearch, Memcached)'),
        ];
    }

    /** GET /clients/{id}/engagements/new */
    public function create(Request $request, array $params): Response
    {
        $client = $this->clientOr404($params);
        return $this->form($client, ['intensity' => 'gentle', 'tests' => ['nse_safe', 'anon_access']], []);
    }

    /** POST /clients/{id}/engagements (multipart: the signed document) */
    public function store(Request $request, array $params): Response
    {
        $client = $this->clientOr404($params);
        $clientId = (int) $client['id'];
        if ((int) $client['is_archived'] === 1 || (int) ($client['is_demo'] ?? 0) === 1) {
            throw new HttpException(400, __('Engagements are not possible for archived or demo clients.'));
        }
        $tz = new DateTimeZone((string) $client['timezone']);
        $today = ScopeService::today((string) $client['timezone']);
        $v = [];
        foreach (['name', 'signer_name', 'signer_role', 'signed_on', 'window_start', 'window_end', 'intensity', 'notes', 'confirm', 'creds_confirm'] as $f) {
            $v[$f] = $request->input($f);
        }
        $v['external'] = mb_substr($request->raw('external'), 0, 20000);
        $v['exclusions'] = mb_substr($request->raw('exclusions'), 0, 20000);
        $v['tests'] = array_values(array_intersect(EngagementRepository::TESTS, $request->postList('tests')));
        $v['retest_of'] = $request->input('retest_of');
        $sites = App::clients()->sites($clientId);
        foreach ($sites as $s) {
            $v['internal'][(int) $s['id']] = mb_substr($request->raw('internal_' . (int) $s['id']), 0, 20000);
        }
        $errors = [];
        foreach (['name' => [__('Name the engagement, e.g. "Annual internal test 2027".'), 150], 'signer_name' => [__('Enter who at the client signed the authorisation.'), 150],
                  'signer_role' => [__('Enter their role.'), 150]] as $f => [$msg, $max]) {
            if ($v[$f] === '' || mb_strlen($v[$f]) > $max || preg_match('/[\x00-\x1F\x7F]/u', $v[$f])) {
                $errors[$f] = $msg;
            }
        }
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $v['signed_on']) !== 1 || !checkdate((int) substr($v['signed_on'], 5, 2), (int) substr($v['signed_on'], 8, 2), (int) substr($v['signed_on'], 0, 4))) {
            $errors['signed_on'] = __('Enter the date it was signed (YYYY-MM-DD).');
        } elseif ($v['signed_on'] > $today) {
            $errors['signed_on'] = __('The signing date cannot be in the future.');
        }
        if (!in_array($v['intensity'], EngagementRepository::INTENSITIES, true)) {
            $errors['intensity'] = __('Choose how hard the tests may push.');
        }
        if ($v['tests'] === []) {
            $errors['tests'] = __('Choose at least one test.');
        } elseif (in_array('tcp_full', $v['tests'], true) && $v['intensity'] === 'gentle') {
            // Gentle timing waits between probes: 65,535 ports would take about 7 hours per host and never finish.
            $errors['intensity'] = __('All 65,535 ports need the normal pace (gentle would take about 7 hours per host). Choose normal, or untick all ports.');
        }
        $retestOf = null;
        if ($v['retest_of'] !== '') {
            $prev = ctype_digit($v['retest_of']) ? App::engagements()->find((int) $v['retest_of']) : null;
            if ($prev === null || (int) $prev['client_id'] !== $clientId || $prev['approved_at'] === null) {
                $errors['retest_of'] = __('Choose an earlier approved engagement of this client.');
            } else {
                $retestOf = (int) $prev['id'];
            }
        }
        if (mb_strlen($v['notes']) > 5000) {
            $errors['notes'] = __('Notes are too long.');
        }

        // The window, in the client's timezone.
        $parseTime = static function (string $s) use ($tz): ?DateTimeImmutable {
            $d = preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/', $s) === 1 ? DateTimeImmutable::createFromFormat('Y-m-d\TH:i', $s, $tz) : false;
            return $d === false ? null : $d;
        };
        $start = $parseTime($v['window_start']);
        $end = $parseTime($v['window_end']);
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        if ($start === null || $end === null) {
            $errors['window'] = __('Enter when testing may start and when it must end.');
        } elseif ($end <= $start) {
            $errors['window'] = __('The end must be after the start.');
        } elseif ($end->getTimestamp() - $start->getTimestamp() > EngagementRepository::MAX_DAYS * 86400) {
            $errors['window'] = __('An engagement lasts at most {n} days.', ['n' => EngagementRepository::MAX_DAYS]);
        } elseif ($end <= $now) {
            $errors['window'] = __('The window has already ended.');
        } elseif ($start->getTimestamp() > $now->getTimestamp() + EngagementRepository::MAX_AHEAD_DAYS * 86400) {
            $errors['window'] = __('Start within {n} days; create it closer to the date.', ['n' => EngagementRepository::MAX_AHEAD_DAYS]);
        }
        $endDay = $end?->format('Y-m-d') ?? $today;

        // Targets: each inside the scope that is active now AND still valid on the window's last day.
        $targets = [];
        $external = [];
        if (trim(preg_replace('/#.*$/m', '', $v['external']) ?? '') !== '') {
            $parsed = App::scopeParser()->parseLines($v['external']);
            $activeNow = App::authorisations()->activeEntries($clientId, $today);
            $activeEnd = App::authorisations()->activeEntries($clientId, max($today, $endDay));
            foreach ($parsed['entries'] as $entry) {
                if (!EngagementRepository::insideScope($entry, $activeNow) || !EngagementRepository::insideScope($entry, $activeEnd)) {
                    $parsed['errors'][] = __('{t} is not inside this client\'s authorised scope for the whole window: authorise it first (Authorisations).', ['t' => $entry['value']]);
                    continue;
                }
                $external[] = $entry['value'];
                $targets[] = ['kind' => 'external', 'site_id' => null, 'entry_type' => $entry['type'], 'value' => $entry['value'],
                              'range_start' => $entry['range']?->start, 'range_end' => $entry['range']?->end];
            }
            if ($parsed['errors'] !== []) {
                $errors['external'] = implode(' ', array_slice($parsed['errors'], 0, 5));
            }
        }
        foreach ($sites as $s) {
            $sid = (int) $s['id'];
            if (trim(preg_replace('/#.*$/m', '', $v['internal'][$sid]) ?? '') === '') {
                continue;
            }
            $parsed = InternalRanges::parseLines($v['internal'][$sid]);
            $authNow = App::agents()->activeAuthorisation($sid, $today);
            $authEnd = App::agents()->activeAuthorisation($sid, max($today, $endDay));
            if ($authNow === null || $authEnd === null) {
                $parsed['errors'][] = __('Site {s} has no internal authorisation valid for the whole window.', ['s' => $s['name']]);
            } elseif (!InternalRanges::allWithin($parsed['ranges'], $authNow['ranges_list']) || !InternalRanges::allWithin($parsed['ranges'], $authEnd['ranges_list'])) {
                $parsed['errors'][] = __('Site {s}: every range must lie inside the site\'s internal authorisation.', ['s' => $s['name']]);
            }
            if ($parsed['errors'] !== []) {
                $errors['internal_' . $sid] = implode(' ', array_slice($parsed['errors'], 0, 5));
                continue;
            }
            foreach ($parsed['ranges'] as $cidr) {
                $r = IpRange::parse($cidr);
                $targets[] = ['kind' => 'internal', 'site_id' => $sid, 'entry_type' => $r !== null && $r->hostBits() === 0 ? 'ip' : 'cidr', 'value' => $cidr,
                              'range_start' => $r?->start, 'range_end' => $r?->end];
            }
        }
        if ($targets === [] && !isset($errors['external']) && !array_filter(array_keys($errors), static fn (string $k): bool => str_starts_with($k, 'internal_'))) {
            $errors['external'] = __('Enter at least one target: external, or internal for a site.');
        }
        // Exclusions: public or private addresses, ranges or domain names never to touch.
        foreach (preg_split('/\R/', $v['exclusions']) ?: [] as $n => $line) {
            $line = trim((string) preg_replace('/#.*$/', '', $line));
            if ($line === '') {
                continue;
            }
            $priv = InternalRanges::parse($line);
            if (isset($priv['cidr'])) {
                $r = IpRange::parse($priv['cidr']);
                $targets[] = ['kind' => 'exclude', 'site_id' => null, 'entry_type' => $r !== null && $r->hostBits() === 0 ? 'ip' : 'cidr', 'value' => $priv['cidr'],
                              'range_start' => $r?->start, 'range_end' => $r?->end];
                continue;
            }
            $pub = App::scopeParser()->parse($line);
            if (is_string($pub) || $pub['type'] === 'domain') {
                // By address only: a name can't protect the address behind it (and agents test addresses).
                $errors['exclusions'] = __('Line {n} ("{text}"): {error}', ['n' => $n + 1, 'text' => mb_substr($line, 0, 80),
                    'error' => is_string($pub) ? $pub : __('Exclude by IP address or range, not by name.')]);
                break;
            }
            $targets[] = ['kind' => 'exclude', 'site_id' => null, 'entry_type' => $pub['type'], 'value' => $pub['value'],
                          'range_start' => $pub['range']?->start, 'range_end' => $pub['range']?->end];
        }

        // The signed authorisation: a PDF, kept by its hash.
        $doc = $request->uploadedFile('document');
        $docBytes = $doc !== null ? (int) filesize($doc) : 0;
        if ($doc === null) {
            $errors['document'] = __('Attach the client\'s signed authorisation (PDF).');
        } elseif ($docBytes === 0 || $docBytes > self::MAX_DOC_BYTES || (string) file_get_contents($doc, false, null, 0, 5) !== '%PDF-') {
            $errors['document'] = __('The signed authorisation must be a PDF of at most 10 MB.');
        }
        if ($v['confirm'] !== '1') {
            $errors['confirm'] = __('Confirm that the client signed this authorisation for these targets, tests and window.');
        }
        // Trying passwords is a step further than scanning: the signed document must say so explicitly (annex, item 6).
        if (in_array('default_creds', $v['tests'], true) && $v['creds_confirm'] !== '1') {
            $errors['creds_confirm'] = __('Confirm that the signed authorisation explicitly allows trying vendor default passwords, or untick that test.');
        }
        if ($errors !== []) {
            return $this->form($client, $v, $errors, 422);
        }

        $sha = hash_file('sha256', (string) $doc);
        $dir = self::documentDir();
        if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
            throw new HttpException(500, __('The document could not be stored.'));
        }
        $path = $dir . '/' . $sha . '.pdf';
        if (!is_file($path) && !move_uploaded_file((string) $doc, $path) && !copy((string) $doc, $path)) {
            throw new HttpException(500, __('The document could not be stored.'));
        }
        @chmod($path, 0640);
        $utc = new DateTimeZone('UTC');
        $name = preg_replace('/[^A-Za-z0-9._ -]/', '_', basename($request->uploadedName('document') ?: 'authorisation.pdf')) ?: 'authorisation.pdf';
        $id = App::engagements()->create($clientId, [
            'name' => $v['name'], 'window_start' => $start->setTimezone($utc)->format('Y-m-d H:i:s'), 'window_end' => $end->setTimezone($utc)->format('Y-m-d H:i:s'),
            'intensity' => $v['intensity'], 'tests' => $v['tests'], 'signer_name' => $v['signer_name'], 'signer_role' => $v['signer_role'], 'signed_on' => $v['signed_on'],
            'document_sha256' => $sha, 'document_name' => mb_substr($name, 0, 190), 'document_bytes' => $docBytes, 'notes' => $v['notes'], 'retest_of' => $retestOf,
        ], $targets, (int) $this->user()['id']);
        $this->audit($request, 'engagement.created', 'engagement', $id, ['client_id' => $clientId, 'tests' => $v['tests'], 'intensity' => $v['intensity'],
            'default_passwords_confirmed' => in_array('default_creds', $v['tests'], true),
            'external' => count($external), 'internal' => count(array_filter($targets, static fn (array $t): bool => $t['kind'] === 'internal')), 'document_sha256' => $sha]);
        // Tell the approvers: the engagement can't run until one of them approves it (1.34). Approvers other than the creator.
        $me = (int) $this->user()['id'];
        $approvers = count(array_filter(App::roles()->usersWith('engagements.approve'), static fn (array $u): bool => $u['id'] !== $me));
        App::alerts()->notifyUsers('engagement', 'warn', __('Engagement awaiting approval: {name}', ['name' => $v['name']]),
            __('{user} created it for {client}. A different admin must approve it before anything runs.', ['user' => (string) ($this->user()['display_name'] ?? ''), 'client' => (string) $client['name']]),
            '/engagements/' . $id, 'engagements.approve', $clientId);
        Session::flash('success', $approvers >= 1
            ? __('Engagement created. Someone else who may approve engagements must approve it before anything runs; they were notified.')
            : __('Engagement created. Nobody else may approve engagements yet: give a second person a role that can approve them (Users) first.'));
        return Response::redirect('/engagements/' . $id);
    }

    /** GET /engagements: every engagement across clients, with those awaiting the viewer's approval first (1.34). */
    public function index(Request $request): Response
    {
        $canApprove = App::auth()->can('engagements.approve');
        return $this->page('engagements/index', __('Pen-test engagements'), [
            'engagements' => App::engagements()->all(200, App::auth()->clientIds()),
            'awaiting' => $canApprove ? App::engagements()->awaitingApprovalBy((int) $this->user()['id'], App::auth()->clientIds()) : [],
            'approverCount' => count(App::roles()->usersWith('engagements.approve')),
        ]);
    }

    /** GET /engagements/{id} */
    public function show(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $client = App::clients()->find((int) $e['client_id']) ?? throw new HttpException(404);
        $siteNames = [];
        foreach (App::clients()->sites((int) $client['id']) as $s) {
            $siteNames[(int) $s['id']] = (string) $s['name'];
        }
        return $this->page('engagements/show', (string) $e['name'], ['client' => $client, 'engagement' => $e, 'siteNames' => $siteNames,
            'results' => $results = App::engagements()->results((int) $e['id']), 'findings' => \Sentinel\Engagements\EngagementFindings::analyse($results),
            'externalJobs' => App::engagements()->externalJobs((int) $e['id']),
            'agentJobs' => App::agents()->engagementJobs((int) $e['id']), 'reports' => App::reports()->forEngagement((int) $e['id']),
            'retestOf' => $e['retest_of'] !== null ? App::engagements()->find((int) $e['retest_of']) : null,
            'state' => EngagementRepository::state($e, gmdate('Y-m-d H:i:s')), 'testLabels' => self::testLabels(),
            'clientNav' => ClientController::nav($client, 'engagements', App::findings()->counts((int) $client['id']))]);
    }

    /** POST /engagements/{id}/approve (admins, with their password; never the creator, nor an account the creator made or reset recently) */
    public function approve(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $back = Response::redirect('/engagements/' . (int) $e['id']);
        $me = (int) $this->user()['id'];
        if ((int) $e['created_by'] === $me) {
            Session::flash('danger', __('You created this engagement: a different admin must approve it.'));
            return $back;
        }
        // The second person must really be someone else: not linked to the creator in the last 30 days (either one
        // created the other or reset its password or 2FA, directly or through a chain of such accounts), otherwise one
        // admin could approve their own engagement through an account they control.
        if (in_array((int) $e['created_by'], App::engagements()->linkedAccounts($me), true)) {
            $this->audit($request, 'engagement.approval_refused', 'engagement', (int) $e['id'], ['reason' => 'account linked to the creator']);
            Session::flash('danger', __('Your account and the creator\'s are linked: one created the other, or reset its password or two-factor authentication, in the last 30 days (directly or through another account). Another admin must approve it.'));
            return $back;
        }
        $user = App::db()->query('SELECT id, password_hash FROM users WHERE id = ' . $me)->fetch() ?: [];
        if (($why = $this->checkCurrentPassword($request, $user, $request->raw('password'))) !== null) {
            Session::flash('danger', __('Enter your Sentinel password to approve.') . ' ' . $why);
            return $back;
        }
        if (!App::engagements()->approve((int) $e['id'], $me)) {
            Session::flash('danger', __('It can no longer be approved (stopped, cancelled, already approved or its window has ended).'));
            return $back;
        }
        $this->audit($request, 'engagement.approved', 'engagement', (int) $e['id'], ['client_id' => (int) $e['client_id']]);
        Session::flash('success', __('Engagement approved. Tests can run inside its window.'));
        return $back;
    }

    /** POST /engagements/{id}/stop (technicians and admins): the kill switch, for good. */
    public function stop(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $reason = mb_substr(trim($request->input('reason')), 0, 500);
        if ($reason === '') {
            Session::flash('danger', __('Give a reason for stopping.'));
            return Response::redirect('/engagements/' . (int) $e['id']);
        }
        if (App::engagements()->stop((int) $e['id'], (int) $this->user()['id'], $reason)) {
            $this->audit($request, 'engagement.stopped', 'engagement', (int) $e['id'], ['client_id' => (int) $e['client_id'], 'reason' => $reason]);
            Session::flash('warning', __('Engagement stopped. Running tests stop at their next check (within a minute); nothing more runs for it.'));
        }
        return Response::redirect('/engagements/' . (int) $e['id']);
    }

    /**
     * POST /engagements/{id}/run-external (technicians and admins): queue the external tests. Only while the engagement
     * is active and has external targets; one queued or running job at a time. The worker checks everything again
     * for every host while it runs.
     */
    public function runExternal(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $back = Response::redirect('/engagements/' . (int) $e['id']);
        if (!App::engagements()->isActive((int) $e['id'])) {
            Session::flash('danger', __('Tests run only while the engagement is active: approved, inside its window and not stopped (and scanning not paused).'));
            return $back;
        }
        if (!array_filter($e['targets'], static fn (array $t): bool => $t['kind'] === 'external')) {
            Session::flash('warning', __('This engagement has no external targets.'));
            return $back;
        }
        foreach (App::engagements()->externalJobs((int) $e['id']) as $j) {
            if (in_array($j['status'], ['queued', 'running'], true)) {
                Session::flash('info', __('The external tests are already queued or running.'));
                return $back;
            }
        }
        $job = App::scans()->queue((int) $e['client_id'], 'manual', (int) $this->user()['id'], true, __('Engagement window'), ['engagement_id' => (int) $e['id']], 'engagement');
        $this->audit($request, 'engagement.external_started', 'engagement', (int) $e['id'], ['client_id' => (int) $e['client_id'], 'scan_job' => $job]);
        Session::flash('success', __('External tests queued (scan #{id}). They start within a minute and stop at once if the engagement is stopped.', ['id' => $job]));
        return $back;
    }

    /**
     * POST /engagements/{id}/run-internal (technicians and admins): queue the internal tests with each site's agent
     * (one per site that has ranges in this engagement), only while the engagement is active, only with agents that
     * run engagement jobs (1.27.0 or later), one open job per site. The job is signed when handed out (everything
     * checked again then), stops when the engagement does, and the agent stops by itself at the window's end.
     */
    public function runInternal(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $back = Response::redirect('/engagements/' . (int) $e['id']);
        if (!App::engagements()->isActive((int) $e['id'])) {
            Session::flash('danger', __('Tests run only while the engagement is active: approved, inside its window and not stopped (and scanning not paused).'));
            return $back;
        }
        $client = App::clients()->find((int) $e['client_id']) ?? throw new HttpException(404);
        $open = [];
        foreach (App::agents()->engagementJobs((int) $e['id']) as $j) {
            if (in_array($j['status'], ['queued', 'sent', 'ingesting'], true)) {
                $open[(int) $j['site_id']] = true;
            }
        }
        $bySite = [];
        foreach ($e['targets'] as $t) {
            if ($t['kind'] === 'internal') {
                $bySite[(int) $t['site_id']][] = (string) $t['value'];
            }
        }
        $queued = [];
        $notes = [];
        // The default-credential test needs agents that know it (older ones would refuse the signed job).
        $minVersion = in_array('default_creds', $e['tests_list'], true) ? \Sentinel\Agent\AgentRepository::DEFAULT_CREDS_SINCE : \Sentinel\Agent\AgentRepository::ENGAGEMENT_SINCE;
        foreach ($bySite as $siteId => $ranges) {
            $auth = App::agents()->activeAuthorisation($siteId, ScopeService::today((string) $client['timezone']));
            if ($auth === null || isset($open[$siteId])) {
                $siteName = (string) ($this->siteName($siteId) ?: '#' . $siteId);
                $notes[] = $auth === null ? __('Site {s} has no valid internal authorisation today: record one under the client\'s Agents page.', ['s' => $siteName])
                    : __('Site {s} already has internal tests queued or running.', ['s' => $siteName]);
                continue;
            }
            $agent = null;
            $siteAgents = App::agents()->agents($siteId);
            $siteName = (string) ($this->siteName($siteId) ?: '#' . $siteId);
            if (array_filter($siteAgents, static fn (array $a): bool => $a['status'] === 'active') === []) {
                $notes[] = __('No agent is enrolled at site {s}: enrol one under the client\'s Agents page first.', ['s' => $siteName]);
                continue;
            }
            foreach ($siteAgents as $a) {
                if ($a['status'] === 'active' && preg_match('/^\d+\.\d+\.\d+$/', (string) $a['version']) === 1
                    && version_compare((string) $a['version'], $minVersion, '>=')) {
                    $agent = $a;
                    break;
                }
            }
            if ($agent === null) {
                $notes[] = __('The agent at site {s} is older than {v}: update it from the client\'s Agents page first.', ['s' => $siteName, 'v' => $minVersion]);
                continue;
            }
            $queued[] = App::agents()->queueEngagementJob((int) $agent['id'], (int) $client['id'], $siteId, (int) $auth['id'], (int) $e['id'], (int) $this->user()['id'],
                $ranges, (string) $e['window_end']);
        }
        if ($queued !== []) {
            $this->audit($request, 'engagement.internal_started', 'engagement', (int) $e['id'], ['client_id' => (int) $e['client_id'], 'agent_jobs' => $queued]);
            Session::flash('success', __('Internal tests queued with {n} agent(s); each starts at its next check-in.', ['n' => count($queued)]));
        }
        if ($notes !== []) {
            Session::flash('warning', implode(' ', array_unique($notes)));
        }
        return $back;
    }

    /**
     * POST /engagements/{id}/report (technicians and admins): issue the pen-test report (or, for a retest, the retest
     * letter, comparing with the earlier engagement's latest report) from the evidence recorded so far. A frozen
     * snapshot, like every report; it can be issued again later (e.g. after more tests), each one kept.
     */
    public function report(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $back = Response::redirect('/engagements/' . (int) $e['id']);
        if ($e['approved_at'] === null) {
            Session::flash('danger', __('Only an approved engagement has a report.'));
            return $back;
        }
        $results = App::engagements()->results((int) $e['id']);
        if ($results === []) {
            Session::flash('warning', __('Run the tests first: there are no results to report yet.'));
            return $back;
        }
        $client = App::clients()->find((int) $e['client_id']) ?? throw new HttpException(404);
        $original = null;
        if ($e['retest_of'] !== null) {
            $prev = App::reports()->forEngagement((int) $e['retest_of']);
            foreach ($prev as $p) {
                if ($p['kind'] === 'pentest') {
                    $row = App::reports()->find((int) $p['id']);
                    $original = is_array($row) ? json_decode((string) $row['snapshot'], true) : null;
                    break;
                }
            }
            if (!is_array($original)) {
                Session::flash('danger', __('The engagement this retests has no penetration test report to compare with.'));
                return $back;
            }
        }
        $siteNames = [];
        foreach (App::clients()->sites((int) $client['id']) as $s) {
            $siteNames[(int) $s['id']] = (string) $s['name'];
        }
        $user = $this->user();
        $builder = new \Sentinel\Reports\ReportBuilder(App::db(), App::settings(), App::authorisations(), SENTINEL_ROOT . '/storage/branding', App::version());
        $snap = \Sentinel\Engagements\EngagementReport::build($e, $client, $results, $builder->brand(), $siteNames, self::testLabels(), (string) $user['display_name'], $original);
        $html = \Sentinel\Engagements\EngagementReport::render($snap, SENTINEL_ROOT . '/views/reports');
        $kind = $original === null ? 'pentest' : 'retest';
        $title = ($kind === 'pentest' ? __('Penetration test report') : __('Retest letter')) . ' – ' . $client['name'] . ' – ' . $e['name'];
        $id = App::reports()->create((int) $client['id'], $kind, 'manual', $title, substr((string) $e['window_start'], 0, 10), substr((string) $e['window_end'], 0, 10),
            (int) $user['id'], $html, $snap);
        App::reports()->setEngagement($id, (int) $e['id']);
        $this->audit($request, 'report.created', 'report', $id, ['client' => (int) $client['id'], 'kind' => $kind, 'engagement' => (int) $e['id']]);
        Session::flash('success', $kind === 'pentest' ? __('Penetration test report issued.') : __('Retest letter issued.'));
        return Response::redirect('/reports/' . $id);
    }

    /** POST /engagements/{id}/cancel (before approval) */
    public function cancel(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        if (App::engagements()->cancel((int) $e['id'])) {
            $this->audit($request, 'engagement.cancelled', 'engagement', (int) $e['id'], ['client_id' => (int) $e['client_id']]);
            Session::flash('success', __('Engagement cancelled.'));
        }
        return Response::redirect('/clients/' . (int) $e['client_id'] . '/engagements');
    }

    /** GET /engagements/{id}/document: the signed authorisation, as a download (never shown inline). */
    public function document(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $path = self::documentDir() . '/' . $e['document_sha256'] . '.pdf';
        if (preg_match('/^[0-9a-f]{64}$/', (string) $e['document_sha256']) !== 1 || !is_file($path)) {
            throw new HttpException(404);
        }
        return (new Response((string) file_get_contents($path), 200))
            ->header('Content-Type', 'application/pdf')
            ->header('Content-Disposition', 'attachment; filename="engagement-' . (int) $e['id'] . '-authorisation.pdf"')
            ->header('X-Content-Type-Options', 'nosniff')
            ->header('Content-Security-Policy', "default-src 'none'; sandbox")
            ->header('Cache-Control', 'private, no-store');
    }

    /** Where signed documents are kept (storage/engagements; never web-served directly). */
    public static function documentDir(): string
    {
        return SENTINEL_ROOT . '/storage/engagements';
    }

    /** @param array<string,mixed> $client @param array<string,mixed> $values @param array<string,string> $errors */
    private function form(array $client, array $values, array $errors, int $status = 200): Response
    {
        $sites = [];
        $today = ScopeService::today((string) $client['timezone']);
        foreach (App::clients()->sites((int) $client['id']) as $s) {
            $a = App::agents()->activeAuthorisation((int) $s['id'], $today);
            $sites[] = ['site' => $s, 'ranges' => $a['ranges_list'] ?? [], 'until' => $a['valid_until'] ?? null];
        }
        $earlier = array_values(array_filter(App::engagements()->forClient((int) $client['id']), static fn (array $g): bool => $g['approved_at'] !== null));
        return $this->page('engagements/form', __('New engagement'), ['client' => $client, 'values' => $values, 'errors' => $errors, 'earlier' => $earlier,
            'sites' => $sites, 'scope' => App::authorisations()->activeEntries((int) $client['id'], $today), 'testLabels' => self::testLabels(),
            'clientNav' => ClientController::nav($client, 'engagements', App::findings()->counts((int) $client['id']))], $status);
    }

    /** @return array<string,mixed> */
    private function clientOr404(array $params): array
    {
        $id = (string) ($params['id'] ?? '');
        $client = ctype_digit($id) ? App::clients()->find((int) $id) : null;
        return $client ?? throw new HttpException(404, __('Client not found.'));
    }

    /** @return array<string,mixed> */
    private function engagementOr404(array $params): array
    {
        $id = (string) ($params['id'] ?? '');
        $e = ctype_digit($id) ? App::engagements()->find((int) $id) : null;
        return $e ?? throw new HttpException(404, __('Engagement not found.'));
    }

    /** A site's name for messages ('' when unknown). */
    private function siteName(int $siteId): string
    {
        $stmt = App::db()->prepare('SELECT name FROM sites WHERE id = :id');
        $stmt->execute(['id' => $siteId]);
        return (string) ($stmt->fetchColumn() ?: '');
    }
}
