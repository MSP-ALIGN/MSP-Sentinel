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
            'udp_common' => __('Common UDP services (DNS, NTP, SNMP, NetBIOS, SSDP and others)'),
            'nse_safe' => __('nmap\'s "safe" service scripts (details of each service; nothing intrusive)'),
            'anon_access' => __('Anonymous access checks (anonymous FTP, SMB guest shares, NFS exports, open SNMP)'),
        ];
    }

    /** GET /clients/{id}/engagements/new */
    public function create(Request $request, array $params): Response
    {
        $client = $this->clientOr404($params);
        return $this->form($client, ['intensity' => 'gentle', 'tests' => ['tcp_full', 'nse_safe']], []);
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
        foreach (['name', 'signer_name', 'signer_role', 'signed_on', 'window_start', 'window_end', 'intensity', 'notes', 'confirm'] as $f) {
            $v[$f] = $request->input($f);
        }
        $v['external'] = mb_substr($request->raw('external'), 0, 20000);
        $v['exclusions'] = mb_substr($request->raw('exclusions'), 0, 20000);
        $v['tests'] = array_values(array_intersect(EngagementRepository::TESTS, $request->postList('tests')));
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
            if (is_string($pub)) {
                $errors['exclusions'] = __('Line {n} ("{text}"): {error}', ['n' => $n + 1, 'text' => mb_substr($line, 0, 80), 'error' => $pub]);
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
            'document_sha256' => $sha, 'document_name' => mb_substr($name, 0, 190), 'document_bytes' => $docBytes, 'notes' => $v['notes'],
        ], $targets, (int) $this->user()['id']);
        $this->audit($request, 'engagement.created', 'engagement', $id, ['client_id' => $clientId, 'tests' => $v['tests'], 'intensity' => $v['intensity'],
            'external' => count($external), 'internal' => count(array_filter($targets, static fn (array $t): bool => $t['kind'] === 'internal')), 'document_sha256' => $sha]);
        Session::flash('success', __('Engagement created. Another admin must approve it before anything runs.'));
        return Response::redirect('/engagements/' . $id);
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
            'results' => App::engagements()->results((int) $e['id']), 'externalJobs' => App::engagements()->externalJobs((int) $e['id']),
            'state' => EngagementRepository::state($e, gmdate('Y-m-d H:i:s')), 'testLabels' => self::testLabels(),
            'clientNav' => ClientController::nav($client, 'engagements', App::findings()->counts((int) $client['id']))]);
    }

    /** POST /engagements/{id}/approve (admins, with their password; never the creator) */
    public function approve(Request $request, array $params): Response
    {
        $e = $this->engagementOr404($params);
        $back = Response::redirect('/engagements/' . (int) $e['id']);
        $me = (int) $this->user()['id'];
        if ((int) $e['created_by'] === $me) {
            Session::flash('danger', __('You created this engagement: a different admin must approve it.'));
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
        return $this->page('engagements/form', __('New engagement'), ['client' => $client, 'values' => $values, 'errors' => $errors,
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
}
