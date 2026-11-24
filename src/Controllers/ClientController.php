<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\View;
use Sentinel\Core\Session;
use Sentinel\Scanning\PortProfile;
use Sentinel\Scanning\ScanWindow;
use Sentinel\Scope\ScopeService;

/**
 * Clients and their sites.
 *
 * Access (enforced by the routes): everyone signed in can view; admins
 * create, edit, archive and manage sites; technicians and admins can pause
 * a client's scanning; only admins can resume it.
 *
 * Untrusted: all form fields and the {id} path parameter.
 *
 * Security assumptions:
 * - Clients are archived, never deleted, so authorisation evidence survives.
 * - Every change is audited.
 * - Pausing is deliberately easy and resuming deliberately restricted: stopping
 *   a scan that bothers a client must never wait for an admin.
 */
final class ClientController extends Controller
{
    /** GET /clients */
    public function index(Request $request): Response
    {
        $showArchived = $request->query('archived') === '1';
        $clients = App::clients()->all($showArchived);
        $authRepo = App::authorisations();
        foreach ($clients as &$client) {
            $client['auth_summary'] = $this->authSummary($authRepo->forClient((int) $client['id']), (string) $client['timezone']);
        }
        unset($client);
        // Risk and open findings per client (1.37), from the dashboard's own figures (archived clients have none).
        $risk = [];
        foreach (App::dashboard()->clients() as $r) {
            $risk[$r['id']] = $r;
        }
        return $this->page('clients/index', __('Clients'), [
            'clients' => $clients,
            'risk' => $risk,
            'showArchived' => $showArchived,
            'globallyPaused' => App::scope()->globallyPaused(),
        ]);
    }

    /** GET /clients/new */
    public function create(Request $request): Response
    {
        return $this->page('clients/form', __('Add client'), [
            'mode' => 'create',
            'values' => ['name' => '', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '22:00', 'scan_window_end' => '06:00', 'notes' => '',
                         'ports_extra' => '', 'ports_excluded' => ''],
            'errors' => [],
        ]);
    }

    /** POST /clients */
    public function store(Request $request): Response
    {
        [$values, $clean, $errors] = $this->validate($request, null);
        if ($errors !== []) {
            return $this->page('clients/form', __('Add client'), ['mode' => 'create', 'values' => $values, 'errors' => $errors], 422);
        }
        $id = App::clients()->create($clean, (int) $this->user()['id']);
        $this->audit($request, 'client.created', 'client', $id, ['name' => $clean['name']]);
        Session::flash('success', __('Client {name} created. Next, choose Record authorisation (below) to note who approved scanning and what may be scanned.', ['name' => $clean['name']]));
        return Response::redirect('/clients/' . $id);
    }

    /**
     * The client's pages: one URL per section (GET /clients/{id} is the overview, /clients/{id}/findings, ...),
     * each with the client's own menu in the sidebar. Only the data the section shows is loaded.
     */
    public const SECTIONS = ['overview', 'findings', 'scans', 'vulnerabilities', 'certificates', 'website', 'agents', 'devices', 'authorisations', 'engagements', 'discovery', 'reports', 'compliance'];

    /**
     * GET /clients/{id} and /clients/{id}/{section} (any signed-in role; actions inside are role-checked by their routes).
     * Untrusted: the path (the section must be one of SECTIONS, else the overview) and the client ID (404 if unknown).
     */
    public function show(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        $cid = (int) $client['id'];
        $last = substr($request->path, (int) strrpos($request->path, '/') + 1);
        $section = in_array($last, self::SECTIONS, true) ? $last : 'overview';
        $today = ScopeService::today((string) $client['timezone']);
        $authorisations = static function () use ($cid, $today): array {
            $rows = App::authorisations()->forClient($cid);
            foreach ($rows as &$a) {
                $a['status'] = ScopeService::status($a, $today);
            }
            return $rows;
        };
        $web = static fn (): \Sentinel\Web\WebsiteRepository => new \Sentinel\Web\WebsiteRepository(App::db());
        // What each section needs (closures, so a page only runs its own queries).
        $loaders = [
            'overview' => ['sites' => fn () => App::clients()->sites($cid), 'authorisations' => $authorisations, 'overview' => fn () => self::overviewData($client)],
            'findings' => ['clientFindings' => fn () => App::findings()->search(['client' => $cid, 'status' => 'open'])['rows']],
            'scans' => ['openJob' => fn () => App::scans()->openJob($cid), 'recentJobs' => fn () => App::scans()->recentJobs($cid), 'services' => fn () => App::scans()->openServices($cid),
                        'scanLog' => fn () => App::scans()->logForClient($cid, 30), 'ports' => fn () => PortProfile::forClient($client), 'windowOpen' => fn () => ScanWindow::isOpen($client)],
            'vulnerabilities' => ['vulns' => fn () => App::vulns()->forClient($cid), 'vulnCoverage' => fn () => App::vulns()->coverage($cid), 'feeds' => fn () => App::vulns()->feedStatuses()],
            'certificates' => ['tlsEndpoints' => fn () => App::endpoints()->tlsForClient($cid), 'webPages' => fn () => App::endpoints()->webForClient($cid)],
            'website' => ['websiteChecks' => fn () => $web()->checksForClient($cid), 'emailChecks' => fn () => $web()->emailForClient($cid), 'domainChecks' => fn () => $web()->domainChecksForClient($cid),
                'breaches' => fn () => \Sentinel\Breach\BreachMonitor::forClient(App::db(), $cid)],
            'agents' => ['agentSites' => fn () => self::agentSites($client)],
            'devices' => ['inventorySources' => fn () => array_map(static fn (\Sentinel\Inventory\InventorySource $s): string => $s->label(), App::inventorySources()),
                          'inventoryLinks' => fn () => array_map(fn (\Sentinel\Inventory\InventorySource $s): ?array => App::inventory()->link($cid, $s->name()), App::inventorySources()),
                          'devices' => fn () => App::inventory()->devicesForClient($cid, 500),
                          'deviceTotal' => fn () => (int) App::db()->query('SELECT COUNT(*) FROM devices d WHERE d.removed_at IS NULL AND ' . \Sentinel\Inventory\InventoryRepository::notMerged('d') . ' AND d.client_id = ' . $cid)->fetchColumn(),
                          'devicePatches' => fn () => App::inventory()->patchesByDevice($cid)],
            'authorisations' => ['authorisations' => $authorisations],
            'engagements' => ['engagements' => fn () => App::engagements()->forClient($cid)],
            'discovery' => ['suggestions' => fn () => App::suggestions()->forClient($cid, 'pending'), 'dismissed' => fn () => App::suggestions()->forClient($cid, 'dismissed'),
                            'lastRun' => fn () => App::suggestions()->lastRun($cid)],
            'reports' => ['clientReports' => fn () => App::reports()->list($cid, 20)],
            'compliance' => ['alignOn' => fn () => App::align() !== null,
                             'compliance' => fn () => (int) ($client['align_client_id'] ?? 0) > 0 ? (new \Sentinel\Compliance\AlignCompliance(App::db(), App::align()))->forClient($client) : null,
                             'alignClients' => function () use ($client): array {
                                 // Choices for linking (admins, unlinked clients only); the exact-name match first.
                                 // Only when an admin could link this client: nobody else needs the list.
                                 if ((int) ($client['align_client_id'] ?? 0) > 0 || App::align() === null || (int) $client['is_archived'] === 1
                                     || (int) ($client['is_demo'] ?? 0) === 1 || !\Sentinel\Auth\Role::atLeast((string) ($this->user()['role'] ?? ''), \Sentinel\Auth\Role::ADMIN)) {
                                     return ['list' => [], 'error' => ''];
                                 }
                                 $s = App::settings();
                                 $cached = json_decode($s->fresh('mspalign_clients_cache'), true);
                                 if (is_array($cached) && is_array($cached['list'] ?? null) && (int) ($cached['at'] ?? 0) > time() - 600) {
                                     $list = $cached['list']; // the list for linking is read at most every 10 minutes
                                 } else {
                                     try {
                                         $list = App::align()->clients();
                                         $s->set('mspalign_clients_cache', (string) json_encode(['at' => time(), 'list' => $list]));
                                     } catch (\Sentinel\Compliance\AlignException $ex) {
                                         return ['list' => [], 'error' => $ex->getMessage()];
                                     }
                                 }
                                 usort($list, static fn (array $a, array $b): int => [strcasecmp($a['name'], (string) $client['name']) !== 0, $a['name']] <=> [strcasecmp($b['name'], (string) $client['name']) !== 0, $b['name']]);
                                 return ['list' => $list, 'error' => ''];
                             }],
        ];
        $data = ['client' => $client, 'section' => $section, 'today' => $today, 'globallyPaused' => App::scope()->globallyPaused(),
                 'findingCounts' => App::findings()->counts($cid), 'authorisations' => [], 'sites' => []];
        foreach ($loaders[$section] as $key => $load) {
            $data[$key] = $load();
        }
        $data['clientNav'] = self::nav($client, $section, $data['findingCounts']);
        return $this->page('clients/show', (string) $client['name'], $data);
    }

    /**
     * The client's menu for the sidebar: sections in groups, with the current one marked.
     *
     * @param array<string,mixed> $client
     * @param array<string,mixed> $counts FindingRepository::counts()
     * @return array<string,mixed>
     */
    public static function nav(array $client, string $section, array $counts): array
    {
        $item = static fn (string $key, string $label, string $icon): array => ['key' => $key, 'label' => $label, 'icon' => $icon,
            'url' => '/clients/' . (int) $client['id'] . ($key === 'overview' ? '' : '/' . $key), 'active' => $key === $section];
        $open = (int) ($counts['fail'] ?? 0) + (int) ($counts['warn'] ?? 0);
        return [
            'name' => (string) $client['name'], 'id' => (int) $client['id'], 'demo' => (int) ($client['is_demo'] ?? 0) === 1, 'archived' => (int) $client['is_archived'] === 1,
            'groups' => [
                ['label' => null, 'items' => [$item('overview', __('Overview'), 'bi-speedometer2'), $item('findings', __('Findings'), 'bi-flag') + ['badge' => $open]]],
                ['label' => __('External'), 'items' => [$item('scans', __('Scans & ports'), 'bi-hdd-network'), $item('vulnerabilities', __('Vulnerabilities'), 'bi-bug'),
                    $item('certificates', __('Certificates & web'), 'bi-shield-lock'), $item('website', __('Website & email'), 'bi-globe')]],
                ['label' => __('Internal'), 'items' => [$item('agents', __('Agents'), 'bi-router'), $item('devices', __('Devices'), 'bi-pc-display')]],
                ['label' => __('Manage'), 'items' => [$item('authorisations', __('Authorisations'), 'bi-file-earmark-check'), $item('engagements', __('Pen-test engagements'), 'bi-crosshair'),
                    $item('discovery', __('Discovery'), 'bi-search'),
                    $item('reports', __('Reports'), 'bi-file-earmark-text'), $item('compliance', __('Compliance'), 'bi-clipboard-check')]],
            ],
        ];
    }

    /**
     * Per site: the active internal authorisation, all authorisations, agents and recent agent jobs.
     *
     * @param array<string,mixed> $client
     * @return list<array<string,mixed>>
     */
    private static function agentSites(array $client): array
    {
        $today = \Sentinel\Scope\ScopeService::today((string) $client['timezone']);
        $repo = App::agents();
        $out = [];
        foreach (App::clients()->sites((int) $client['id']) as $site) {
            $out[] = ['site' => $site, 'active' => $repo->activeAuthorisation((int) $site['id'], $today), 'authorisations' => $repo->authorisations((int) $site['id']),
                      'agents' => $repo->agents((int) $site['id']), 'jobs' => $repo->recentJobs((int) $site['id'], 5),
                      'directory' => App::directory()->find((int) $site['id'])];
        }
        return $out;
    }

    /** GET /clients/{id}/overview: the overview panel alone, for the 60-second refresh (any signed-in role). */
    public function overview(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        if ((int) $client['is_archived'] === 1) {
            throw new HttpException(404); // archived clients have no overview
        }
        return Response::html(View::render('clients/overview', ['client' => $client, 'ov' => self::overviewData($client)], null))->header('X-Sentinel-Fragment', '1');
    }

    /**
     * Numbers for a client's overview console.
     *
     * @param array<string,mixed> $client
     * @return array<string,mixed>
     */
    private static function overviewData(array $client): array
    {
        $data = App::dashboard();
        $cid = (int) $client['id'];
        $summary = $data->clients($cid)[0] ?? ['fail' => 0, 'warn' => 0, 'kev' => 0, 'score' => 0, 'level' => 'good', 'last_scan' => null];
        return [
            'summary' => $summary,
            'window' => (int) ($client['is_demo'] ?? 0) === 1 ? null : \Sentinel\Dashboard\DashboardData::window($client), // demo clients are never scanned
            'paused' => (int) $client['scanning_paused'] === 1 || App::scope()->globallyPaused(),
            'trend' => $data->trend(90, $cid, (int) $summary['fail'], (int) $summary['warn']),
            'surface' => $data->surface($cid),
            'activity' => $data->activity(6, $cid),
            'certs' => $data->certificates(30, $cid),
        ];
    }

    /** GET /clients/{id}/edit */
    public function edit(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        $values = $client;
        $values['scan_window_start'] = substr((string) $client['scan_window_start'], 0, 5);
        $values['scan_window_end'] = substr((string) $client['scan_window_end'], 0, 5);
        $values['itflow_client_id'] = $client['itflow_client_id'] === null ? '' : (string) $client['itflow_client_id'];
        return $this->page('clients/form', __('Edit client'), ['mode' => 'edit', 'client' => $client, 'values' => $values, 'errors' => []]);
    }

    /** POST /clients/{id} */
    public function update(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        $id = (int) $client['id'];
        [$values, $clean, $errors] = $this->validate($request, $id);
        if ($errors !== []) {
            return $this->page('clients/form', __('Edit client'), ['mode' => 'edit', 'client' => $client, 'values' => $values, 'errors' => $errors], 422);
        }
        App::clients()->update($id, $clean);
        $changes = [];
        foreach (['name', 'itflow_client_id', 'timezone', 'scan_window_start', 'scan_window_end', 'ports_extra', 'ports_excluded'] as $field) {
            $old = $field === 'scan_window_start' || $field === 'scan_window_end' ? substr((string) $client[$field], 0, 5) : (string) $client[$field];
            $new = $field === 'scan_window_start' || $field === 'scan_window_end' ? substr((string) $clean[$field], 0, 5) : (string) $clean[$field];
            if ($old !== $new) {
                $changes[$field] = ['from' => $old, 'to' => $new];
            }
        }
        if ((string) $client['notes'] !== $clean['notes']) {
            $changes['notes'] = 'changed';
        }
        $this->audit($request, 'client.updated', 'client', $id, ['changes' => $changes]);
        Session::flash('success', __('Client details saved.'));
        return Response::redirect('/clients/' . $id);
    }

    /** POST /clients/{id}/archive: toggles archived (field "archive" = 1 or 0). */
    public function archive(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        $archive = $request->input('archive') === '1';
        App::clients()->setArchived((int) $client['id'], $archive);
        $this->audit($request, $archive ? 'client.archived' : 'client.restored', 'client', (int) $client['id']);
        Session::flash('success', $archive
            ? __('Client archived. It will not be scanned, and its history is kept.')
            : __('Client restored.'));
        return Response::redirect('/clients/' . (int) $client['id']);
    }

    /** POST /clients/{id}/pause (technician or admin) */
    public function pause(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        App::clients()->setPaused((int) $client['id'], true);
        $this->audit($request, 'scanning.client_paused', 'client', (int) $client['id'], ['reason' => mb_substr($request->input('reason'), 0, 300)]);
        Session::flash('warning', __('Scanning paused for {name}. An admin can resume it.', ['name' => $client['name']]));
        return Response::redirect('/clients/' . (int) $client['id']);
    }

    /** POST /clients/{id}/resume (admin) */
    public function resume(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        App::clients()->setPaused((int) $client['id'], false);
        $this->audit($request, 'scanning.client_resumed', 'client', (int) $client['id']);
        Session::flash('success', __('Scanning resumed for {name}.', ['name' => $client['name']]));
        return Response::redirect('/clients/' . (int) $client['id']);
    }

    /** POST /clients/{id}/sites (admin) */
    public function addSite(Request $request, array $params): Response
    {
        $client = $this->findOr404($params);
        $id = (int) $client['id'];
        [$name, $location, $error] = $this->validateSite($request, $id, null);
        if ($error !== null) {
            Session::flash('danger', $error);
            return Response::redirect('/clients/' . $id);
        }
        $siteId = App::clients()->createSite($id, $name, $location);
        $this->audit($request, 'site.created', 'site', $siteId, ['client_id' => $id, 'name' => $name]);
        Session::flash('success', __('Site {name} added.', ['name' => $name]));
        return Response::redirect('/clients/' . $id);
    }

    /** POST /sites/{id} (admin): rename or change ITFlow location ID. */
    public function updateSite(Request $request, array $params): Response
    {
        $site = App::clients()->findSite((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
        $clientId = (int) $site['client_id'];
        [$name, $location, $error] = $this->validateSite($request, $clientId, (int) $site['id']);
        if ($error !== null) {
            Session::flash('danger', $error);
            return Response::redirect('/clients/' . $clientId);
        }
        App::clients()->updateSite((int) $site['id'], $name, $location);
        $this->audit($request, 'site.updated', 'site', (int) $site['id'], ['client_id' => $clientId, 'name' => $name]);
        Session::flash('success', __('Site saved.'));
        return Response::redirect('/clients/' . $clientId);
    }

    /**
     * Validate the client form.
     *
     * @return array{0: array<string,string>, 1: array<string,mixed>, 2: array<string,string>} [raw values for re-display, clean values, errors]
     */
    private function validate(Request $request, ?int $exceptId): array
    {
        $values = [
            'name' => $request->input('name'),
            'itflow_client_id' => $request->input('itflow_client_id'),
            'timezone' => $request->input('timezone'),
            'scan_window_start' => $request->input('scan_window_start'),
            'scan_window_end' => $request->input('scan_window_end'),
            'notes' => $request->input('notes'),
            'ports_extra' => $request->input('ports_extra'),
            'ports_excluded' => $request->input('ports_excluded'),
        ];
        $errors = [];
        $portLists = [];
        foreach (['ports_extra', 'ports_excluded'] as $field) {
            $parsed = PortProfile::parseList($values[$field]);
            if (is_string($parsed)) {
                $errors[$field] = $parsed;
            } else {
                $portLists[$field] = PortProfile::toNmapArg($parsed); // stored in normalised form
            }
        }
        if ($values['name'] === '' || mb_strlen($values['name']) > 150 || preg_match('/[\x00-\x1F\x7F]/u', $values['name'])) {
            $errors['name'] = __('Enter a name of up to 150 characters.');
        } elseif (App::clients()->nameTaken($values['name'], $exceptId)) {
            $errors['name'] = __('Another client already has this name.');
        }
        $itflow = null;
        if ($values['itflow_client_id'] !== '') {
            if (!preg_match('/^[1-9][0-9]{0,9}$/', $values['itflow_client_id']) || (int) $values['itflow_client_id'] > 4294967295) {
                $errors['itflow_client_id'] = __('Enter the numeric ITFlow client ID, or leave it empty.');
            } else {
                $itflow = (int) $values['itflow_client_id'];
            }
        }
        if (!in_array($values['timezone'], \DateTimeZone::listIdentifiers(), true)) {
            $errors['timezone'] = __('Choose a timezone from the list.');
        }
        foreach (['scan_window_start', 'scan_window_end'] as $field) {
            if (!preg_match('/^([01][0-9]|2[0-3]):[0-5][0-9]$/', $values[$field])) {
                $errors[$field] = __('Use 24-hour time, e.g. 22:00.');
            }
        }
        if (!isset($errors['scan_window_start'], $errors['scan_window_end']) && $values['scan_window_start'] === $values['scan_window_end']) {
            $errors['scan_window_end'] = __('The window must not start and end at the same time.');
        }
        if (mb_strlen($values['notes']) > 2000) {
            $errors['notes'] = __('Notes can be at most 2000 characters.');
        }
        $clean = [
            'name' => $values['name'],
            'itflow_client_id' => $itflow,
            'timezone' => $values['timezone'],
            'scan_window_start' => $values['scan_window_start'] . ':00',
            'scan_window_end' => $values['scan_window_end'] . ':00',
            'notes' => $values['notes'],
            'ports_extra' => $portLists['ports_extra'] ?? '',
            'ports_excluded' => $portLists['ports_excluded'] ?? '',
        ];
        return [$values, $clean, $errors];
    }

    /** @return array{0:string,1:?int,2:?string} [name, ITFlow location ID, error] */
    private function validateSite(Request $request, int $clientId, ?int $exceptId): array
    {
        $name = $request->input('name');
        $locationText = $request->input('itflow_location_id');
        if ($name === '' || mb_strlen($name) > 150 || preg_match('/[\x00-\x1F\x7F]/u', $name)) {
            return ['', null, __('Enter a site name of up to 150 characters.')];
        }
        if (App::clients()->siteNameTaken($clientId, $name, $exceptId)) {
            return ['', null, __('This client already has a site with that name.')];
        }
        if ($locationText !== '' && (!preg_match('/^[1-9][0-9]{0,9}$/', $locationText) || (int) $locationText > 4294967295)) {
            return ['', null, __('Enter the numeric ITFlow location ID, or leave it empty.')];
        }
        return [$name, $locationText === '' ? null : (int) $locationText, null];
    }

    /**
     * Summary of a client's authorisations for the list page.
     *
     * @param list<array<string,mixed>> $authorisations
     * @return array{status:string,valid_until:?string}
     */
    private function authSummary(array $authorisations, string $timezone): array
    {
        $today = ScopeService::today($timezone);
        $best = ['status' => 'none', 'valid_until' => null];
        foreach ($authorisations as $a) {
            $status = ScopeService::status($a, $today);
            if ($status === ScopeService::STATUS_ACTIVE && ($best['status'] !== 'active' || $a['valid_until'] > $best['valid_until'])) {
                $best = ['status' => 'active', 'valid_until' => (string) $a['valid_until']];
            } elseif ($best['status'] === 'none' && $status !== ScopeService::STATUS_REVOKED) {
                $best = ['status' => $status, 'valid_until' => (string) $a['valid_until']];
            }
        }
        return $best;
    }

    /** @return array<string,mixed> The client, or a 404. */
    private function findOr404(array $params): array
    {
        return App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }
}
