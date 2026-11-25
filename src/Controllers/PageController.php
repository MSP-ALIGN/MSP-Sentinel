<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\View;

/**
 * Simple read-only pages: dashboard and help.
 *
 * Security assumptions: no input is used apart from the signed-in user.
 * Help entries are trusted text shipped with the app, and are still
 * escaped in the view.
 */
final class PageController extends Controller
{
    /** GET /: the main dashboard ("command view"). */
    public function dashboard(Request $request): Response
    {
        $isAdmin = App::auth()->can('engagements.approve');
        return $this->page('dashboard', __('Dashboard'), ['d' => self::dashboardData(), 'globallyPaused' => App::scope()->globallyPaused(),
            // Engagements someone else created that this user can approve (1.34: approvals were easy to miss).
            'awaitingApproval' => $isAdmin ? App::engagements()->awaitingApprovalBy((int) $this->user()['id'], App::auth()->clientIds(), \Sentinel\Controllers\EngagementController::twoPerson()) : [],
            // The first-run checklist (1.51), for whoever sets Sentinel up; it counts every client, so only for users who see all.
            'setup' => self::setupSteps()]);
    }

    /**
     * The first-run checklist's steps when this user should see it (can manage settings, sees every client, not
     * hidden, not finished), else [].
     *
     * @return list<array<string,mixed>>
     */
    private static function setupSteps(): array
    {
        if (!App::auth()->can('settings.manage') || App::auth()->clientIds() !== null) {
            return [];
        }
        $list = new \Sentinel\Dashboard\SetupChecklist(App::db(), App::settings());
        return $list->visible() ? $list->steps() : [];
    }

    /** POST /dashboard/setup-checklist/hide: hide the first-run checklist for everyone (settings.manage; CSRF-checked by the router). */
    public function hideSetup(Request $request): Response
    {
        App::settings()->set('setup_checklist_hidden', '1');
        $this->audit($request, 'settings.setup_checklist_hidden', null, null, []);
        return Response::redirect('/');
    }

    /** GET /dashboard/live: the dashboard panels alone, for the 60-second refresh (any signed-in role). */
    public function live(Request $request): Response
    {
        return Response::html(View::render('dashboard/panels', ['d' => self::dashboardData(), 'currentUser' => $this->user()], null))->header('X-Sentinel-Fragment', '1');
    }

    /**
     * Everything the dashboard shows (read-only).
     *
     * @return array<string,mixed>
     */
    private static function dashboardData(): array
    {
        $data = App::dashboard(); // limited to the user's clients (1.41)
        $only = \Sentinel\Auth\ClientAccess::sql('a.client_id', App::auth()->clientIds());
        $clients = $data->clients();
        $totals = ['fail' => 0, 'warn' => 0, 'kev' => 0];
        foreach ($clients as $c) {
            $totals['fail'] += $c['fail'];
            $totals['warn'] += $c['warn'];
            $totals['kev'] += $c['kev'];
        }
        return [
            'clients' => $clients,
            'totals' => $totals,
            'trend' => $data->trend(90, null, $totals['fail'], $totals['warn']),
            'activity' => $data->activity(12),
            'surface' => $data->surface(),
            'top' => $data->topExposures(6),
            'certs' => $data->certificates(30),
            'certsSoon' => $data->certificateCount(\Sentinel\Scanning\ExposureRules::EXPIRY_WARN_DAYS),
            'ops' => $data->ops(),
            'kevPossible' => App::vulns()->kevCounts(App::auth()->clientIds())['possible_kev'],
            'authorisations' => [
                'active' => (int) App::db()->query('SELECT COUNT(*) FROM scan_authorisations a JOIN clients c ON c.id = a.client_id AND c.is_archived = 0
                    WHERE a.revoked_at IS NULL AND a.valid_from <= UTC_DATE() AND a.valid_until >= UTC_DATE()' . $only)->fetchColumn(),
                'ending' => (int) App::db()->query('SELECT COUNT(*) FROM scan_authorisations a JOIN clients c ON c.id = a.client_id AND c.is_archived = 0
                    WHERE a.revoked_at IS NULL AND a.valid_until BETWEEN UTC_DATE() AND UTC_DATE() + INTERVAL 30 DAY' . $only)->fetchColumn(),
            ],
        ];
    }

    /**
     * GET /search?q=: the top bar's search across clients, findings, hosts, devices, engagements and help (1.34).
     * Every signed-in user; the query is untrusted and only ever a bound, escaped LIKE value (SearchService).
     */
    public function search(Request $request): Response
    {
        $q = \Sentinel\Search\SearchService::normalise($request->query('q'));
        $entries = require SENTINEL_ROOT . '/help/entries.php';
        $topics = is_array($entries) && is_array($entries['topics'] ?? null) ? $entries['topics'] : [];
        $results = (new \Sentinel\Search\SearchService(App::db()))->search($q, $topics, App::auth()->clientIds()); // only the user's clients (1.41)
        return $this->page('search/index', $q === '' ? __('Search') : __('Search: {q}', ['q' => $q]), ['q' => $q, 'raw' => mb_substr($request->query('q'), 0, 100), 'searchQuery' => mb_substr($request->query('q'), 0, 100), 'results' => $results]);
    }

    /** GET /help */
    public function help(Request $request): Response
    {
        $entries = require SENTINEL_ROOT . '/help/entries.php';
        return $this->page('help/index', __('Help'), ['entries' => is_array($entries) ? $entries : []]);
    }
}
