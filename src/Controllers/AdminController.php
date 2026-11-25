<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Findings\FixWorkflow;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * Admin pages: the Administration overview, audit log and general settings
 * (admin only: enforced by the routes).
 *
 * Untrusted: the page query parameter and all settings form fields.
 *
 * Security assumptions:
 * - The audit log is read-only in the UI.
 * - Settings are validated strictly before saving: the product name is
 *   plain text, and the source URL must be an http(s) URL. Both are escaped
 *   wherever they're shown.
 */
final class AdminController extends Controller
{
    private const AUDIT_PAGE_SIZE = 50;

    /** GET /admin: the Administration overview, one card per area with its key status. */
    public function index(Request $request): Response
    {
        $db = App::db();
        $checks = App::health()->run();
        $tokens = (int) $db->query('SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL AND expires_at > UTC_TIMESTAMP()')->fetchColumn();
        return $this->page('admin/index', __('Administration'), [
            'users' => [
                'active' => (int) $db->query('SELECT COUNT(*) FROM users WHERE is_active = 1')->fetchColumn(),
                'admins' => App::roles()->completeHoldersAfter(), // users who hold every permission (1.40)
            ],
            'email' => App::settings()->get('email_enabled') === '1',
            'webhook' => App::settings()->get('webhook_enabled') === '1',
            'tokens' => $tokens,
            'events' => App::settings()->get('event_webhook_enabled') === '1',
            // Labels of the inventory sources that are connected and on (1.52: any registered RMM).
            'inventoryOn' => array_values(array_map(static fn (\Sentinel\Inventory\InventorySource $s): string => $s->label(), App::inventorySources())),
            'problems' => count(array_filter($checks, static fn (array $c): bool => $c['status'] === 'fail')),
            'warnings' => count(array_filter($checks, static fn (array $c): bool => $c['status'] === 'warn')),
            'newer' => App::updates()->newer(),
            'audit' => (int) $db->query('SELECT COUNT(*) FROM audit_log WHERE created_at > UTC_TIMESTAMP() - INTERVAL 1 DAY')->fetchColumn(),
        ]);
    }

    /** GET /admin/audit */
    public function auditLog(Request $request): Response
    {
        $page = max(1, min(100000, (int) $request->query('page')));
        // Text filter (1.34): action, user name or details contain it (bound, LIKE wildcards escaped).
        $q = \Sentinel\Search\SearchService::normalise($request->query('q'));
        $where = $q === '' ? '1 = 1' : "(action LIKE :q1 ESCAPE '!' OR username LIKE :q2 ESCAPE '!' OR details LIKE :q3 ESCAPE '!' OR target_type LIKE :q4 ESCAPE '!')";
        $params = $q === '' ? [] : array_fill_keys(['q1', 'q2', 'q3', 'q4'], \Sentinel\Search\SearchService::like($q));
        $count = App::db()->prepare("SELECT COUNT(*) FROM audit_log WHERE {$where}");
        $count->execute($params);
        $total = (int) $count->fetchColumn();
        $stmt = App::db()->prepare("SELECT * FROM audit_log WHERE {$where} ORDER BY id DESC LIMIT :lim OFFSET :off");
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue('lim', self::AUDIT_PAGE_SIZE, \PDO::PARAM_INT);
        $stmt->bindValue('off', ($page - 1) * self::AUDIT_PAGE_SIZE, \PDO::PARAM_INT);
        $stmt->execute();
        return $this->page('audit/index', __('Audit log'), [
            'entries' => $stmt->fetchAll(),
            'page' => $page,
            'pages' => max(1, (int) ceil($total / self::AUDIT_PAGE_SIZE)),
            'q' => $q,
            'total' => $total,
        ]);
    }

    /** GET /admin/settings */
    public function settings(Request $request): Response
    {
        $settings = App::settings();
        return $this->settingsPage(['product_name' => $settings->get('product_name'), 'source_url' => $settings->get('source_url'),
            'display_timezone' => $settings->get('display_timezone')], [], 200);
    }

    /** The Settings page with these General values and errors (also the 422 re-render of saveSettings). */
    private function settingsPage(array $values, array $errors, int $status): Response
    {
        return $this->page('settings/index', __('Settings'), [
            'values' => $values,
            'errors' => $errors,
            // Clients still on UTC while the organisation's zone is another (1.48: the one-time "move" button).
            'utcClients' => App::settings()->get('display_timezone') === 'UTC' ? [] : App::db()->query("SELECT id, name FROM clients WHERE timezone = 'UTC' AND is_archived = 0 AND is_demo = 0 ORDER BY name")->fetchAll(),
            'mayEditClients' => App::auth()->can('clients.manage'),
            'orgZone' => App::settings()->get('display_timezone'), // the stored zone: what the move button really uses (1.48.1)
            'feeds' => App::vulns()->feedStatuses(),
            'nvdKeySet' => trim((string) App::config()->get('nvd.api_key', '')) !== '',
            'nvdKeyUsable' => \Sentinel\Vulns\FeedUpdater::usableKey(App::config()) !== null,
            'alerts' => self::alertSettings(),
            'branding' => ReportController::brandingSettings(),
            'duePolicy' => App::fixWorkflow()->policy(),
            'twoPerson' => EngagementController::twoPerson(),
            'mayChangeTwoPerson' => \Sentinel\Auth\Permissions::isComplete((array) ($this->user()['permissions'] ?? [])) && ($this->user()['client_ids'] ?? null) === null,
            'feedsRefresh' => (new \Sentinel\Vulns\FeedSchedule(App::settings()))->status(),
        ], $status);
    }

    /** POST /admin/settings/engagements: whether pen-test engagements need a second person to approve (1.47). */
    public function saveEngagementPolicy(Request $request): Response
    {
        $back = Response::redirect('/admin/settings#engagements');
        // It weakens a safety control: only an Admin who holds every permission and sees every client, with their own
        // password (1.47). Audited, and everyone who may approve engagements is told.
        if (!\Sentinel\Auth\Permissions::isComplete((array) ($this->user()['permissions'] ?? [])) || ($this->user()['client_ids'] ?? null) !== null) {
            throw new \Sentinel\Core\HttpException(403, __('Only someone who holds every permission (an Admin) and sees every client can change engagement approval.'));
        }
        if (($why = $this->confirmWithOwnPassword($request)) !== null) {
            Session::flash('danger', $why);
            return $back;
        }
        // Explicit values only (1.47.1): the form sends a hidden "0" before the box's "1", so a request without the field
        // never turns the rule off.
        $choice = $request->input('two_person');
        if (!in_array($choice, ['0', '1'], true)) {
            Session::flash('danger', __('Nothing changed.'));
            return $back;
        }
        $twoPerson = $choice === '1';
        if ($twoPerson === EngagementController::twoPerson()) {
            Session::flash('info', __('Nothing changed.'));
            return $back;
        }
        App::settings()->set('engagement_two_person', $twoPerson ? '1' : '0');
        $this->audit($request, 'settings.engagement_approval', null, null, ['two_person' => $twoPerson]);
        $who = (string) ($this->user()['display_name'] ?: $this->user()['username']);
        App::alerts()->notifyAllWith('engagements.approve', 'security', $twoPerson ? 'info' : 'warn',
            $twoPerson ? __('Pen-test engagements need two people to approve again') : __('Pen-test engagements no longer need a second person to approve'),
            $twoPerson ? __('{who} turned two-person approval back on. Every engagement now needs someone other than its creator to approve it.', ['who' => $who])
                : __('{who} turned two-person approval off. From now on, whoever creates an engagement may approve it themselves if they may approve engagements. Engagements created before still need a second person.', ['who' => $who]),
            '/engagements');
        Session::flash('success', $twoPerson ? __('Two-person approval is on.') : __('Two-person approval is off for new engagements.'));
        return $back;
    }

    /**
     * POST /admin/settings/clients-timezone (1.48): move the clients still on UTC to the organisation's time zone,
     * once. Their scan window times stay the same numbers, now read as local time. Needs Manage settings (the route)
     * and Edit clients; audited with the list of clients.
     */
    public function moveClientsTimezone(Request $request): Response
    {
        $back = Response::redirect('/admin/settings');
        if (!App::auth()->can('clients.manage')) {
            throw new \Sentinel\Core\HttpException(403, __('Changing clients needs the permission to edit clients.'));
        }
        $zone = App::settings()->get('display_timezone');
        if ($zone === 'UTC' || !valid_timezone($zone)) {
            Session::flash('warning', __('Choose the organization\'s time zone first.'));
            return $back;
        }
        $rows = App::db()->query("SELECT id, name FROM clients WHERE timezone = 'UTC' AND is_archived = 0 AND is_demo = 0 ORDER BY name")->fetchAll();
        if ($rows === []) {
            Session::flash('info', __('No client is on UTC.'));
            return $back;
        }
        $upd = App::db()->prepare("UPDATE clients SET timezone = :z, updated_at = UTC_TIMESTAMP() WHERE id = :id AND timezone = 'UTC'");
        foreach ($rows as $r) {
            $upd->execute(['z' => $zone, 'id' => (int) $r['id']]);
        }
        $this->audit($request, 'clients.timezone_moved', null, null, ['timezone' => $zone, 'clients' => array_map(static fn (array $r): string => (string) $r['name'], $rows)]);
        Session::flash('success', __('{n} client(s) moved to {zone}. Their scan windows now count in that time zone.', ['n' => count($rows), 'zone' => $zone]));
        return $back;
    }

    /** POST /admin/settings/due-dates: days to fix by severity (known-exploited, Fail, Warning). */
    public function saveDuePolicy(Request $request): Response
    {
        $s = App::settings();
        $new = [];
        foreach (['kev', 'fail', 'warn'] as $k) {
            $v = $request->input('due_days_' . $k);
            if (!ctype_digit($v) || str_starts_with($v, '0') || (int) $v < FixWorkflow::MIN_DAYS || (int) $v > FixWorkflow::MAX_DAYS) {
                Session::flash('danger', __('Enter whole days from {min} to {max}.', ['min' => FixWorkflow::MIN_DAYS, 'max' => FixWorkflow::MAX_DAYS]));
                return Response::redirect('/admin/settings#due-dates');
            }
            $new[$k] = (int) $v;
        }
        $old = App::fixWorkflow()->policy();
        foreach ($new as $k => $v) {
            $s->set('due_days_' . $k, (string) $v);
        }
        App::fixWorkflow()->recomputeDue(null); // every finding that follows the policy gets its new date now
        if ($old !== $new) {
            $this->audit($request, 'settings.due_policy_updated', null, null, ['from' => $old, 'to' => $new]);
        }
        Session::flash('success', __('Due dates saved. Findings that follow the policy were updated.'));
        return Response::redirect('/admin/settings#due-dates');
    }

    /**
     * Alert settings for the form: secrets are reported only as set or not set.
     *
     * @return array<string,mixed>
     */
    private static function alertSettings(): array
    {
        $s = App::settings();
        $values = [];
        foreach (['email_enabled', 'smtp_host', 'smtp_port', 'smtp_security', 'smtp_username', 'smtp_from', 'team_addresses', 'webhook_enabled', 'webhook_format'] as $k) {
            $values[$k] = $s->get($k);
        }
        return $values + [
            'password_set' => $s->get('smtp_password') !== '',
            'webhook_set' => $s->get('webhook_url') !== '',
            'recent' => App::outbox()->recent(),
            'public_url' => (string) App::config()->get('app.public_url', ''),
        ];
    }

    /** POST /admin/settings */
    public function saveSettings(Request $request): Response
    {
        $values = ['product_name' => $request->input('product_name'), 'source_url' => $request->input('source_url'), 'display_timezone' => $request->input('display_timezone') !== '' ? $request->input('display_timezone') : App::settings()->get('display_timezone')]; // missing: unchanged
        $errors = [];
        if ($values['product_name'] === '' || mb_strlen($values['product_name']) > 60 || preg_match('/[\x00-\x1F\x7F<>]/u', $values['product_name'])) {
            $errors['product_name'] = __('Enter a name of up to 60 characters, without < or >.');
        }
        $scheme = strtolower((string) parse_url($values['source_url'], PHP_URL_SCHEME));
        if (mb_strlen($values['source_url']) > 255 || filter_var($values['source_url'], FILTER_VALIDATE_URL) === false || !in_array($scheme, ['http', 'https'], true)) {
            $errors['source_url'] = __('Enter a full http:// or https:// address.');
        }
        // The organisation's time zone (1.48): only a zone from PHP's list (untrusted input).
        if (!valid_timezone($values['display_timezone'])) {
            $errors['display_timezone'] = __('Choose a time zone from the list.');
        }
        if ($errors !== []) {
            return $this->settingsPage($values, $errors, 422);
        }

        $settings = App::settings();
        $changed = [];
        foreach ($values as $name => $value) {
            if ($settings->get($name) !== $value) {
                $changed[$name] = $value;
                $settings->set($name, $value);
            }
        }
        if ($changed !== []) {
            $this->audit($request, 'settings.updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', __('Settings saved.'));
        return Response::redirect('/admin/settings');
    }

    /**
     * POST /admin/feeds/refresh (admins; CSRF-checked like every POST): ask for a vulnerability data refresh. The
     * cron job (bin/feeds.php --if-due, every 5 minutes) picks it up; nothing runs in this web request.
     * Untrusted input: none.
     */
    public function refreshFeeds(Request $request): Response
    {
        $schedule = new \Sentinel\Vulns\FeedSchedule(App::settings());
        $status = $schedule->status();
        if ($status['running'] || $status['requested']) {
            Session::flash('info', __('A refresh is already waiting or running.'));
        } else {
            $schedule->request();
            $this->audit($request, 'feeds.refresh_requested');
            Session::flash('success', __('Refresh requested: it starts within 5 minutes and can take a while the first time.'));
        }
        return Response::redirect('/admin/settings#feeds');
    }
}
