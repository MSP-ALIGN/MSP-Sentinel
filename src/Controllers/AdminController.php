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
                'admins' => (int) $db->query("SELECT COUNT(*) FROM users WHERE is_active = 1 AND role = 'admin'")->fetchColumn(),
            ],
            'email' => App::settings()->get('email_enabled') === '1',
            'webhook' => App::settings()->get('webhook_enabled') === '1',
            'tokens' => $tokens,
            'events' => App::settings()->get('event_webhook_enabled') === '1',
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
        $total = (int) App::db()->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
        $stmt = App::db()->prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT :lim OFFSET :off');
        $stmt->bindValue('lim', self::AUDIT_PAGE_SIZE, \PDO::PARAM_INT);
        $stmt->bindValue('off', ($page - 1) * self::AUDIT_PAGE_SIZE, \PDO::PARAM_INT);
        $stmt->execute();
        return $this->page('audit/index', __('Audit log'), [
            'entries' => $stmt->fetchAll(),
            'page' => $page,
            'pages' => max(1, (int) ceil($total / self::AUDIT_PAGE_SIZE)),
        ]);
    }

    /** GET /admin/settings */
    public function settings(Request $request): Response
    {
        $settings = App::settings();
        return $this->page('settings/index', __('Settings'), [
            'values' => ['product_name' => $settings->get('product_name'), 'source_url' => $settings->get('source_url')],
            'errors' => [],
            'feeds' => App::vulns()->feedStatuses(),
            'nvdKeySet' => trim((string) App::config()->get('nvd.api_key', '')) !== '',
            'nvdKeyUsable' => \Sentinel\Vulns\FeedUpdater::usableKey(App::config()) !== null,
            'alerts' => self::alertSettings(),
            'branding' => ReportController::brandingSettings(),
            'duePolicy' => App::fixWorkflow()->policy(),
        ]);
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
        $values = ['product_name' => $request->input('product_name'), 'source_url' => $request->input('source_url')];
        $errors = [];
        if ($values['product_name'] === '' || mb_strlen($values['product_name']) > 60 || preg_match('/[\x00-\x1F\x7F<>]/u', $values['product_name'])) {
            $errors['product_name'] = __('Enter a name of up to 60 characters, without < or >.');
        }
        $scheme = strtolower((string) parse_url($values['source_url'], PHP_URL_SCHEME));
        if (mb_strlen($values['source_url']) > 255 || filter_var($values['source_url'], FILTER_VALIDATE_URL) === false || !in_array($scheme, ['http', 'https'], true)) {
            $errors['source_url'] = __('Enter a full http:// or https:// address.');
        }
        if ($errors !== []) {
            return $this->page('settings/index', __('Settings'), ['values' => $values, 'errors' => $errors,
                'feeds' => App::vulns()->feedStatuses(), 'nvdKeySet' => trim((string) App::config()->get('nvd.api_key', '')) !== '',
                'nvdKeyUsable' => \Sentinel\Vulns\FeedUpdater::usableKey(App::config()) !== null, 'alerts' => self::alertSettings(), 'branding' => ReportController::brandingSettings(), 'duePolicy' => App::fixWorkflow()->policy()], 422);
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
}
