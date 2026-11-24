<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Alerts\WebhookSender;
use Sentinel\Api\EventPublisher;
use Sentinel\Api\TokenService;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Scope\IpRange;

/**
 * Admin page for API tokens and the outbound event webhook.
 *
 * Access (enforced by the routes): admins only.
 *
 * Untrusted: token name, client IDs, permission checkboxes, IP allowlist,
 * expiry choice, event webhook URL.
 *
 * Security assumptions:
 * - A new token (and a new signing secret) is shown exactly once: it is
 *   kept in the session only until the next page view, then removed.
 *   Neither is ever stored in plain text in the database or the audit log.
 * - Triage and scan permissions are off unless ticked.
 * - The event webhook URL gets the same SSRF checks as the alert webhook.
 * - Every change is audited.
 */
final class ApiAdminController extends Controller
{
    private const EXPIRY_CHOICES = [30, 90, 180, 365];

    /**
     * The API reference as a page (1.34): the same OpenAPI description the API serves at /api/v1/openapi.json (which
     * needs a token), shown to admins in the browser, with a download of the JSON. Static text only; all escaped.
     */
    public function docs(Request $request): Response
    {
        $spec = \Sentinel\Api\OpenApi::spec(App::version());
        if ($request->query('format') === 'json') {
            return (new Response((string) json_encode($spec, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)))
                ->header('Content-Type', 'application/json')->header('Content-Disposition', 'attachment; filename="msp-sentinel-openapi.json"');
        }
        return $this->page('api/docs', __('API reference'), ['spec' => $spec]);
    }

    /** GET /admin/api */
    public function index(Request $request): Response
    {
        $newToken = Session::get('show_api_token');
        $newSecret = Session::get('show_event_secret');
        Session::remove('show_api_token');
        Session::remove('show_event_secret');
        $s = App::settings();
        $recent = App::db()->query("SELECT id, subject, status, attempts, last_error, created_at, sent_at FROM deliveries WHERE channel = 'event' ORDER BY id DESC LIMIT 10")->fetchAll();
        return $this->page('api/index', __('API'), [
            'tokens' => App::apiTokens()->all(App::auth()->clientIds()),
            'clients' => App::clients()->all(false, App::auth()->clientIds()),
            'newToken' => is_string($newToken) ? $newToken : null,
            'newSecret' => is_string($newSecret) ? $newSecret : null,
            'events' => ['enabled' => $s->get('event_webhook_enabled'), 'url_set' => $s->get('event_webhook_url') !== '', 'secret_set' => $s->get('event_webhook_secret') !== '', 'recent' => $recent],
        ]);
    }

    /** POST /admin/api/tokens */
    public function create(Request $request): Response
    {
        $name = $request->input('name');
        $all = $request->input('all_clients') === '1';
        $clientIds = array_values(array_unique(array_map('intval', array_filter($request->postList('clients'), 'ctype_digit'))));
        $days = (int) $request->input('expires_days');
        $errors = [];
        if (($why = $this->confirmWithOwnPassword($request)) !== null) {
            $errors[] = $why; // a token can act as this admin for up to a year
        }
        if ($name === '' || mb_strlen($name) > 100 || !mb_check_encoding($name, 'UTF-8') || preg_match('/[\x00-\x1F\x7F]/u', $name)) {
            $errors[] = __('Give the token a name (up to 100 characters), for example "MSP Align".');
        }
        if (!in_array($days, self::EXPIRY_CHOICES, true)) {
            $errors[] = __('Choose when the token expires.');
        }
        // Only clients you see yourself (1.42): "All clients" only if you see every client.
        $known = array_map(static fn (array $c): int => (int) $c['id'], App::clients()->all(true, App::auth()->clientIds()));
        if ($all && App::auth()->clientIds() !== null) {
            $errors[] = __('You see only some clients, so a token can\'t have all clients.');
        } elseif (!$all && ($clientIds === [] || array_diff($clientIds, $known) !== [])) {
            $errors[] = __('Choose "All clients" or at least one client (only clients you see).');
        }
        $ips = [];
        foreach (array_filter(array_map('trim', preg_split('/[\s,]+/', $request->input('ip_allowlist')) ?: [])) as $entry) {
            $range = IpRange::parse($entry);
            if ($range === null) {
                $errors[] = __('"{entry}" is not an IP address or network (for example 203.0.113.10 or 203.0.113.0/24).', ['entry' => mb_substr($entry, 0, 60)]);
                break;
            }
            $ips[] = $range->canonical();
        }
        if (count($ips) > 20 || strlen(implode(',', $ips)) > 1000) {
            $errors[] = __('At most 20 addresses or networks.');
        }
        $triage = $request->input('can_triage') === '1';
        $scan = $request->input('can_scan') === '1';
        // Never more than you hold (1.40.1): a token can't triage or scan unless its creator may.
        if (($triage && !App::auth()->can('findings.triage')) || ($scan && !App::auth()->can('scans.run'))) {
            $errors[] = __('A token can only triage findings or start scans if you may do that yourself.');
        }
        if ($errors !== []) {
            foreach ($errors as $e) {
                Session::flash('danger', $e);
            }
            return Response::redirect('/admin/api');
        }
        [$id, $token] = App::apiTokens()->create($name, $all, $clientIds, $triage, $scan, $ips, $days, (int) $this->user()['id']);
        $this->audit($request, 'api.token_created', 'api_token', $id, ['name' => $name, 'all_clients' => $all, 'clients' => $all ? [] : $clientIds,
            'triage' => $triage, 'scan' => $scan, 'ip_allowlist' => $ips, 'days' => $days]);
        Session::set('show_api_token', $token);
        return Response::redirect('/admin/api');
    }

    /** POST /admin/api/tokens/{id}/revoke */
    public function revoke(Request $request, array $params): Response
    {
        $id = (int) ($params['id'] ?? 0);
        if (!App::apiTokens()->revoke($id, (int) $this->user()['id'], App::auth()->clientIds())) {
            throw new HttpException(404);
        }
        $this->audit($request, 'api.token_revoked', 'api_token', $id);
        Session::flash('success', __('Token revoked. It stops working immediately.'));
        return Response::redirect('/admin/api');
    }

    /** POST /admin/api/events: event webhook on/off and URL. */
    public function events(Request $request): Response
    {
        // Events carry every client's changes: only someone who sees every client sets them up (1.42).
        if (App::auth()->clientIds() !== null) {
            throw new HttpException(403, __('Event webhooks send every client\'s changes, so only someone who sees every client can set them up.'));
        }
        $s = App::settings();
        $enabled = $request->input('event_webhook_enabled') === '1';
        $url = $request->input('event_webhook_url');
        if ($url !== '') {
            $check = (new WebhookSender(App::webhookTestMode()))->check($url);
            if (is_string($check)) {
                Session::flash('danger', $check);
                return Response::redirect('/admin/api#events');
            }
        }
        if ($enabled && $url === '' && $s->get('event_webhook_url') === '') {
            Session::flash('danger', __('To turn events on, enter the receiving address.'));
            return Response::redirect('/admin/api#events');
        }
        $changed = [];
        if ($url !== '') {
            $s->setSecret('event_webhook_url', $url);
            $changed['url'] = 'changed';
        }
        if ($enabled && $s->get('event_webhook_secret') === '') {
            $secret = self::newSecret();
            $s->setSecret('event_webhook_secret', $secret);
            Session::set('show_event_secret', $secret);
            $changed['secret'] = 'created';
        }
        if ($s->get('event_webhook_enabled') !== ($enabled ? '1' : '0')) {
            $s->set('event_webhook_enabled', $enabled ? '1' : '0');
            $changed['enabled'] = $enabled;
        }
        if ($changed !== []) {
            $this->audit($request, 'settings.events_updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', __('Event settings saved.'));
        return Response::redirect('/admin/api#events');
    }

    /** POST /admin/api/events/secret: a new signing secret (shown once). */
    public function secret(Request $request): Response
    {
        // Events carry every client's changes: only someone who sees every client sets them up (1.42).
        if (App::auth()->clientIds() !== null) {
            throw new HttpException(403, __('Event webhooks send every client\'s changes, so only someone who sees every client can set them up.'));
        }
        $secret = self::newSecret();
        App::settings()->setSecret('event_webhook_secret', $secret);
        Session::set('show_event_secret', $secret);
        $this->audit($request, 'settings.events_secret_rotated');
        return Response::redirect('/admin/api#events');
    }

    /** POST /admin/api/events/test: send a "ping" event now. */
    public function test(Request $request): Response
    {
        // Events carry every client's changes: only someone who sees every client sets them up (1.42).
        if (App::auth()->clientIds() !== null) {
            throw new HttpException(403, __('Event webhooks send every client\'s changes, so only someone who sees every client can set them up.'));
        }
        if (App::settings()->get('event_webhook_enabled') !== '1') {
            Session::flash('danger', __('Turn events on first.'));
            return Response::redirect('/admin/api#events');
        }
        App::events()->publish('ping', ['message' => 'Test event from MSP Sentinel.']);
        $id = (int) App::db()->query("SELECT MAX(id) FROM deliveries WHERE channel = 'event' AND subject = 'ping'")->fetchColumn();
        App::outbox()->flush(1, $id);
        $row = App::db()->query('SELECT status, last_error FROM deliveries WHERE id = ' . $id)->fetch();
        if ($row !== false && $row['status'] === 'sent') {
            Session::flash('success', __('Test event delivered.'));
        } else {
            App::db()->prepare("UPDATE deliveries SET status = 'failed' WHERE id = :id AND status = 'pending'")->execute(['id' => $id]);
            Session::flash('danger', __('Sending failed: {e}', ['e' => (string) ($row['last_error'] ?? '')]));
        }
        return Response::redirect('/admin/api#events');
    }

    /** A random signing secret. */
    private static function newSecret(): string
    {
        return 'whsec_' . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
