<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Alerts\SmtpMailer;
use Sentinel\Alerts\WebhookSender;
use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * Alerts: admin settings (SMTP, team addresses, webhook) with test buttons,
 * the in-app notification list, and each user's email and appearance preferences.
 *
 * Access (enforced by the routes): settings and tests are admin-only;
 * notifications and the email and appearance preferences belong to the signed-in user.
 *
 * Untrusted: every form field.
 *
 * Security assumptions:
 * - The SMTP password and webhook URL are write-only: stored encrypted,
 *   never shown again, kept when the field is left empty, cleared only
 *   with the explicit checkbox.
 * - The webhook URL must be https and resolve to public addresses (WebhookSender::check).
 * - Hosts and addresses are validated strictly. Changes are audited
 *   without the secret values.
 */
final class AlertController extends Controller
{
    /** POST /admin/alerts */
    public function save(Request $request): Response
    {
        $settings = App::settings();
        $errors = [];
        $v = [
            'email_enabled' => $request->input('email_enabled') === '1' ? '1' : '0',
            'smtp_host' => strtolower($request->input('smtp_host')),
            'smtp_port' => $request->input('smtp_port'),
            'smtp_security' => $request->input('smtp_security'),
            'smtp_username' => $request->input('smtp_username'),
            'smtp_from' => $request->input('smtp_from'),
            'team_addresses' => implode(',', array_filter(array_map('trim', preg_split('/[,;\s]+/', $request->input('team_addresses')) ?: []))),
            'webhook_enabled' => $request->input('webhook_enabled') === '1' ? '1' : '0',
            'webhook_format' => $request->input('webhook_format'),
        ];
        if ($v['smtp_host'] !== '' && !preg_match('/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/', $v['smtp_host']) && filter_var($v['smtp_host'], FILTER_VALIDATE_IP) === false) {
            $errors[] = __('The mail server must be a host name or IP address.');
        }
        if (!preg_match('/^\d{1,5}$/', $v['smtp_port']) || (int) $v['smtp_port'] < 1 || (int) $v['smtp_port'] > 65535) {
            $errors[] = __('The mail server port must be a number from 1 to 65535.');
        }
        if (!in_array($v['smtp_security'], ['starttls', 'tls', 'none'], true)) {
            $errors[] = __('Choose how to connect to the mail server.');
        }
        if (mb_strlen($v['smtp_username']) > 190 || preg_match('/[\x00-\x1F\x7F]/u', $v['smtp_username'])) {
            $errors[] = __('The mail server user name is not valid.');
        }
        if ($v['smtp_from'] !== '' && !SmtpMailer::validAddress($v['smtp_from'])) {
            $errors[] = __('The sender address is not a valid email address.');
        }
        $team = $v['team_addresses'] === '' ? [] : explode(',', $v['team_addresses']);
        if (count($team) > 5 || array_filter($team, static fn (string $a): bool => !SmtpMailer::validAddress($a)) !== []) {
            $errors[] = __('Team addresses: up to 5 valid email addresses, separated by commas.');
        }
        if ($v['email_enabled'] === '1' && ($v['smtp_host'] === '' || $v['smtp_from'] === '')) {
            $errors[] = __('To turn email on, enter the mail server and the sender address.');
        }
        if ($v['email_enabled'] === '1' && $v['smtp_security'] === 'none' && !in_array($v['smtp_host'], ['127.0.0.1', '::1', 'localhost'], true)) {
            $errors[] = __('Unencrypted SMTP is only allowed to a relay on this server (127.0.0.1).');
        }
        if (!in_array($v['webhook_format'], WebhookSender::FORMATS, true)) {
            $errors[] = __('Choose a webhook format.');
        }
        $newUrl = $request->input('webhook_url');
        if ($newUrl !== '') {
            $check = (new WebhookSender(App::webhookTestMode()))->check($newUrl);
            if (is_string($check)) {
                $errors[] = $check;
            }
        }
        $hasUrl = $newUrl !== '' || ($settings->get('webhook_url') !== '' && $request->input('clear_webhook') !== '1');
        if ($v['webhook_enabled'] === '1' && !$hasUrl) {
            $errors[] = __('To turn the webhook on, enter its address.');
        }
        if ($errors !== []) {
            foreach ($errors as $e) {
                Session::flash('danger', $e);
            }
            return Response::redirect('/admin/settings#alerts');
        }

        $changed = [];
        // A saved SMTP password never follows a new mail server: a changed host needs the password entered again.
        if (isset($v['smtp_host']) && $settings->get('smtp_host') !== $v['smtp_host'] && $settings->getSecret('smtp_password') !== '' && $request->raw('smtp_password') === '') {
            $settings->setSecret('smtp_password', '');
            $changed['smtp_password'] = 'cleared (server changed)';
            Session::flash('warning', __('The mail server changed, so the saved SMTP password was removed. Enter it again for the new server.'));
        }
        foreach ($v as $name => $value) {
            if ($settings->get($name) !== $value) {
                $settings->set($name, $value);
                $changed[$name] = $name === 'team_addresses' ? count($team) . ' address(es)' : $value;
            }
        }
        $password = $request->raw('smtp_password');
        if ($request->input('clear_password') === '1') {
            $settings->setSecret('smtp_password', '');
            $changed['smtp_password'] = 'cleared';
        } elseif ($password !== '') {
            $settings->setSecret('smtp_password', $password);
            $changed['smtp_password'] = 'changed';
        }
        if ($request->input('clear_webhook') === '1') {
            $settings->setSecret('webhook_url', '');
            $changed['webhook_url'] = 'cleared';
        } elseif ($newUrl !== '') {
            $settings->setSecret('webhook_url', $newUrl);
            $changed['webhook_url'] = 'changed';
        }
        if ($changed !== []) {
            $this->audit($request, 'settings.alerts_updated', null, null, ['changed' => $changed]);
        }
        Session::flash('success', __('Alert settings saved.'));
        return Response::redirect('/admin/settings#alerts');
    }

    /** POST /admin/alerts/test: send a test email (to the current admin) or webhook right now. */
    public function test(Request $request): Response
    {
        $channel = $request->input('channel');
        $user = $this->user();
        $db = App::db();
        if ($channel === 'email') {
            if (!SmtpMailer::validAddress((string) $user['email'])) {
                Session::flash('danger', __('Add an email address to your user account first: the test goes to you.'));
                return Response::redirect('/admin/settings#alerts');
            }
            $db->prepare("INSERT INTO deliveries (channel, recipient, subject, body, status, next_attempt_at, created_at) VALUES ('email', :r, :s, :b, 'pending', UTC_TIMESTAMP(), UTC_TIMESTAMP())")
                ->execute(['r' => $user['email'], 's' => __('MSP Sentinel test email'), 'b' => __('If you can read this, email alerts work.')]);
        } elseif ($channel === 'webhook') {
            $format = App::settings()->get('webhook_format');
            $payload = WebhookSender::format(in_array($format, WebhookSender::FORMATS, true) ? $format : 'json',
                ['title' => __('MSP Sentinel test message'), 'text' => __('If you can see this, webhook alerts work.'), 'severity' => 'info', 'client' => '', 'items' => [], 'link' => '']);
            $db->prepare("INSERT INTO deliveries (channel, recipient, subject, body, status, next_attempt_at, created_at) VALUES ('webhook', 'test', :s, :b, 'pending', UTC_TIMESTAMP(), UTC_TIMESTAMP())")
                ->execute(['s' => __('Test message'), 'b' => json_encode($payload)]);
        } else {
            return Response::redirect('/admin/settings#alerts');
        }
        $id = (int) $db->lastInsertId();
        App::outbox()->flush(1, $id);
        // Read the real outcome: the worker may have sent it first.
        $row = $db->query('SELECT status, last_error FROM deliveries WHERE id = ' . $id)->fetch();
        $ok = $row['status'] === 'sent';
        $this->audit($request, 'settings.alerts_tested', null, null, ['channel' => $channel, 'ok' => $ok]);
        if ($ok) {
            Session::flash('success', $channel === 'email' ? __('Test email sent to {to}.', ['to' => $user['email']]) : __('Test webhook message sent.'));
        } else {
            // Don't keep retrying a test message in the background.
            $db->prepare("UPDATE deliveries SET status = 'failed' WHERE id = :id AND status = 'pending'")->execute(['id' => $id]);
            Session::flash('danger', $row['status'] === 'sending'
                ? __('The test message is being sent by the background worker; check the recent deliveries below.')
                : __('Sending failed: {e}', ['e' => (string) $row['last_error']]));
        }
        return Response::redirect('/admin/settings#alerts');
    }

    /**
     * GET /notifications: the signed-in user's notifications. Read-only (1.34): a GET never changes anything, so a link
     * from another site can't mark alerts read unseen; "Mark all as read" (POST, CSRF-checked) does.
     */
    public function notifications(Request $request): Response
    {
        $uid = (int) $this->user()['id'];
        $stmt = App::db()->prepare('SELECT * FROM notifications WHERE user_id = :u ORDER BY id DESC LIMIT 100');
        $stmt->execute(['u' => $uid]);
        return $this->page('notifications/index', __('Notifications'), ['notifications' => $stmt->fetchAll()]);
    }

    /** POST /notifications/read: mark the signed-in user's notifications up to the newest one shown as read. */
    public function markRead(Request $request): Response
    {
        $uid = (int) $this->user()['id'];
        $upTo = ctype_digit($request->input('up_to')) ? (int) $request->input('up_to') : 0; // not ones that arrived since
        App::db()->prepare('UPDATE notifications SET read_at = UTC_TIMESTAMP() WHERE user_id = :u AND read_at IS NULL AND id <= :hi')
            ->execute(['u' => $uid, 'hi' => $upTo]);
        return Response::redirect('/notifications');
    }

    /** POST /profile/alerts: the signed-in user's email preference. */
    public function preference(Request $request): Response
    {
        $pref = $request->input('alert_email');
        if (!in_array($pref, ['none', 'immediate', 'digest', 'both'], true)) {
            Session::flash('danger', __('Choose which emails you want.'));
            return Response::redirect('/profile');
        }
        $uid = (int) $this->user()['id'];
        App::db()->prepare('UPDATE users SET alert_email = :p WHERE id = :id')->execute(['p' => $pref, 'id' => $uid]);
        $this->audit($request, 'user.alert_preference', 'user', $uid, ['alert_email' => $pref]);
        Session::flash('success', __('Email preference saved.'));
        return Response::redirect('/profile');
    }

    /** POST /profile/timezone (1.48): the time zone times are shown in for you ('' = the organisation's). */
    public function timezone(Request $request): Response
    {
        $zone = $request->input('timezone');
        if ($zone !== '' && !valid_timezone($zone)) {
            Session::flash('danger', __('Choose a time zone from the list, or leave it empty.'));
            return Response::redirect('/profile#timezone');
        }
        $uid = (int) $this->user()['id'];
        App::db()->prepare('UPDATE users SET timezone = :t WHERE id = :id')->execute(['t' => $zone, 'id' => $uid]);
        $this->audit($request, 'user.timezone', 'user', $uid, ['timezone' => $zone]);
        Session::flash('success', __('Time zone saved.'));
        return Response::redirect('/profile#timezone');
    }

    /**
     * POST /profile/theme: the signed-in user's interface theme (dark or light).
     *
     * Untrusted: the choice, checked against a fixed list. Only the caller's own row is
     * written; the kernel has already checked sign-in and CSRF. Audited like the email preference.
     */
    public function theme(Request $request): Response
    {
        $theme = $request->input('ui_theme');
        if (!in_array($theme, ['dark', 'light'], true)) {
            Session::flash('danger', __('Choose dark or light.'));
            return Response::redirect('/profile#appearance');
        }
        $uid = (int) $this->user()['id'];
        App::db()->prepare('UPDATE users SET ui_theme = :t WHERE id = :id')->execute(['t' => $theme, 'id' => $uid]);
        $this->audit($request, 'user.ui_theme', 'user', $uid, ['ui_theme' => $theme]);
        Session::flash('success', __('Appearance saved.'));
        return Response::redirect('/profile#appearance');
    }
}
