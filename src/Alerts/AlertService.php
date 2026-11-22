<?php

declare(strict_types=1);

namespace Sentinel\Alerts;

use PDO;
use Sentinel\Core\Settings;

/**
 * Turns events into alerts: in-app notifications, emails and webhook posts.
 * Emails and webhooks are only QUEUED here (deliveries table). The worker
 * sends them (Outbox), so a slow mail server never delays a scan.
 *
 * What triggers what:
 * - a NEW or REAPPEARED Fail finding, or an open Warning that became a Fail
 *   (for example its CVE was added to the known-exploited list): immediate
 *   alert (in-app for everyone; email to users who chose "immediate" or
 *   "both", plus the team addresses; webhook). A finding that already
 *   alerted in the last 24 hours doesn't alert again when it flaps
 *   (resolves and comes back), so an unstable service can't flood anyone;
 * - after each scan or certificate job, if anything changed: one digest per
 *   client (new warnings, new fails, resolved findings): in-app; email to users
 *   who chose "digest" or "both", plus the team addresses; webhook;
 * - a failed scan job: in-app for admins and an email to the team addresses;
 * - a failed feed refresh: in-app for admins only, at most once a day per feed.
 * Feed refreshes (bin/feeds.php) send immediate alerts only, no digest: new
 * warnings and resolved items from them show in the next scan's client page
 * and the findings list.
 *
 * Each email is a separate delivery per recipient, so one bad address can't
 * block the others, and recipients never see each other's addresses.
 * Accepted and false-positive findings never trigger alerts.
 *
 * Security assumptions: notification and email text comes from finding
 * titles (scan data, untrusted). It is plain text and escaped by the views.
 * Webhook payloads carry only summaries and links. Recipients are validated.
 */
final class AlertService
{
    private const MAX_IMMEDIATE = 20;

    /** @param string $publicUrl Base URL for links (config app.public_url), or '' for no links. */
    public function __construct(private readonly PDO $db, private readonly Settings $settings, private readonly string $publicUrl)
    {
    }

    /**
     * React to a findings refresh for one client.
     *
     * @param array{opened_ids:list<int>, reopened_ids:list<int>, resolved_ids:list<int>, escalated_ids?:list<int>} $result From FindingsEngine::refreshClient.
     * @param bool $digest Also send the change digest (after scan and certificate jobs; not after feed refreshes).
     */
    public function findingsChanged(int $clientId, array $result, bool $digest): void
    {
        $client = (string) $this->db->query('SELECT name FROM clients WHERE id = ' . (int) $clientId)->fetchColumn();
        $newIds = array_merge($result['opened_ids'], $result['reopened_ids']);
        $new = $this->findings($newIds);
        $escalated = array_values(array_filter($this->findings(array_diff($result['escalated_ids'] ?? [], $newIds)),
            static fn (array $f): bool => $f['severity'] === 'fail' && $f['status'] === 'open'));
        $fails = array_merge(array_values(array_filter($new, static fn (array $f): bool => $f['severity'] === 'fail' && $f['status'] === 'open')), $escalated);
        $warns = array_values(array_filter($new, static fn (array $f): bool => $f['severity'] === 'warn' && $f['status'] === 'open'));
        $resolved = $this->findings($result['resolved_ids']);

        // Immediate alerts for new Fail findings (summarised if there are very many), skipping
        // findings that already alerted in the last 24 hours (flapping).
        $fresh = array_values(array_filter($fails, fn (array $f): bool => !$this->alertedRecently((int) $f['id'])));
        $immediate = array_slice($fresh, 0, self::MAX_IMMEDIATE);
        foreach ($immediate as $f) {
            $this->markAlerted((int) $f['id']);
            $title = __('Fail: {title}', ['title' => $f['title']]);
            $text = __('{client}: {target}', ['client' => $client, 'target' => $f['target']]) . ((int) $f['reappeared'] === 1 ? ' ' . __('(reappeared)') : '');
            $link = '/findings/' . (int) $f['id'];
            $this->notifyUsers('finding_fail', 'fail', $title, $text . "\n" . $f['detail'], $link, null);
            $this->queueEmail($this->emailRecipients(['immediate', 'both']), '[' . $client . '] ' . $title,
                $title . "\n\n" . $text . "\n\n" . $f['detail'] . "\n\n" . $this->absolute($link));
            $this->queueWebhook(['title' => $title, 'text' => $text, 'severity' => 'fail', 'client' => $client, 'items' => [], 'link' => $this->absolute($link)]);
        }
        if (count($fresh) > self::MAX_IMMEDIATE) {
            $more = count($fresh) - self::MAX_IMMEDIATE;
            $this->notifyUsers('finding_fail', 'fail', __('{n} more new Fail findings for {client}', ['n' => $more, 'client' => $client]), '', '/findings?client=' . $clientId, null);
        }

        if (!$digest || ($fails === [] && $warns === [] && $resolved === [])) {
            return;
        }
        $title = __('{client}: {f} new Fail, {w} new Warning, {r} resolved', ['client' => $client, 'f' => count($fails), 'w' => count($warns), 'r' => count($resolved)]);
        $items = [];
        foreach ($fails as $f) {
            $items[] = __('FAIL: {t} ({target})', ['t' => $f['title'], 'target' => $f['target']]);
        }
        foreach ($warns as $f) {
            $items[] = __('WARNING: {t} ({target})', ['t' => $f['title'], 'target' => $f['target']]);
        }
        foreach ($resolved as $f) {
            $items[] = __('RESOLVED: {t} ({target})', ['t' => $f['title'], 'target' => $f['target']]);
        }
        $link = '/clients/' . $clientId;
        $this->notifyUsers('digest', $fails !== [] ? 'fail' : ($warns !== [] ? 'warn' : 'info'), $title, implode("\n", array_slice($items, 0, 30)), $link, null);
        $this->queueEmail($this->emailRecipients(['digest', 'both']), '[' . $client . '] ' . __('Scan summary'),
            $title . "\n\n" . implode("\n", array_slice($items, 0, 200)) . "\n\n" . $this->absolute($link));
        $this->queueWebhook(['title' => $title, 'text' => __('Changes after the latest checks.'), 'severity' => $fails !== [] ? 'fail' : ($warns !== [] ? 'warn' : 'info'),
                             'client' => $client, 'items' => $items, 'link' => $this->absolute($link)]);
    }

    /** A scan job failed: tell admins (in-app) and the team addresses. */
    public function scanFailed(int $clientId, int $jobId, string $message): void
    {
        $client = (string) $this->db->query('SELECT name FROM clients WHERE id = ' . (int) $clientId)->fetchColumn();
        $title = __('Scan #{id} for {client} failed', ['id' => $jobId, 'client' => $client]);
        $this->notifyUsers('scan_failed', 'warn', $title, $message, '/clients/' . $clientId . '#scans', 'admin');
        $this->queueEmail($this->teamAddresses(), '[Sentinel] ' . $title, $title . "\n\n" . $message . "\n\n" . $this->absolute('/clients/' . $clientId));
    }

    /** A threat feed refresh failed: tell admins in-app (at most once a day per feed). */
    public function feedFailed(string $feed, string $message): void
    {
        $title = __('The {feed} vulnerability feed could not be refreshed', ['feed' => strtoupper($feed)]);
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM notifications WHERE kind = 'feed_failed' AND title = :t AND created_at > UTC_TIMESTAMP() - INTERVAL 20 HOUR");
        $stmt->execute(['t' => $title]);
        if ((int) $stmt->fetchColumn() > 0) {
            return;
        }
        $this->notifyUsers('feed_failed', 'warn', $title, $message, '/admin/settings', 'admin');
    }

    /**
     * Create an in-app notification for every active user (or only admins).
     *
     * @param string|null $role 'admin' to limit to admins.
     */
    public function notifyUsers(string $kind, string $severity, string $title, string $body, string $link, ?string $role): void
    {
        $users = $this->db->query("SELECT id FROM users WHERE is_active = 1" . ($role === 'admin' ? " AND role = 'admin'" : ''))->fetchAll(PDO::FETCH_COLUMN);
        $stmt = $this->db->prepare('INSERT INTO notifications (user_id, kind, severity, title, body, link, created_at) VALUES (:u, :k, :s, :t, :b, :l, UTC_TIMESTAMP())');
        foreach ($users as $uid) {
            $stmt->execute(['u' => $uid, 'k' => $kind, 's' => $severity, 't' => mb_substr($title, 0, 300), 'b' => mb_substr($body, 0, 2000), 'l' => mb_substr($link, 0, 300)]);
        }
    }

    /**
     * Queue the email once per recipient (nothing if email is off or there is no recipient).
     *
     * @param list<string> $recipients
     * @param string $reportIds Comma-separated report IDs to attach (monthly reports).
     */
    public function queueEmail(array $recipients, string $subject, string $body, string $reportIds = ''): void
    {
        $recipients = array_values(array_unique(array_filter($recipients, [SmtpMailer::class, 'validAddress'])));
        if ($recipients === [] || $this->settings->get('email_enabled') !== '1') {
            return;
        }
        $body .= "\n\n-- \n" . __('Sent by MSP Sentinel. Choose which emails you get on your profile page.');
        foreach ($recipients as $to) {
            $this->queue('email', $to, $subject, $body, $reportIds);
        }
    }

    /**
     * Queue a webhook post (nothing if the webhook is off).
     *
     * @param array{title:string,text:string,severity:string,client:string,items:list<string>,link:string} $alert
     */
    public function queueWebhook(array $alert): void
    {
        if ($this->settings->get('webhook_enabled') !== '1') {
            return;
        }
        $format = in_array($this->settings->get('webhook_format'), WebhookSender::FORMATS, true) ? $this->settings->get('webhook_format') : 'json';
        $this->queue('webhook', $format, mb_substr($alert['title'], 0, 300),
            json_encode(WebhookSender::format($format, $alert), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE));
    }

    /**
     * Email addresses of active users whose preference is one of $prefs, plus the team addresses.
     *
     * @param list<string> $prefs
     * @return list<string>
     */
    private function emailRecipients(array $prefs): array
    {
        $in = implode(',', array_map(fn (string $p): string => $this->db->quote($p), $prefs));
        $users = $this->db->query("SELECT email FROM users WHERE is_active = 1 AND email <> '' AND alert_email IN ({$in})")->fetchAll(PDO::FETCH_COLUMN);
        return array_merge($users, $this->teamAddresses());
    }

    /** @return list<string> Valid team addresses from settings. */
    private function teamAddresses(): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $this->settings->get('team_addresses'))), [SmtpMailer::class, 'validAddress']));
    }

    /**
     * Findings by ID.
     *
     * @param list<int> $ids
     * @return list<array<string,mixed>>
     */
    private function findings(array $ids): array
    {
        $ids = array_values(array_unique(array_map('intval', $ids)));
        if ($ids === []) {
            return [];
        }
        $stmt = $this->db->prepare('SELECT * FROM findings WHERE id IN (' . implode(',', array_fill(0, count($ids), '?')) . ') ORDER BY severity = \'fail\' DESC, id');
        $stmt->execute($ids);
        return $stmt->fetchAll();
    }

    /** True if this finding sent an immediate alert in the last 24 hours. */
    private function alertedRecently(int $findingId): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM finding_events WHERE finding_id = :id AND event = 'alerted' AND created_at > UTC_TIMESTAMP() - INTERVAL 24 HOUR");
        $stmt->execute(['id' => $findingId]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** Record in the finding's history that an immediate alert went out. */
    private function markAlerted(int $findingId): void
    {
        $this->db->prepare("INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:id, 'alerted', NULL, :n, UTC_TIMESTAMP())")
            ->execute(['id' => $findingId, 'n' => __('Immediate alert sent.')]);
    }

    /** Absolute link for emails and webhooks ('' when no public URL is configured). */
    private function absolute(string $path): string
    {
        return $this->publicUrl === '' ? '' : rtrim($this->publicUrl, '/') . $path;
    }

    /** Insert a pending delivery. */
    private function queue(string $channel, string $recipient, string $subject, string $body, string $reportIds = ''): void
    {
        $reportIds = implode(',', array_filter(array_map('intval', explode(',', $reportIds))));
        $this->db->prepare("INSERT INTO deliveries (channel, recipient, subject, body, status, next_attempt_at, created_at, report_ids) VALUES (:c, :r, :s, :b, 'pending', UTC_TIMESTAMP(), UTC_TIMESTAMP(), :ri)")
            ->execute(['c' => $channel, 'r' => $recipient, 's' => mb_substr($subject, 0, 300), 'b' => $body, 'ri' => $reportIds]);
    }
}
