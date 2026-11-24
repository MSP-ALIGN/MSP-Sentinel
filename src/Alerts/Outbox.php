<?php

declare(strict_types=1);

namespace Sentinel\Alerts;

use PDO;
use Sentinel\Core\CaBundle;
use Sentinel\Core\Settings;

/**
 * Sends queued emails and webhook posts (called by the worker every minute,
 * and right away for the "Send test" buttons).
 *
 * Retries: up to 3 attempts, 5 and 15 minutes apart (outbound events: 8
 * attempts over about two days). Then the delivery is
 * marked failed and the error kept (shown on the Settings page). If the
 * channel has been turned off since the message was queued, it is dropped
 * (marked failed) instead of sent.
 *
 * Concurrency: the worker, the feeds job and the "Send test" buttons can all
 * flush at once. Each delivery is claimed with a conditional UPDATE
 * (pending -> sending) before it is sent, so only one process sends it.
 * A claim older than 10 minutes belongs to a process that died; it goes
 * back to the queue, counted as an attempt.
 *
 * Old rows are pruned (prune()): sent/failed deliveries after 90 days,
 * notifications after 180 days.
 *
 * Security assumptions: SMTP credentials and the webhook URL are read from
 * encrypted settings when sending, and never stored in the outbox or in
 * error messages.
 */
final class Outbox
{
    private const MAX_ATTEMPTS = 3;
    /** Outbound events retry longer (receivers may be down for a while): gaps in minutes after each failed attempt. */
    private const EVENT_BACKOFF = [5, 15, 60, 180, 360, 720, 1440];
    private const CLAIM_TIMEOUT_MINUTES = 10;
    /** Report attachments larger than this in total are left out; the email then points to the reports in Sentinel. */
    private const MAX_ATTACH_BYTES = 5_000_000;

    /** Needs settings (for SMTP and webhook) and an optional extra CA file for SMTP TLS. */
    public function __construct(private readonly PDO $db, private readonly Settings $settings, private readonly ?string $caFile, private readonly WebhookSender $webhook)
    {
    }

    /**
     * Send due deliveries.
     *
     * @return array{sent:int, failed:int}
     */
    public function flush(int $limit = 50, ?int $onlyId = null): array
    {
        // Claims left by a process that died: back to the queue (or failed after the last attempt).
        $this->db->exec("UPDATE deliveries SET attempts = attempts + 1, claimed_at = NULL, last_error = 'Interrupted while sending.',
                         status = IF(attempts + 1 >= IF(channel = 'event', " . (count(self::EVENT_BACKOFF) + 1) . ', ' . self::MAX_ATTEMPTS . "), 'failed', 'pending')
                         WHERE status = 'sending' AND claimed_at < UTC_TIMESTAMP() - INTERVAL " . self::CLAIM_TIMEOUT_MINUTES . ' MINUTE');
        $sql = "SELECT * FROM deliveries WHERE status = 'pending' AND next_attempt_at <= UTC_TIMESTAMP()" . ($onlyId !== null ? ' AND id = ' . (int) $onlyId : '') . ' ORDER BY id LIMIT ' . (int) $limit;
        $stats = ['sent' => 0, 'failed' => 0];
        $claim = $this->db->prepare("UPDATE deliveries SET status = 'sending', claimed_at = UTC_TIMESTAMP() WHERE id = :id AND status = 'pending'");
        foreach ($this->db->query($sql)->fetchAll() as $d) {
            $claim->execute(['id' => $d['id']]);
            if ($claim->rowCount() !== 1) {
                continue; // another process got it first
            }
            $enabled = match ($d['channel']) { 'email' => 'email_enabled', 'event' => 'event_webhook_enabled', default => 'webhook_enabled' };
            if ($this->settings->fresh($enabled) !== '1') {
                $this->db->prepare("UPDATE deliveries SET status = 'failed', claimed_at = NULL, last_error = :e WHERE id = :id")
                    ->execute(['e' => $d['channel'] === 'email' ? 'Not sent: email alerts were turned off.' : 'Not sent: the webhook was turned off.', 'id' => $d['id']]);
                $stats['failed']++;
                continue;
            }
            try {
                if ($d['channel'] === 'email') {
                    $files = $this->attachments((string) ($d['report_ids'] ?? ''));
                    $body = (string) $d['body'];
                    if ($files === [] && (string) ($d['report_ids'] ?? '') !== '') {
                        $body .= "\n\n" . 'The reports are too large to attach. Open them in MSP Sentinel under Reports (report IDs: ' . $d['report_ids'] . ').';
                    }
                    $this->mailer()->send(explode(',', (string) $d['recipient']), (string) $d['subject'], $body, $files);
                } elseif ($d['channel'] === 'event') {
                    // Signed at send time, so each retry carries a fresh timestamp.
                    $secret = $this->settings->getSecret('event_webhook_secret');
                    if ($secret === '') {
                        throw new \RuntimeException('The event webhook has no signing secret.');
                    }
                    $this->webhook->sendRaw($this->settings->getSecret('event_webhook_url'), (string) $d['body'], [
                        'X-Sentinel-Event: ' . preg_replace('/[^a-z.]/', '', (string) $d['subject']),
                        'X-Sentinel-Delivery: ' . (int) $d['id'],
                        'X-Sentinel-Signature: ' . \Sentinel\Api\EventPublisher::sign($secret, (string) $d['body'], time()),
                    ]);
                } else {
                    $this->webhook->send($this->settings->getSecret('webhook_url'), (array) json_decode((string) $d['body'], true));
                }
                $this->db->prepare("UPDATE deliveries SET status = 'sent', claimed_at = NULL, attempts = attempts + 1, sent_at = UTC_TIMESTAMP(), last_error = '' WHERE id = :id")->execute(['id' => $d['id']]);
                $stats['sent']++;
            } catch (\Throwable $ex) {
                // Any error (not only RuntimeException) is recorded, so one bad row can't block the queue.
                $message = $ex instanceof \RuntimeException ? $ex->getMessage() : 'Unexpected error while sending.';
                $attempts = (int) $d['attempts'] + 1;
                $isEvent = $d['channel'] === 'event';
                $final = $attempts >= ($isEvent ? count(self::EVENT_BACKOFF) + 1 : self::MAX_ATTEMPTS);
                $wait = $isEvent ? self::EVENT_BACKOFF[min($attempts, count(self::EVENT_BACKOFF)) - 1] : ($attempts === 1 ? 5 : 15);
                $this->db->prepare("UPDATE deliveries SET claimed_at = NULL, attempts = :a, last_error = :e, status = :s, next_attempt_at = UTC_TIMESTAMP() + INTERVAL :wait MINUTE WHERE id = :id")
                    ->execute(['a' => $attempts, 'e' => mb_substr($message, 0, 300), 's' => $final ? 'failed' : 'pending', 'wait' => $wait, 'id' => $d['id']]);
                if ($final && (string) ($d['report_ids'] ?? '') !== '') {
                    // A monthly report email gave up: tell those who schedule reports in-app, so it isn't lost silently.
                    $note = $this->db->prepare("INSERT INTO notifications (user_id, kind, severity, title, body, link, created_at)
                                                VALUES (:u, 'report_failed', 'warn', :t, :b, '/reports', UTC_TIMESTAMP())");
                    // Only those who see the report's client (1.42.1).
                    $rid = (int) explode(',', (string) $d['report_ids'])[0];
                    $see = $this->db->prepare('SELECT u.id FROM users u JOIN reports r ON r.id = :r
                                               WHERE u.all_clients = 1 OR EXISTS (SELECT 1 FROM user_clients uc WHERE uc.user_id = u.id AND uc.client_id = r.client_id)');
                    $see->execute(['r' => $rid]);
                    $seeing = array_flip(array_map('intval', $see->fetchAll(\PDO::FETCH_COLUMN)));
                    foreach ((new \Sentinel\Auth\RoleRepository($this->db))->usersWith('reports.schedule') as $u) {
                        if (!isset($seeing[$u['id']])) {
                            continue;
                        }
                        $note->execute(['u' => $u['id'], 't' => mb_substr('A monthly report email to ' . $d['recipient'] . ' could not be sent', 0, 300), 'b' => mb_substr($message, 0, 2000)]);
                    }
                }
                $stats['failed']++;
            }
        }
        return $stats;
    }

    /** Delete old sent/failed deliveries (90 days) and notifications (180 days). */
    public function prune(): void
    {
        $this->db->exec("DELETE FROM deliveries WHERE status IN ('sent', 'failed') AND created_at < UTC_TIMESTAMP() - INTERVAL 90 DAY LIMIT 1000");
        $this->db->exec('DELETE FROM notifications WHERE created_at < UTC_TIMESTAMP() - INTERVAL 180 DAY LIMIT 1000');
    }

    /**
     * Recent deliveries for the Settings page.
     *
     * @return list<array<string,mixed>>
     */
    public function recent(int $limit = 10): array
    {
        return $this->db->query('SELECT id, channel, subject, status, attempts, last_error, created_at, sent_at FROM deliveries ORDER BY id DESC LIMIT ' . (int) $limit)->fetchAll();
    }

    /**
     * Report files to attach (self-contained HTML), read when sending. A deleted report is skipped.
     *
     * @return list<array{name:string, type:string, content:string}>
     */
    private function attachments(string $reportIds): array
    {
        // Mail servers often refuse messages over 10-25 MB (and base64 adds a third), so large reports go as links.
        $sizes = $reportIds === '' ? 0 : (int) $this->db->query('SELECT COALESCE(SUM(LENGTH(html)), 0) FROM reports WHERE id IN (' . implode(',', array_map('intval', explode(',', $reportIds)) ?: [0]) . ')')->fetchColumn();
        if ($sizes > self::MAX_ATTACH_BYTES) {
            return [];
        }
        $files = [];
        foreach (array_filter(array_map('intval', explode(',', $reportIds))) as $id) {
            $stmt = $this->db->prepare('SELECT id, kind, period_end, html FROM reports WHERE id = :id');
            $stmt->execute(['id' => $id]);
            $r = $stmt->fetch();
            if ($r !== false) {
                $files[] = ['name' => 'report-' . $r['id'] . '-' . $r['kind'] . '-' . $r['period_end'] . '.html', 'type' => 'text/html', 'content' => (string) $r['html']];
            }
        }
        return $files;
    }

    /** The configured SMTP mailer. */
    private function mailer(): SmtpMailer
    {
        if ($this->settings->get('email_enabled') !== '1' || $this->settings->get('smtp_host') === '') {
            throw new \RuntimeException('Email is not set up.');
        }
        return new SmtpMailer(
            $this->settings->get('smtp_host'), (int) $this->settings->get('smtp_port'), $this->settings->get('smtp_security'),
            $this->settings->get('smtp_username'), $this->settings->getSecret('smtp_password'), $this->settings->get('smtp_from'),
            CaBundle::path($this->caFile),
        );
    }
}
