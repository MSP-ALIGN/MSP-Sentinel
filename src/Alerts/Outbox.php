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
 * Retries: up to 3 attempts, 5 and 15 minutes apart. Then the delivery is
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
    private const CLAIM_TIMEOUT_MINUTES = 10;

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
                         status = IF(attempts + 1 >= " . self::MAX_ATTEMPTS . ", 'failed', 'pending')
                         WHERE status = 'sending' AND claimed_at < UTC_TIMESTAMP() - INTERVAL " . self::CLAIM_TIMEOUT_MINUTES . ' MINUTE');
        $sql = "SELECT * FROM deliveries WHERE status = 'pending' AND next_attempt_at <= UTC_TIMESTAMP()" . ($onlyId !== null ? ' AND id = ' . (int) $onlyId : '') . ' ORDER BY id LIMIT ' . (int) $limit;
        $stats = ['sent' => 0, 'failed' => 0];
        $claim = $this->db->prepare("UPDATE deliveries SET status = 'sending', claimed_at = UTC_TIMESTAMP() WHERE id = :id AND status = 'pending'");
        foreach ($this->db->query($sql)->fetchAll() as $d) {
            $claim->execute(['id' => $d['id']]);
            if ($claim->rowCount() !== 1) {
                continue; // another process got it first
            }
            $enabled = $d['channel'] === 'email' ? 'email_enabled' : 'webhook_enabled';
            if ($this->settings->fresh($enabled) !== '1') {
                $this->db->prepare("UPDATE deliveries SET status = 'failed', claimed_at = NULL, last_error = :e WHERE id = :id")
                    ->execute(['e' => $d['channel'] === 'email' ? 'Not sent: email alerts were turned off.' : 'Not sent: the webhook was turned off.', 'id' => $d['id']]);
                $stats['failed']++;
                continue;
            }
            try {
                if ($d['channel'] === 'email') {
                    $this->mailer()->send(explode(',', (string) $d['recipient']), (string) $d['subject'], (string) $d['body']);
                } else {
                    $this->webhook->send($this->settings->getSecret('webhook_url'), (array) json_decode((string) $d['body'], true));
                }
                $this->db->prepare("UPDATE deliveries SET status = 'sent', claimed_at = NULL, attempts = attempts + 1, sent_at = UTC_TIMESTAMP(), last_error = '' WHERE id = :id")->execute(['id' => $d['id']]);
                $stats['sent']++;
            } catch (\Throwable $ex) {
                // Any error (not only RuntimeException) is recorded, so one bad row can't block the queue.
                $message = $ex instanceof \RuntimeException ? $ex->getMessage() : 'Unexpected error while sending.';
                $attempts = (int) $d['attempts'] + 1;
                $final = $attempts >= self::MAX_ATTEMPTS;
                $this->db->prepare("UPDATE deliveries SET claimed_at = NULL, attempts = :a, last_error = :e, status = :s, next_attempt_at = UTC_TIMESTAMP() + INTERVAL :wait MINUTE WHERE id = :id")
                    ->execute(['a' => $attempts, 'e' => mb_substr($message, 0, 300), 's' => $final ? 'failed' : 'pending', 'wait' => $attempts === 1 ? 5 : 15, 'id' => $d['id']]);
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
