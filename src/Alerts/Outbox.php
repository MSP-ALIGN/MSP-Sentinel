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
 * marked failed and the error kept (shown on the Settings page).
 *
 * Security assumptions: SMTP credentials and the webhook URL are read from
 * encrypted settings when sending, and never stored in the outbox or in
 * error messages.
 */
final class Outbox
{
    private const MAX_ATTEMPTS = 3;

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
        $sql = "SELECT * FROM deliveries WHERE status = 'pending' AND next_attempt_at <= UTC_TIMESTAMP()" . ($onlyId !== null ? ' AND id = ' . (int) $onlyId : '') . ' ORDER BY id LIMIT ' . (int) $limit;
        $stats = ['sent' => 0, 'failed' => 0];
        foreach ($this->db->query($sql)->fetchAll() as $d) {
            try {
                if ($d['channel'] === 'email') {
                    $this->mailer()->send(explode(',', (string) $d['recipient']), (string) $d['subject'], (string) $d['body']);
                } else {
                    $this->webhook->send($this->settings->getSecret('webhook_url'), (array) json_decode((string) $d['body'], true));
                }
                $this->db->prepare("UPDATE deliveries SET status = 'sent', attempts = attempts + 1, sent_at = UTC_TIMESTAMP(), last_error = '' WHERE id = :id")->execute(['id' => $d['id']]);
                $stats['sent']++;
            } catch (\RuntimeException $ex) {
                $attempts = (int) $d['attempts'] + 1;
                $final = $attempts >= self::MAX_ATTEMPTS;
                $this->db->prepare("UPDATE deliveries SET attempts = :a, last_error = :e, status = :s, next_attempt_at = UTC_TIMESTAMP() + INTERVAL :wait MINUTE WHERE id = :id")
                    ->execute(['a' => $attempts, 'e' => mb_substr($ex->getMessage(), 0, 300), 's' => $final ? 'failed' : 'pending', 'wait' => $attempts === 1 ? 5 : 15, 'id' => $d['id']]);
                $stats['failed']++;
            }
        }
        return $stats;
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
