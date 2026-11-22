<?php

declare(strict_types=1);

namespace Sentinel\Api;

use PDO;
use Sentinel\Core\Settings;

/**
 * Outbound events for other systems (for example MSP Align): queued in the
 * delivery outbox and POSTed as signed JSON to the event webhook.
 *
 * Event types: ping (test button), finding.opened, finding.reopened, finding.escalated,
 * finding.resolved, finding.triaged, scan.finished, report.created.
 * Payload: {"id", "type", "created_at", "data": {...IDs and short fields}}.
 * Receivers fetch details through the API.
 *
 * Delivery: retried with growing gaps for about two days (see Outbox), so a
 * receiver may get events late or out of order: dedupe by "id" and use the
 * API to resync. Header X-Sentinel-Delivery carries the outbox ID.
 *
 * Signature (checked by the receiver): header X-Sentinel-Signature:
 * "t=<unix time>,v1=<hex HMAC-SHA256(secret, t + "." + body)>". The receiver
 * should reject old timestamps (for example over 5 minutes) to stop replays.
 *
 * Security assumptions: the webhook URL and secret are stored encrypted; the
 * URL is checked like the alert webhook (https, public addresses, pinned).
 * Data fields are scan data (untrusted) and are JSON-encoded.
 */
final class EventPublisher
{
    public const TYPES = ['ping', 'finding.opened', 'finding.reopened', 'finding.escalated', 'finding.resolved', 'finding.triaged', 'scan.finished', 'report.created'];

    /** Uses the outbox table and settings. */
    public function __construct(private readonly PDO $db, private readonly Settings $settings)
    {
    }

    /**
     * Queue one event (nothing if the event webhook is off).
     *
     * @param array<string,mixed> $data
     */
    public function publish(string $type, array $data): void
    {
        if (!in_array($type, self::TYPES, true) || $this->settings->get('event_webhook_enabled') !== '1') {
            return;
        }
        // An event must never break the change that caused it (a triage, a report, an alert): log and go on.
        try {
            $this->queue($type, $data);
        } catch (\Throwable $ex) {
            error_log('[msp-sentinel] could not queue event ' . $type . ': ' . $ex->getMessage());
        }
    }

    /**
     * Insert the event into the outbox.
     *
     * @param array<string,mixed> $data
     */
    private function queue(string $type, array $data): void
    {
        $body = json_encode([
            'id' => 'evt_' . bin2hex(random_bytes(12)),
            'type' => $type,
            'created_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'data' => $data,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        $this->db->prepare("INSERT INTO deliveries (channel, recipient, subject, body, status, next_attempt_at, created_at) VALUES ('event', :r, :s, :b, 'pending', UTC_TIMESTAMP(), UTC_TIMESTAMP())")
            ->execute(['r' => $type, 's' => $type, 'b' => $body]);
    }

    /**
     * Events for a findings refresh (see FindingsEngine::refreshClient).
     *
     * @param array<string,mixed> $result
     */
    public function findingsChanged(int $clientId, array $result): void
    {
        if ($this->settings->get('event_webhook_enabled') !== '1') {
            return;
        }
        foreach (['opened_ids' => 'finding.opened', 'reopened_ids' => 'finding.reopened', 'escalated_ids' => 'finding.escalated', 'resolved_ids' => 'finding.resolved'] as $key => $type) {
            foreach (array_slice($result[$key] ?? [], 0, 500) as $id) {
                $f = $this->finding((int) $id);
                if ($f !== null) {
                    $this->publish($type, $f);
                }
            }
        }
    }

    /** Short finding fields for an event, or null. */
    public function finding(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT id, client_id, finding_type, severity, status, title, target, cve_id FROM findings WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $f = $stmt->fetch();
        if ($f === false) {
            return null;
        }
        return ['finding_id' => (int) $f['id'], 'client_id' => (int) $f['client_id'], 'type' => $f['finding_type'], 'severity' => $f['severity'],
                'status' => $f['status'], 'title' => $f['title'], 'target' => $f['target'], 'cve_id' => $f['cve_id']];
    }

    /** The signature header value for a body. */
    public static function sign(string $secret, string $body, int $time): string
    {
        return 't=' . $time . ',v1=' . hash_hmac('sha256', $time . '.' . $body, $secret);
    }
}
