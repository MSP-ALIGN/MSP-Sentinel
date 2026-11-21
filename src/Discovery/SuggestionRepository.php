<?php

declare(strict_types=1);

namespace Sentinel\Discovery;

use PDO;
use Sentinel\Scope\ScopeService;

/**
 * Database access for target suggestions and discovery runs.
 *
 * Security assumptions:
 * - Values are canonical and validated before they reach this class.
 * - A dismissed suggestion stays dismissed when discovery finds it again
 *   (only last_seen moves), so the team isn't nagged about the same name.
 * - Accepting is only done as a side effect of recording an authorisation.
 */
final class SuggestionRepository
{
    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Insert a new suggestion, or refresh an existing one: last_seen moves; the
     * third-party flag can only be raised (with its explanation); an
     * "accepted" suggestion goes back to pending, because callers only upsert
     * values that are NOT in scope now (its authorisation was revoked or
     * expired). Dismissed stays dismissed.
     *
     * @return bool True if it was new.
     */
    public function upsert(int $clientId, string $kind, string $value, string $source, string $detail, bool $thirdParty): bool
    {
        $stmt = $this->db->prepare(
            'INSERT INTO target_suggestions (client_id, kind, value, source, detail, third_party_hint, status, first_seen, last_seen)
             VALUES (:c, :k, :v, :s, :d, :t, \'pending\', UTC_TIMESTAMP(), UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE
                last_seen = UTC_TIMESTAMP(),
                detail = IF(VALUES(third_party_hint) = 1 AND third_party_hint = 0, VALUES(detail), detail),
                third_party_hint = GREATEST(third_party_hint, VALUES(third_party_hint)),
                status = IF(status = \'accepted\', \'pending\', status)'
        );
        $stmt->execute(['c' => $clientId, 'k' => $kind, 'v' => $value, 's' => $source, 'd' => mb_substr($detail, 0, 500), 't' => $thirdParty ? 1 : 0]);
        return $stmt->rowCount() === 1; // 1 = inserted, 2 = updated, 0 = unchanged
    }

    /**
     * Suggestions of a client with a given status.
     *
     * @return list<array<string,mixed>>
     */
    public function forClient(int $clientId, string $status): array
    {
        $stmt = $this->db->prepare('SELECT * FROM target_suggestions WHERE client_id = :c AND status = :s ORDER BY third_party_hint, kind, value');
        $stmt->execute(['c' => $clientId, 's' => $status]);
        return $stmt->fetchAll();
    }

    /**
     * Pending suggestions of a client with the given IDs (others are ignored).
     *
     * @param list<int> $ids Untrusted IDs from the query string, already cast to int.
     * @return list<array<string,mixed>>
     */
    public function pendingByIds(int $clientId, array $ids): array
    {
        $ids = array_values(array_unique(array_filter($ids, static fn (int $id): bool => $id > 0)));
        if ($ids === []) {
            return [];
        }
        $ids = array_slice($ids, 0, 256);
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $this->db->prepare("SELECT * FROM target_suggestions WHERE client_id = ? AND status = 'pending' AND id IN ({$placeholders}) ORDER BY value");
        $stmt->execute(array_merge([$clientId], $ids));
        return $stmt->fetchAll();
    }

    /**
     * A suggestion by ID, or null.
     *
     * @return array<string,mixed>|null
     */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM target_suggestions WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Set status to dismissed or pending (restore). */
    public function setStatus(int $id, string $status, int $userId): void
    {
        $this->db->prepare('UPDATE target_suggestions SET status = :s, decided_by = :u, decided_at = UTC_TIMESTAMP() WHERE id = :id')
            ->execute(['s' => $status, 'u' => $userId, 'id' => $id]);
    }

    /**
     * Mark every pending or dismissed suggestion that the new scope covers
     * (exactly, by range, or by a "*." wildcard) as accepted.
     *
     * @param list<array{entry_type:string,value:string,range_start:?string,range_end:?string}> $entries New scope entries.
     */
    public function markAccepted(int $clientId, array $entries, int $userId): void
    {
        $stmt = $this->db->prepare("SELECT id, value FROM target_suggestions WHERE client_id = :c AND status <> 'accepted'");
        $stmt->execute(['c' => $clientId]);
        $update = $this->db->prepare("UPDATE target_suggestions SET status = 'accepted', decided_by = :u, decided_at = UTC_TIMESTAMP() WHERE id = :id");
        foreach ($stmt->fetchAll() as $row) {
            if (ScopeService::matches($entries, (string) $row['value'])) {
                $update->execute(['u' => $userId, 'id' => $row['id']]);
            }
        }
    }

    /** Start a discovery run record. Returns its ID. */
    public function startRun(int $clientId, string $trigger, ?int $userId): int
    {
        $this->db->prepare("INSERT INTO discovery_runs (client_id, trigger_type, triggered_by, status, started_at) VALUES (:c, :t, :u, 'running', UTC_TIMESTAMP())")
            ->execute(['c' => $clientId, 't' => $trigger, 'u' => $userId]);
        return (int) $this->db->lastInsertId();
    }

    /**
     * Finish a run.
     *
     * @param array<string,mixed> $summary Counts, errors and informational lists (no secrets).
     */
    public function finishRun(int $runId, string $status, array $summary): void
    {
        $this->db->prepare('UPDATE discovery_runs SET status = :s, finished_at = UTC_TIMESTAMP(), summary = :j WHERE id = :id')
            ->execute(['s' => $status, 'j' => json_encode($summary, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR), 'id' => $runId]);
    }

    /**
     * The most recent run of a client (summary decoded), or null.
     *
     * @return array<string,mixed>|null
     */
    public function lastRun(int $clientId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM discovery_runs WHERE client_id = :c ORDER BY id DESC LIMIT 1');
        $stmt->execute(['c' => $clientId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $row['summary'] = json_decode((string) $row['summary'], true) ?: [];
        return $row;
    }
}
