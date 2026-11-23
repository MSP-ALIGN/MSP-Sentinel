<?php

declare(strict_types=1);

namespace Sentinel\Engagements;

use PDO;
use Sentinel\Agent\InternalRanges;
use Sentinel\Scope\IpRange;
use Sentinel\Scope\ScopeService;

/**
 * Pen-test engagements: storage, their state, and the one gate every engagement test goes through (isActive()).
 *
 * What an engagement is: the client's written consent (a signed document, stored as a file) to test targets that are
 * ALREADY in its authorised scope more deeply, inside a time window, with test types chosen from a fixed list. It
 * never widens what may be tested: external targets must lie inside the client's active external authorisations,
 * internal ranges inside the site's active internal authorisation (checked when it is created, and again for every
 * host when a test runs).
 *
 * Rules enforced here:
 * - two-person rule: approve() only succeeds for an admin who did not create it (the controller checks the role);
 * - nothing runs before approval, outside the window, after a stop (kill switch) or a cancel;
 * - approved engagements are never edited: they can only be stopped. A cancel is only possible before approval.
 *
 * Untrusted: nothing here comes straight from a form; the controller validates first. Values are bound parameters.
 */
final class EngagementRepository
{
    /** Test types an engagement can allow (fixed list; labels in the UI). */
    public const TESTS = ['tcp_full', 'udp_common', 'nse_safe', 'anon_access'];
    public const INTENSITIES = ['gentle', 'normal'];
    /** Longest window, and how far ahead one may start. */
    public const MAX_DAYS = 14;
    public const MAX_AHEAD_DAYS = 90;

    public const STATE_AWAITING = 'awaiting_approval';
    public const STATE_SCHEDULED = 'scheduled';
    public const STATE_ACTIVE = 'active';
    public const STATE_ENDED = 'ended';
    public const STATE_STOPPED = 'stopped';
    public const STATE_CANCELLED = 'cancelled';

    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Save a validated engagement and its targets (one transaction). Returns its id.
     *
     * @param array{name:string, window_start:string, window_end:string, intensity:string, tests:list<string>, signer_name:string,
     *              signer_role:string, signed_on:string, document_sha256:string, document_name:string, document_bytes:int, notes:string} $e
     * @param list<array{kind:string, site_id:?int, entry_type:string, value:string, range_start:?string, range_end:?string}> $targets
     */
    public function create(int $clientId, array $e, array $targets, int $userId): int
    {
        $this->db->beginTransaction();
        try {
            $this->db->prepare('INSERT INTO engagements (client_id, name, window_start, window_end, intensity, tests, signer_name, signer_role, signed_on,
                document_sha256, document_name, document_bytes, notes, created_by, created_at)
                VALUES (:c, :n, :ws, :we, :i, :t, :sn, :sr, :so, :dh, :dn, :db, :no, :u, UTC_TIMESTAMP())')->execute([
                'c' => $clientId, 'n' => $e['name'], 'ws' => $e['window_start'], 'we' => $e['window_end'], 'i' => $e['intensity'], 't' => implode(',', $e['tests']),
                'sn' => $e['signer_name'], 'sr' => $e['signer_role'], 'so' => $e['signed_on'], 'dh' => $e['document_sha256'], 'dn' => $e['document_name'],
                'db' => $e['document_bytes'], 'no' => $e['notes'] !== '' ? $e['notes'] : null, 'u' => $userId,
            ]);
            $id = (int) $this->db->lastInsertId();
            $stmt = $this->db->prepare('INSERT INTO engagement_targets (engagement_id, kind, site_id, entry_type, value, range_start, range_end) VALUES (:e, :k, :s, :t, :v, :rs, :re)');
            foreach ($targets as $t) {
                $stmt->execute(['e' => $id, 'k' => $t['kind'], 's' => $t['site_id'], 't' => $t['entry_type'], 'v' => $t['value'], 'rs' => $t['range_start'], 're' => $t['range_end']]);
            }
            $this->db->commit();
            return $id;
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /** One engagement with its targets ('targets') and the names of who created, approved and stopped it. @return array<string,mixed>|null */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT e.*, uc.username AS created_by_name, ua.username AS approved_by_name, us.username AS stopped_by_name
            FROM engagements e LEFT JOIN users uc ON uc.id = e.created_by LEFT JOIN users ua ON ua.id = e.approved_by LEFT JOIN users us ON us.id = e.stopped_by
            WHERE e.id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $t = $this->db->prepare('SELECT kind, site_id, entry_type, value, range_start, range_end FROM engagement_targets WHERE engagement_id = :e ORDER BY kind, site_id, id');
        $t->execute(['e' => $id]);
        $row['targets'] = $t->fetchAll();
        $row['tests_list'] = array_values(array_filter(explode(',', (string) $row['tests'])));
        return $row;
    }

    /** A client's engagements, newest first (no targets). @return list<array<string,mixed>> */
    public function forClient(int $clientId): array
    {
        $stmt = $this->db->prepare('SELECT e.*, uc.username AS created_by_name, ua.username AS approved_by_name FROM engagements e
            LEFT JOIN users uc ON uc.id = e.created_by LEFT JOIN users ua ON ua.id = e.approved_by WHERE e.client_id = :c ORDER BY e.id DESC');
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Approve (two-person rule: never by its creator). Only while awaiting approval and before the window ends.
     * Returns whether it was approved now.
     */
    public function approve(int $id, int $userId): bool
    {
        $stmt = $this->db->prepare('UPDATE engagements SET approved_by = :u, approved_at = UTC_TIMESTAMP() WHERE id = :id AND approved_at IS NULL
            AND stopped_at IS NULL AND cancelled_at IS NULL AND created_by <> :u2 AND window_end > UTC_TIMESTAMP()');
        $stmt->execute(['u' => $userId, 'u2' => $userId, 'id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /** The kill switch: stop for good (running tests stop at their next check). Returns whether it was stopped now. */
    public function stop(int $id, int $userId, string $reason): bool
    {
        $stmt = $this->db->prepare('UPDATE engagements SET stopped_by = :u, stopped_at = UTC_TIMESTAMP(), stop_reason = :r WHERE id = :id AND stopped_at IS NULL AND cancelled_at IS NULL');
        $stmt->execute(['u' => $userId, 'r' => mb_substr($reason, 0, 500), 'id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /** Withdraw before approval. Returns whether it was cancelled now. */
    public function cancel(int $id): bool
    {
        $stmt = $this->db->prepare('UPDATE engagements SET cancelled_at = UTC_TIMESTAMP() WHERE id = :id AND approved_at IS NULL AND cancelled_at IS NULL AND stopped_at IS NULL');
        $stmt->execute(['id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /** The engagement's state at $now (UTC 'Y-m-d H:i:s'). @param array<string,mixed> $e */
    public static function state(array $e, string $now): string
    {
        return match (true) {
            $e['cancelled_at'] !== null => self::STATE_CANCELLED,
            $e['stopped_at'] !== null => self::STATE_STOPPED,
            $e['approved_at'] === null => (string) $e['window_end'] <= $now ? self::STATE_ENDED : self::STATE_AWAITING,
            (string) $e['window_end'] <= $now => self::STATE_ENDED,
            (string) $e['window_start'] > $now => self::STATE_SCHEDULED,
            default => self::STATE_ACTIVE,
        };
    }

    /**
     * THE gate for every engagement test: approved, not stopped or cancelled, inside its window, read fresh from the
     * database (never a cached row), and the client not archived or paused, and scanning not paused globally.
     */
    public function isActive(int $id): bool
    {
        $stmt = $this->db->prepare("SELECT e.id FROM engagements e JOIN clients c ON c.id = e.client_id
            WHERE e.id = :id AND e.approved_at IS NOT NULL AND e.stopped_at IS NULL AND e.cancelled_at IS NULL
            AND e.window_start <= UTC_TIMESTAMP() AND e.window_end > UTC_TIMESTAMP() AND c.is_archived = 0 AND c.scanning_paused = 0
            AND NOT EXISTS (SELECT 1 FROM settings s WHERE s.name = 'scanning_paused' AND s.value = '1')");
        $stmt->execute(['id' => $id]);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * Whether a single address or hostname is an external target of this engagement and not excluded. (The caller
     * ALSO checks the client's live scope with ScopeService::isInScope(): both must agree.)
     *
     * @param list<array<string,mixed>> $targets the engagement's targets
     */
    public static function externalAllows(array $targets, string $target): bool
    {
        $canonical = ScopeService::canonicalTarget($target);
        if ($canonical === null || $canonical !== $target) {
            return false;
        }
        $ext = array_values(array_filter($targets, static fn (array $t): bool => $t['kind'] === 'external'));
        $excl = array_values(array_filter($targets, static fn (array $t): bool => $t['kind'] === 'exclude'));
        return ScopeService::matches($ext, $target) && !ScopeService::matches($excl, $target);
    }

    /**
     * Whether an internal address (or CIDR) is inside this engagement's ranges for $siteId and not excluded.
     *
     * @param list<array<string,mixed>> $targets
     */
    public static function internalAllows(array $targets, int $siteId, string $address): bool
    {
        $ranges = [];
        foreach ($targets as $t) {
            if ($t['kind'] === 'internal' && (int) $t['site_id'] === $siteId) {
                $ranges[] = (string) $t['value'];
            }
        }
        if ($ranges === [] || !InternalRanges::allWithin([$address], $ranges)) {
            return false;
        }
        foreach ($targets as $t) {
            if ($t['kind'] === 'exclude' && $t['entry_type'] !== 'domain' && InternalRanges::within($address, self::asCidr((string) $t['value']))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether a parsed external entry lies completely inside the client's active scope entries: an address or range
     * inside one authorised range, a domain authorised exactly or covered by an authorised wildcard (a wildcard only by
     * the same wildcard).
     *
     * @param array{type:string,value:string,range:?IpRange} $entry
     * @param list<array{entry_type:string,value:string,range_start:?string,range_end:?string}> $active
     */
    public static function insideScope(array $entry, array $active): bool
    {
        if ($entry['range'] !== null) {
            foreach ($active as $a) {
                if ($a['range_start'] !== null && strlen((string) $a['range_start']) === strlen($entry['range']->start)
                    && strcmp($entry['range']->start, (string) $a['range_start']) >= 0 && strcmp($entry['range']->end, (string) $a['range_end']) <= 0) {
                    return true;
                }
            }
            return false;
        }
        $v = $entry['value'];
        foreach ($active as $a) {
            if ($a['entry_type'] === 'domain' && (string) $a['value'] === $v) {
                return true;
            }
        }
        return !str_starts_with($v, '*.') && ScopeService::matches($active, $v);
    }

    /** "10.1.2.3" -> "10.1.2.3/32" (exclusions may be single addresses). */
    private static function asCidr(string $v): string
    {
        return str_contains($v, '/') ? $v : $v . (str_contains($v, ':') ? '/128' : '/32');
    }
}
