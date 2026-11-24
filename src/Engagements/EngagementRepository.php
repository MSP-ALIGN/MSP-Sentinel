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
 * - two-person rule: approve() only succeeds for an admin who did not create it (the controller checks the role),
 *   unless the engagement was created while two-person approval was off AND it is still off (1.47, single_approval);
 * - nothing runs before approval, outside the window, after a stop (kill switch) or a cancel;
 * - approved engagements are never edited: they can only be stopped. A cancel is only possible before approval.
 *
 * Untrusted: nothing here comes straight from a form; the controller validates first. Values are bound parameters.
 */
final class EngagementRepository
{
    /** Test types an engagement can allow (fixed list; labels in the UI). */
    public const TESTS = ['tcp_full', 'udp_common', 'nse_safe', 'anon_access', 'default_creds'];
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
     *              signer_role:string, signed_on:string, document_sha256:string, document_name:string, document_bytes:int, notes:string, retest_of?:?int} $e
     * @param list<array{kind:string, site_id:?int, entry_type:string, value:string, range_start:?string, range_end:?string}> $targets
     */
    public function create(int $clientId, array $e, array $targets, int $userId): int
    {
        $this->db->beginTransaction();
        try {
            $this->db->prepare('INSERT INTO engagements (client_id, name, window_start, window_end, intensity, tests, signer_name, signer_role, signed_on,
                document_sha256, document_name, document_bytes, notes, retest_of, single_approval, created_by, created_at)
                VALUES (:c, :n, :ws, :we, :i, :t, :sn, :sr, :so, :dh, :dn, :db, :no, :rt, :sa, :u, UTC_TIMESTAMP())')->execute([
                'c' => $clientId, 'n' => $e['name'], 'ws' => $e['window_start'], 'we' => $e['window_end'], 'i' => $e['intensity'], 't' => implode(',', $e['tests']),
                'sn' => $e['signer_name'], 'sr' => $e['signer_role'], 'so' => $e['signed_on'], 'dh' => $e['document_sha256'], 'dn' => $e['document_name'],
                'db' => $e['document_bytes'], 'no' => $e['notes'] !== '' ? $e['notes'] : null, 'rt' => $e['retest_of'] ?? null, 'u' => $userId,
                'sa' => !empty($e['single_approval']) ? 1 : 0,
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
     * Every engagement across clients, newest first (the Engagements page, 1.34), at most $limit.
     *
     * @return list<array<string,mixed>>
     */
    public function all(int $limit = 200, ?array $clientIds = null): array
    {
        return $this->db->query('SELECT e.*, c.name AS client_name, uc.display_name AS created_by_name, ua.display_name AS approved_by_name FROM engagements e
            JOIN clients c ON c.id = e.client_id LEFT JOIN users uc ON uc.id = e.created_by LEFT JOIN users ua ON ua.id = e.approved_by WHERE 1 = 1'
            . \Sentinel\Auth\ClientAccess::sql('e.client_id', $clientIds) . ' ORDER BY e.id DESC LIMIT ' . max(1, $limit))->fetchAll(); // 1.41
    }

    /**
     * Accounts linked to $userId in the last 30 days, in either direction and through chains: one created the other, or
     * reset its password or two-factor authentication (from the audit log). The two-person rule refuses an approver in
     * the creator's group, so one admin can't approve their own engagement through an account they made or reset, or
     * one made by such an account (1.34 audit). Includes $userId itself.
     *
     * @return list<int>
     */
    public function linkedAccounts(int $userId): array
    {
        $edges = $this->db->query("SELECT user_id, target_id FROM audit_log WHERE target_type = 'user' AND user_id IS NOT NULL AND target_id IS NOT NULL
            AND action IN ('user.created', 'user.password_reset', 'user.2fa_reset') AND created_at >= UTC_TIMESTAMP() - INTERVAL 30 DAY LIMIT 10000")->fetchAll();
        $adj = [];
        foreach ($edges as $e) {
            $a = (int) $e['user_id'];
            $b = (int) $e['target_id'];
            $adj[$a][$b] = true;
            $adj[$b][$a] = true;
        }
        $seen = [$userId => true];
        $queue = [$userId];
        while ($queue !== []) {
            foreach (array_keys($adj[array_shift($queue)] ?? []) as $next) {
                if (!isset($seen[$next])) {
                    $seen[$next] = true;
                    $queue[] = $next;
                }
            }
        }
        return array_keys($seen);
    }

    /**
     * Engagements waiting for a second admin, that $userId may approve (not their own), window not over (1.34).
     *
     * @return list<array<string,mixed>>
     */
    public function awaitingApprovalBy(int $userId, ?array $clientIds = null, bool $twoPersonNow = true): array
    {
        // With two-person approval off (1.47), their own single-approval engagements are listed too.
        $stmt = $this->db->prepare('SELECT e.id, e.name, e.window_start, e.window_end, e.created_by, e.single_approval, c.name AS client_name, uc.display_name AS created_by_name
            FROM engagements e JOIN clients c ON c.id = e.client_id LEFT JOIN users uc ON uc.id = e.created_by
            WHERE e.approved_at IS NULL AND e.stopped_at IS NULL AND e.cancelled_at IS NULL AND e.window_end > UTC_TIMESTAMP()
              AND (e.created_by <> :u OR (e.single_approval = 1 AND :off = 1))'
            . \Sentinel\Auth\ClientAccess::sql('e.client_id', $clientIds) . ' ORDER BY e.window_start LIMIT 50'); // only their clients (1.41)
        $stmt->execute(['u' => $userId, 'off' => $twoPersonNow ? 0 : 1]);
        // Only those this admin may really approve (not linked to the creator; see linkedAccounts()), unless self-approval applies.
        $linked = $this->linkedAccounts($userId);
        return array_slice(array_values(array_filter($stmt->fetchAll(), static fn (array $e): bool =>
            self::selfApprovalAllowed($e, $twoPersonNow) || ((int) $e['created_by'] !== $userId && !in_array((int) $e['created_by'], $linked, true)))), 0, 20);
    }

    /**
     * Approve (two-person rule: never by its creator). Only while awaiting approval and before the window ends.
     * $selfAllowed (1.47): two-person approval is off now; the creator may then approve an engagement that was ALSO
     * created while it was off (single_approval = 1). Returns whether it was approved now.
     */
    public function approve(int $id, int $userId, bool $selfAllowed = false): bool
    {
        // The setting is read again in the same statement (1.47.1): an Admin turning two-person approval back on while
        // this request checked the password wins. A missing settings row means "on" (the default).
        $stmt = $this->db->prepare('UPDATE engagements SET approved_by = :u, approved_at = UTC_TIMESTAMP() WHERE id = :id AND approved_at IS NULL
            AND stopped_at IS NULL AND cancelled_at IS NULL AND window_end > UTC_TIMESTAMP()
            AND (created_by <> :u2 OR (single_approval = 1 AND :self = 1 AND ' . self::TWO_PERSON_OFF_SQL . '))');
        $stmt->execute(['u' => $userId, 'u2' => $userId, 'self' => $selfAllowed ? 1 : 0, 'id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /** SQL true only while two-person approval is turned off in Settings (no row: the default, on). */
    private const TWO_PERSON_OFF_SQL = "EXISTS (SELECT 1 FROM settings s WHERE s.name = 'engagement_two_person' AND s.value = '0')";

    /** May the creator approve this engagement themselves (1.47)? Only if created while two-person was off, and still off. */
    public static function selfApprovalAllowed(array $engagement, bool $twoPersonNow): bool
    {
        return !$twoPersonNow && (int) ($engagement['single_approval'] ?? 0) === 1;
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

    /**
     * Record what a test found on one host (evidence for the report). Values came from the tested host: untrusted.
     *
     * @param list<array<string,mixed>> $ports open ports with service details and script results
     * @param array<string,mixed> $checks other checks (host scripts, UDP probes, anonymous access)
     */
    public function addResult(int $engagementId, string $origin, ?int $siteId, string $jobRef, string $ip, array $hostnames, array $ports, array $checks, bool $complete): void
    {
        $this->db->prepare('INSERT INTO engagement_results (engagement_id, origin, site_id, job_ref, ip, hostnames, ports, checks, complete, scanned_at)
            VALUES (:e, :o, :s, :j, :ip, :h, :p, :c, :ok, UTC_TIMESTAMP())')->execute([
            'e' => $engagementId, 'o' => $origin, 's' => $siteId, 'j' => mb_substr($jobRef, 0, 40), 'ip' => $ip, 'h' => mb_substr(implode(', ', $hostnames), 0, 500),
            'p' => (string) json_encode($ports, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), 'c' => (string) json_encode($checks, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
            'ok' => $complete ? 1 : 0,
        ]);
    }

    /**
     * The latest result per host and origin (a host tested again, e.g. a retest, shows its newest result).
     *
     * @return list<array<string,mixed>> with 'ports_list' and 'checks_list' decoded
     */
    public function results(int $engagementId): array
    {
        $stmt = $this->db->prepare('SELECT r.* FROM engagement_results r JOIN (SELECT origin, ip, MAX(id) AS id FROM engagement_results WHERE engagement_id = :e GROUP BY origin, ip) l
            ON l.id = r.id ORDER BY r.origin, INET6_ATON(r.ip), r.ip');
        $stmt->execute(['e' => $engagementId]);
        $rows = $stmt->fetchAll();
        foreach ($rows as &$r) {
            $r['ports_list'] = (array) (json_decode((string) $r['ports'], true) ?: []);
            $r['checks_list'] = (array) (json_decode((string) $r['checks'], true) ?: []);
        }
        return $rows;
    }

    /**
     * What the default-credential test may still do (1.29.1), so no account ever sees a second failed attempt from
     * re-runs: 'done' holds, per address, the credential results already recorded in THIS engagement (that host isn't
     * tried again; its earlier result is carried into the new evidence). 'retest' (a retest engagement only) holds,
     * per address, the logins that worked in the engagement it retests ("service:port" => username): only those are
     * tried again, one attempt each. Null when it isn't a retest.
     *
     * @param array<string,mixed> $e find()
     * @return array{done:array<string,list<array<string,mixed>>>, retest:?array<string,array<string,string>>}
     */
    public function credsPlan(array $e): array
    {
        $done = [];
        foreach ($this->results((int) $e['id']) as $r) {
            if (is_array($r['checks_list']['creds'] ?? null)) {
                $done[(string) $r['ip']] = array_merge($done[(string) $r['ip']] ?? [], $r['checks_list']['creds']);
            }
        }
        $retest = null;
        if (!empty($e['retest_of'])) {
            $retest = [];
            foreach ($this->results((int) $e['retest_of']) as $r) {
                foreach ((array) ($r['checks_list']['creds'] ?? []) as $c) {
                    if (($c['result'] ?? '') === 'login' && is_string($c['user'] ?? null)) {
                        $retest[(string) $r['ip']][(string) $c['service'] . ':' . (int) $c['port']] = $c['user'];
                    }
                }
            }
        }
        return ['done' => $done, 'retest' => $retest];
    }

    /** The engagement's scan jobs (external tests), newest first. @return list<array<string,mixed>> */
    public function externalJobs(int $engagementId): array
    {
        $stmt = $this->db->prepare("SELECT id, status, created_at, started_at, finished_at, summary FROM scan_jobs WHERE job_type = 'engagement'
            AND JSON_UNQUOTE(JSON_EXTRACT(payload, '$.engagement_id')) = :e ORDER BY id DESC");
        $stmt->execute(['e' => (string) $engagementId]);
        return $stmt->fetchAll();
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
