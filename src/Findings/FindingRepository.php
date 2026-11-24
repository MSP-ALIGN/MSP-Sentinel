<?php

declare(strict_types=1);

namespace Sentinel\Findings;

use PDO;

/**
 * Reading and triaging findings.
 *
 * Security assumptions: filter values are validated against fixed lists
 * before use, and all queries use bound parameters. Triage needs a note;
 * every change is written to finding_events and the audit log (by the controller).
 */
final class FindingRepository
{
    public const STATUSES = ['open', 'accepted', 'false_positive', 'resolved'];
    public const SEVERITIES = ['fail', 'warn'];
    public const TYPES = ['port', 'tls', 'web', 'vuln', 'email', 'patch', 'device', 'directory', 'dns'];
    /** Where a finding came from: the external scan, or an inventory source (internal devices). */
    public const SOURCES = ['external', 'internal'];
    public const PAGE_SIZE = 100;

    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Findings matching the filters, most important first (fail before warn, then newest).
     *
     * @param array{client?:int,status?:string,severity?:string,type?:string,assignee?:string,due?:string} $f Validated filters.
     *        assignee: 'none' or a user ID (digits); due: 'overdue' or 'soon' (open findings only);
     *        source: 'external' (internet scan) or 'internal' (inventory sources).
     * @return array{rows:list<array<string,mixed>>, total:int}
     */
    public function search(array $f, int $page = 1): array
    {
        [$sqlWhere, $params] = $this->filterSql($f);
        $order = ($f['due'] ?? '') !== '' ? 'f.due_at, f.id' : "f.status = 'open' DESC, f.severity = 'fail' DESC, f.reappeared DESC, f.first_seen DESC, f.id DESC";
        $count = $this->db->prepare("SELECT COUNT(*) FROM findings f JOIN clients c ON c.id = f.client_id WHERE {$sqlWhere}");
        $count->execute($params);
        $stmt = $this->db->prepare(
            "SELECT f.*, c.name AS client_name, u.username AS triaged_by_username, au.username AS assignee_username, " . self::GROUP_KEY_SQL . " AS group_key FROM findings f
             JOIN clients c ON c.id = f.client_id LEFT JOIN users u ON u.id = f.triaged_by LEFT JOIN users au ON au.id = f.assigned_to
             WHERE {$sqlWhere} ORDER BY {$order}
             LIMIT :lim OFFSET :off"
        );
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue('lim', self::PAGE_SIZE, PDO::PARAM_INT);
        $stmt->bindValue('off', (max(1, $page) - 1) * self::PAGE_SIZE, PDO::PARAM_INT);
        $stmt->execute();
        return ['rows' => $stmt->fetchAll(), 'total' => (int) $count->fetchColumn()];
    }

    /**
     * The same issue on several targets of one client (1.31): same client, same type, and the same CVE (or, without a
     * CVE, the same title). Titles never contain secrets; the key is a SHA-1 of those three, 40 hex characters.
     */
    public const GROUP_KEY_SQL = "SHA1(CONCAT(f.client_id, '|', f.finding_type, '|', COALESCE(NULLIF(f.cve_id, ''), f.title)))";
    /** Groups per page in the grouped list, and members shown per group (the rest: "show all"). */
    public const GROUPS_PER_PAGE = 50;
    public const MEMBERS_SHOWN = 100;

    /** The same key in PHP (reports and tests): client, type, CVE or title. */
    public static function groupKey(array $f): string
    {
        $cve = (string) ($f['cve_id'] ?? '');
        return sha1((int) $f['client_id'] . '|' . (string) $f['finding_type'] . '|' . ($cve !== '' ? $cve : (string) $f['title']));
    }

    /**
     * Findings matching the filters, grouped by issue (one row per issue per client), most important first: any open,
     * any Fail, most targets, newest. Each group carries up to MEMBERS_SHOWN of its findings (the filters apply to
     * them too).
     *
     * @param array<string,mixed> $f validated filters, as search()
     * @return array{groups:list<array<string,mixed>>, total:int} total: number of groups
     */
    public function searchGrouped(array $f, int $page = 1): array
    {
        [$sqlWhere, $params] = $this->filterSql($f);
        $key = self::GROUP_KEY_SQL;
        $count = $this->db->prepare("SELECT COUNT(DISTINCT {$key}) FROM findings f JOIN clients c ON c.id = f.client_id WHERE {$sqlWhere}");
        $count->execute($params);
        $stmt = $this->db->prepare(
            "SELECT {$key} AS group_key, f.client_id, MIN(c.name) AS client_name, f.finding_type, MIN(f.title) AS title, MIN(NULLIF(f.cve_id, '')) AS cve_id,
                    COUNT(*) AS n, SUM(f.status = 'open') AS open_n, MAX(f.severity = 'fail') AS any_fail, MIN(f.first_seen) AS first_seen,
                    MIN(CASE WHEN f.status = 'open' THEN f.due_at END) AS due_at, COUNT(DISTINCT f.status) AS statuses,
                    COUNT(DISTINCT COALESCE(f.assigned_to, 0)) AS owners, MAX(f.reappeared) AS reappeared
             FROM findings f JOIN clients c ON c.id = f.client_id
             WHERE {$sqlWhere}
             GROUP BY group_key, f.client_id, f.finding_type
             ORDER BY SUM(f.status = 'open') > 0 DESC, MAX(f.severity = 'fail') DESC, COUNT(*) DESC, MIN(f.first_seen) DESC, group_key
             LIMIT :lim OFFSET :off"
        );
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue('lim', self::GROUPS_PER_PAGE, PDO::PARAM_INT);
        $stmt->bindValue('off', (max(1, $page) - 1) * self::GROUPS_PER_PAGE, PDO::PARAM_INT);
        $stmt->execute();
        $groups = $stmt->fetchAll();
        if ($groups !== []) {
            // The members of this page's groups, with the same filters.
            $in = implode(',', array_map(fn (array $g): string => $this->db->quote((string) $g['group_key']), $groups));
            $m = $this->db->prepare(
                "SELECT f.*, {$key} AS group_key, au.username AS assignee_username FROM findings f JOIN clients c ON c.id = f.client_id
                 LEFT JOIN users au ON au.id = f.assigned_to
                 WHERE {$sqlWhere} AND {$key} IN ({$in})
                 ORDER BY f.status = 'open' DESC, f.severity = 'fail' DESC, f.target, f.id"
            );
            $m->execute($params);
            $members = [];
            foreach ($m->fetchAll() as $row) {
                if (count($members[$row['group_key']] ?? []) < self::MEMBERS_SHOWN) {
                    $members[$row['group_key']][] = $row;
                }
            }
            foreach ($groups as &$g) {
                $g['members'] = $members[$g['group_key']] ?? [];
                $g['severity'] = (int) $g['any_fail'] === 1 ? 'fail' : 'warn';
            }
            unset($g);
        }
        return ['groups' => $groups, 'total' => (int) $count->fetchColumn()];
    }

    /**
     * The WHERE clause and parameters for the validated filters (shared by both lists).
     *
     * @param array<string,mixed> $f
     * @return array{0:string, 1:array<string,int|string>}
     */
    private function filterSql(array $f): array
    {
        $where = ['c.is_archived = 0'];
        $params = [];
        if (!empty($f['client'])) {
            $where[] = 'f.client_id = :client';
            $params['client'] = (int) $f['client'];
        }
        foreach (['status' => self::STATUSES, 'severity' => self::SEVERITIES, 'type' => self::TYPES] as $key => $allowed) {
            if (!empty($f[$key]) && in_array($f[$key], $allowed, true)) {
                $col = $key === 'type' ? 'finding_type' : $key;
                $where[] = "f.{$col} = :{$key}";
                $params[$key] = $f[$key];
            }
        }
        if (($f['source'] ?? '') === 'external') {
            $where[] = "f.source = 'external'";
        } elseif (($f['source'] ?? '') === 'internal') {
            $where[] = "f.source <> 'external'";
        }
        if (($f['assignee'] ?? '') === 'none') {
            $where[] = 'f.assigned_to IS NULL';
        } elseif (ctype_digit((string) ($f['assignee'] ?? ''))) {
            $where[] = 'f.assigned_to = :assignee';
            $params['assignee'] = (int) $f['assignee'];
        }
        if (($f['due'] ?? '') === 'overdue') {
            $where[] = "f.status = 'open' AND f.due_at < UTC_TIMESTAMP()";
        } elseif (($f['due'] ?? '') === 'soon') {
            $where[] = "f.status = 'open' AND f.due_at >= UTC_TIMESTAMP() AND f.due_at < UTC_TIMESTAMP() + INTERVAL " . FixWorkflow::DUE_SOON_DAYS . ' DAY';
        }
        // One group (a "show all" link from the grouped list): 40 hex characters, compared as a bound value.
        if (preg_match('/^[0-9a-f]{40}$/', (string) ($f['group'] ?? '')) === 1) {
            $where[] = self::GROUP_KEY_SQL . ' = :group';
            $params['group'] = (string) $f['group'];
        }
        return [implode(' AND ', $where), $params];
    }

    /**
     * A finding with its client name, or null.
     *
     * @return array<string,mixed>|null
     */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT f.*, c.name AS client_name, c.is_archived AS client_archived, u.username AS triaged_by_username, a.last_scanned AS asset_last_scanned,
                                           au.username AS assignee_username, au.is_active AS assignee_active, ab.username AS assigned_by_username,
                                           vj.status AS verify_status, vj.summary AS verify_summary, vj.finished_at AS verify_finished_at
                                    FROM findings f JOIN clients c ON c.id = f.client_id LEFT JOIN users u ON u.id = f.triaged_by
                                    LEFT JOIN assets a ON a.id = f.asset_id LEFT JOIN users au ON au.id = f.assigned_to LEFT JOIN users ab ON ab.id = f.assigned_by
                                    LEFT JOIN scan_jobs vj ON vj.id = f.verify_job_id WHERE f.id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * History of a finding, oldest first.
     *
     * @return list<array<string,mixed>>
     */
    public function events(int $id): array
    {
        $stmt = $this->db->prepare('SELECT e.*, u.username FROM finding_events e LEFT JOIN users u ON u.id = e.user_id WHERE e.finding_id = :id ORDER BY e.id');
        $stmt->execute(['id' => $id]);
        return $stmt->fetchAll();
    }

    /**
     * Triage a finding: accepted, false_positive, or back to open. A resolved
     * finding can't be triaged (it isn't being seen).
     *
     * @param string $status Validated: accepted|false_positive|open.
     * @param string $note   Required, validated by the caller.
     * @return string|null The previous status, or null if nothing changed (resolved, or already that status).
     */
    public function triage(int $id, string $status, string $note, int $userId): ?string
    {
        if (!in_array($status, ['accepted', 'false_positive', 'open'], true)) {
            throw new \InvalidArgumentException('Invalid triage status.');
        }
        $this->db->beginTransaction();
        try {
            // Read the current status under a row lock, so the "from" in the history and audit is exact.
            $cur = $this->db->prepare('SELECT status FROM findings WHERE id = :id FOR UPDATE');
            $cur->execute(['id' => $id]);
            $previous = $cur->fetchColumn();
            if ($previous === false || $previous === 'resolved' || $previous === $status) {
                $this->db->rollBack();
                return null;
            }
            // A decision has been made, so the "reappeared" flag has done its job.
            // Reopening by hand keeps the original deadline (opened_at and any admin-set date): accepting and
            // reopening must never be a way to reset an overdue finding. Only admins move due dates.
            $this->db->prepare('UPDATE findings SET status = :s, triage_note = :n, triaged_by = :u, triaged_at = UTC_TIMESTAMP(), reappeared = 0, updated_at = UTC_TIMESTAMP() WHERE id = :id')
                ->execute(['s' => $status, 'n' => $note, 'u' => $userId, 'id' => $id]);
            $this->db->prepare('INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, :e, :u, :n, UTC_TIMESTAMP())')
                ->execute(['f' => $id, 'e' => 'triaged_' . $status, 'u' => $userId, 'n' => $note]);
            $this->db->commit();
            return (string) $previous;
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Counts of open (untriaged) findings by severity, for all clients or one.
     *
     * @return array{fail:int, warn:int, accepted:int, false_positive:int}
     */
    public function counts(?int $clientId = null): array
    {
        $sql = "SELECT SUM(f.status = 'open' AND f.severity = 'fail') AS fail, SUM(f.status = 'open' AND f.severity = 'warn') AS warn,
                       SUM(f.status = 'accepted') AS accepted, SUM(f.status = 'false_positive') AS false_positive
                FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_archived = 0" . ($clientId === null ? '' : ' WHERE f.client_id = :c');
        $stmt = $this->db->prepare($sql);
        $stmt->execute($clientId === null ? [] : ['c' => $clientId]);
        $row = $stmt->fetch() ?: [];
        return ['fail' => (int) ($row['fail'] ?? 0), 'warn' => (int) ($row['warn'] ?? 0),
                'accepted' => (int) ($row['accepted'] ?? 0), 'false_positive' => (int) ($row['false_positive'] ?? 0)];
    }

    /**
     * Clients (not archived) that have any findings, for the filter dropdown.
     *
     * @return list<array{id:int,name:string}>
     */
    public function clientsWithFindings(): array
    {
        return $this->db->query('SELECT DISTINCT c.id, c.name FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 ORDER BY c.name')->fetchAll();
    }
}
