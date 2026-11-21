<?php

declare(strict_types=1);

namespace Sentinel\Scope;

use PDO;

/**
 * Database access for scan authorisations and their scope entries.
 *
 * Security assumptions:
 * - An authorisation and all its scope entries are written in one
 *   transaction. A half-saved scope can never exist.
 * - Authorisations are never edited. The only change allowed is revoking,
 *   and only once (a conditional UPDATE).
 * - Scope values come only from ScopeParser (canonical, validated).
 */
final class AuthorisationRepository
{
    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Save a new authorisation with its scope.
     *
     * @param array{approved_by_name:string,approved_by_role:string,approved_on:string,valid_from:string,valid_until:string,document_ref:string,notes:string} $v Validated values.
     * @param list<array{type:string,value:string,range:?IpRange}> $entries Parsed scope entries.
     * @return int New authorisation ID.
     */
    public function create(int $clientId, array $v, array $entries, int $userId): int
    {
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO scan_authorisations (client_id, approved_by_name, approved_by_role, approved_on, valid_from, valid_until, document_ref, notes, recorded_by, created_at)
                 VALUES (:c, :n, :r, :on, :from, :until, :doc, :notes, :uid, UTC_TIMESTAMP())'
            );
            $stmt->execute([
                'c' => $clientId, 'n' => $v['approved_by_name'], 'r' => $v['approved_by_role'], 'on' => $v['approved_on'],
                'from' => $v['valid_from'], 'until' => $v['valid_until'], 'doc' => $v['document_ref'], 'notes' => $v['notes'], 'uid' => $userId,
            ]);
            $id = (int) $this->db->lastInsertId();
            $insert = $this->db->prepare(
                'INSERT INTO scope_entries (authorisation_id, client_id, entry_type, value, range_start, range_end) VALUES (:a, :c, :t, :v, :s, :e)'
            );
            foreach ($entries as $entry) {
                $insert->bindValue('a', $id, PDO::PARAM_INT);
                $insert->bindValue('c', $clientId, PDO::PARAM_INT);
                $insert->bindValue('t', $entry['type']);
                $insert->bindValue('v', $entry['value']);
                $insert->bindValue('s', $entry['range']?->start, $entry['range'] === null ? PDO::PARAM_NULL : PDO::PARAM_LOB);
                $insert->bindValue('e', $entry['range']?->end, $entry['range'] === null ? PDO::PARAM_NULL : PDO::PARAM_LOB);
                $insert->execute();
            }
            $this->db->commit();
            return $id;
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * An authorisation by ID, or null.
     *
     * @return array<string,mixed>|null
     */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM scan_authorisations WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Authorisations of a client, newest first, each with its scope entries
     * and the names of the users who recorded or revoked it.
     *
     * @return list<array<string,mixed>>
     */
    public function forClient(int $clientId): array
    {
        $stmt = $this->db->prepare(
            'SELECT a.*, ru.username AS recorded_by_username, vu.username AS revoked_by_username
             FROM scan_authorisations a
             LEFT JOIN users ru ON ru.id = a.recorded_by
             LEFT JOIN users vu ON vu.id = a.revoked_by
             WHERE a.client_id = :c ORDER BY a.id DESC'
        );
        $stmt->execute(['c' => $clientId]);
        $rows = $stmt->fetchAll();
        if ($rows === []) {
            return [];
        }
        $entries = $this->db->prepare('SELECT authorisation_id, entry_type, value FROM scope_entries WHERE client_id = :c ORDER BY id');
        $entries->execute(['c' => $clientId]);
        $byAuth = [];
        foreach ($entries->fetchAll() as $e) {
            $byAuth[(int) $e['authorisation_id']][] = $e;
        }
        foreach ($rows as &$row) {
            $row['entries'] = $byAuth[(int) $row['id']] ?? [];
        }
        unset($row);
        return $rows;
    }

    /**
     * Revoke an authorisation (only if not already revoked).
     *
     * @return bool False if it was already revoked.
     */
    public function revoke(int $id, int $userId, string $reason): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE scan_authorisations SET revoked_at = UTC_TIMESTAMP(), revoked_by = :u, revoke_reason = :r WHERE id = :id AND revoked_at IS NULL'
        );
        $stmt->execute(['u' => $userId, 'r' => $reason, 'id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Find other clients whose not-revoked scope overlaps these entries.
     * Used to warn about typos that would point scans at the wrong client.
     *
     * @param list<array{type:string,value:string,range:?IpRange}> $entries
     * @return list<array{value:string,client:string}> One row per overlapping entry.
     */
    public function overlapsWithOtherClients(int $clientId, array $entries): array
    {
        $hits = [];
        $rangeStmt = $this->db->prepare(
            'SELECT DISTINCT c.name FROM scope_entries e
             JOIN scan_authorisations a ON a.id = e.authorisation_id AND a.revoked_at IS NULL
             JOIN clients c ON c.id = e.client_id AND c.is_archived = 0
             WHERE e.client_id <> :c AND e.range_start IS NOT NULL
               AND LENGTH(e.range_start) = :len AND e.range_start <= :end AND e.range_end >= :start'
        );
        // Other clients' domain entries, compared in PHP so wildcards match both ways.
        $domainStmt = $this->db->prepare(
            'SELECT e.value, c.name FROM scope_entries e
             JOIN scan_authorisations a ON a.id = e.authorisation_id AND a.revoked_at IS NULL
             JOIN clients c ON c.id = e.client_id AND c.is_archived = 0
             WHERE e.client_id <> :c AND e.entry_type = \'domain\''
        );
        $domainStmt->execute(['c' => $clientId]);
        $otherDomains = $domainStmt->fetchAll();
        foreach ($entries as $entry) {
            if ($entry['range'] !== null) {
                $rangeStmt->bindValue('c', $clientId, PDO::PARAM_INT);
                $rangeStmt->bindValue('len', strlen($entry['range']->start), PDO::PARAM_INT);
                $rangeStmt->bindValue('start', $entry['range']->start, PDO::PARAM_LOB);
                $rangeStmt->bindValue('end', $entry['range']->end, PDO::PARAM_LOB);
                $rangeStmt->execute();
                $names = $rangeStmt->fetchAll(PDO::FETCH_COLUMN);
            } else {
                $names = [];
                foreach ($otherDomains as $other) {
                    if (self::domainsOverlap($entry['value'], (string) $other['value'])) {
                        $names[(string) $other['name']] = (string) $other['name'];
                    }
                }
            }
            foreach ($names as $name) {
                $hits[] = ['value' => $entry['value'], 'client' => (string) $name];
            }
        }
        return $hits;
    }

    /**
     * True if two domain scope entries can match the same host:
     * equal, or one is a wildcard covering the other (or both are wildcards on related names).
     */
    public static function domainsOverlap(string $a, string $b): bool
    {
        if ($a === $b) {
            return true;
        }
        $covers = static function (string $wild, string $other): bool {
            if (!str_starts_with($wild, '*.')) {
                return false;
            }
            $suffix = substr($wild, 1); // ".client.example"
            $otherHost = str_starts_with($other, '*.') ? substr($other, 2) : $other;
            return str_ends_with($otherHost, $suffix) || (str_starts_with($other, '*.') && str_ends_with(substr($wild, 2), '.' . $otherHost));
        };
        return $covers($a, $b) || $covers($b, $a);
    }

    /**
     * Not-revoked scope entries of a client whose validity covers $today,
     * for scope checks.
     *
     * @param string $today Y-m-d in the client's timezone.
     * @return list<array{entry_type:string,value:string,range_start:?string,range_end:?string}>
     */
    public function activeEntries(int $clientId, string $today): array
    {
        $stmt = $this->db->prepare(
            'SELECT e.entry_type, e.value, e.range_start, e.range_end FROM scope_entries e
             JOIN scan_authorisations a ON a.id = e.authorisation_id
             WHERE e.client_id = :c AND a.revoked_at IS NULL AND a.valid_from <= :t1 AND a.valid_until >= :t2'
        );
        $stmt->execute(['c' => $clientId, 't1' => $today, 't2' => $today]);
        return $stmt->fetchAll();
    }
}
