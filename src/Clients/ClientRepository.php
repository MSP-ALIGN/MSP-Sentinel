<?php

declare(strict_types=1);

namespace Sentinel\Clients;

use PDO;

/**
 * Database access for clients and their sites.
 *
 * Security assumptions:
 * - All queries use bound parameters. Callers validate input first.
 * - Clients are archived, never deleted, so their authorisation history
 *   (evidence) stays intact.
 * - Every new client gets one default site in the same transaction, so a
 *   client never exists without a site (agents attach to sites later).
 */
final class ClientRepository
{
    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * All clients with summary columns for the list page.
     *
     * @param bool $includeArchived Also list archived clients.
     * @return list<array<string,mixed>>
     */
    public function all(bool $includeArchived = false): array
    {
        $sql = 'SELECT c.*, (SELECT COUNT(*) FROM sites s WHERE s.client_id = c.id) AS site_count
                FROM clients c' . ($includeArchived ? '' : ' WHERE c.is_archived = 0') . ' ORDER BY c.name';
        return $this->db->query($sql)->fetchAll();
    }

    /**
     * A client by ID, or null.
     *
     * @return array<string,mixed>|null
     */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM clients WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** True if another client already has this name (case-insensitive). */
    public function nameTaken(string $name, ?int $exceptId = null): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM clients WHERE name = :n AND id <> :id');
        $stmt->execute(['n' => $name, 'id' => $exceptId ?? 0]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /**
     * Create a client and its default site in one transaction.
     *
     * @param array{name:string,itflow_client_id:?int,timezone:string,scan_window_start:string,scan_window_end:string,notes:string} $v Validated values.
     * @return int New client ID.
     */
    public function create(array $v, int $userId): int
    {
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO clients (name, itflow_client_id, timezone, scan_window_start, scan_window_end, notes, created_by, created_at, updated_at)
                 VALUES (:n, :it, :tz, :ws, :we, :notes, :uid, UTC_TIMESTAMP(), UTC_TIMESTAMP())'
            );
            $stmt->execute([
                'n' => $v['name'], 'it' => $v['itflow_client_id'], 'tz' => $v['timezone'],
                'ws' => $v['scan_window_start'], 'we' => $v['scan_window_end'], 'notes' => $v['notes'], 'uid' => $userId,
            ]);
            $id = (int) $this->db->lastInsertId();
            $this->db->prepare(
                "INSERT INTO sites (client_id, name, is_default, created_at, updated_at) VALUES (:c, 'Main site', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())"
            )->execute(['c' => $id]);
            $this->db->commit();
            return $id;
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Update a client's details.
     *
     * @param array{name:string,itflow_client_id:?int,timezone:string,scan_window_start:string,scan_window_end:string,notes:string} $v Validated values.
     */
    public function update(int $id, array $v): void
    {
        $stmt = $this->db->prepare(
            'UPDATE clients SET name = :n, itflow_client_id = :it, timezone = :tz, scan_window_start = :ws, scan_window_end = :we,
                    notes = :notes, updated_at = UTC_TIMESTAMP() WHERE id = :id'
        );
        $stmt->execute([
            'n' => $v['name'], 'it' => $v['itflow_client_id'], 'tz' => $v['timezone'],
            'ws' => $v['scan_window_start'], 'we' => $v['scan_window_end'], 'notes' => $v['notes'], 'id' => $id,
        ]);
    }

    /** Archive or restore a client. Archived clients are never scanned. */
    public function setArchived(int $id, bool $archived): void
    {
        $this->db->prepare('UPDATE clients SET is_archived = :a, updated_at = UTC_TIMESTAMP() WHERE id = :id')
            ->execute(['a' => $archived ? 1 : 0, 'id' => $id]);
    }

    /** Pause or resume scanning for one client (per-client kill switch). */
    public function setPaused(int $id, bool $paused): void
    {
        $this->db->prepare('UPDATE clients SET scanning_paused = :p, updated_at = UTC_TIMESTAMP() WHERE id = :id')
            ->execute(['p' => $paused ? 1 : 0, 'id' => $id]);
    }

    /** @return list<array<string,mixed>> Sites of a client, default first. */
    public function sites(int $clientId): array
    {
        $stmt = $this->db->prepare('SELECT * FROM sites WHERE client_id = :c ORDER BY is_default DESC, name');
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * A site by ID, or null.
     *
     * @return array<string,mixed>|null
     */
    public function findSite(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM sites WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** True if the client already has a site with this name (case-insensitive). */
    public function siteNameTaken(int $clientId, string $name, ?int $exceptId = null): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM sites WHERE client_id = :c AND name = :n AND id <> :id');
        $stmt->execute(['c' => $clientId, 'n' => $name, 'id' => $exceptId ?? 0]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** Add a site. Values have been validated. */
    public function createSite(int $clientId, string $name, ?int $itflowLocationId): int
    {
        $this->db->prepare(
            'INSERT INTO sites (client_id, name, itflow_location_id, is_default, created_at, updated_at) VALUES (:c, :n, :l, 0, UTC_TIMESTAMP(), UTC_TIMESTAMP())'
        )->execute(['c' => $clientId, 'n' => $name, 'l' => $itflowLocationId]);
        return (int) $this->db->lastInsertId();
    }

    /** Rename a site or change its ITFlow location ID. Values have been validated. */
    public function updateSite(int $id, string $name, ?int $itflowLocationId): void
    {
        $this->db->prepare('UPDATE sites SET name = :n, itflow_location_id = :l, updated_at = UTC_TIMESTAMP() WHERE id = :id')
            ->execute(['n' => $name, 'l' => $itflowLocationId, 'id' => $id]);
    }
}
