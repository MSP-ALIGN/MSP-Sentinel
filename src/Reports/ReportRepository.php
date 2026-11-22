<?php

declare(strict_types=1);

namespace Sentinel\Reports;

use PDO;

/**
 * Stores and lists frozen reports.
 *
 * Security assumptions: a report is written once and never updated (only
 * deleted by an admin). Callers check roles; this class only runs queries,
 * all with bound parameters.
 */
final class ReportRepository
{
    /** Uses the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Save a report.
     *
     * @param array<string,mixed> $snapshot
     */
    public function create(int $clientId, string $kind, string $source, string $title, string $start, string $end, ?int $userId, string $html, array $snapshot): int
    {
        $this->db->prepare(
            'INSERT INTO reports (client_id, kind, source, title, period_start, period_end, generated_at, generated_by, html, snapshot, html_sha256)
             VALUES (:c, :k, :s, :t, :ps, :pe, UTC_TIMESTAMP(), :u, :h, :j, :sha)'
        )->execute([
            'c' => $clientId, 'k' => $kind, 's' => $source, 't' => mb_substr($title, 0, 300), 'ps' => $start, 'pe' => $end, 'u' => $userId,
            'h' => $html, 'j' => json_encode($snapshot, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR), 'sha' => hash('sha256', $html),
        ]);
        return (int) $this->db->lastInsertId();
    }

    /** One report with its client name (including the HTML), or null. */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT r.*, c.name AS client_name, u.display_name AS generated_by_name FROM reports r JOIN clients c ON c.id = r.client_id
                                    LEFT JOIN users u ON u.id = r.generated_by WHERE r.id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Report list (without the HTML), newest first.
     *
     * @return list<array<string,mixed>>
     */
    public function list(?int $clientId = null, int $limit = 200): array
    {
        $sql = 'SELECT r.id, r.client_id, r.kind, r.source, r.title, r.period_start, r.period_end, r.generated_at, r.html_sha256, c.name AS client_name,
                       u.display_name AS generated_by_name, LENGTH(r.html) AS size
                FROM reports r JOIN clients c ON c.id = r.client_id LEFT JOIN users u ON u.id = r.generated_by'
            . ($clientId !== null ? ' WHERE r.client_id = :c' : '') . ' ORDER BY r.id DESC LIMIT ' . max(1, min(1000, $limit));
        $stmt = $this->db->prepare($sql);
        $stmt->execute($clientId !== null ? ['c' => $clientId] : []);
        return $stmt->fetchAll();
    }

    /** True if a scheduled report for this client and period start already exists. */
    public function scheduledExists(int $clientId, string $periodStart): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM reports WHERE client_id = :c AND source = 'scheduled' AND period_start = :p");
        $stmt->execute(['c' => $clientId, 'p' => $periodStart]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** Delete a report. Returns false if it didn't exist. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM reports WHERE id = :id');
        $stmt->execute(['id' => $id]);
        return $stmt->rowCount() === 1;
    }
}
