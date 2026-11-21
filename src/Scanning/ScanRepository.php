<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use PDO;

/**
 * Database access for scan jobs, the append-only scan log, assets and services.
 *
 * Security assumptions:
 * - All queries use bound parameters. Values from nmap output have been
 *   cleaned by NmapXmlParser.
 * - A job is claimed with a conditional UPDATE (queued -> running), so two
 *   workers can never run the same job.
 * - scan_log rows are only ever inserted, then finished once (finished_at
 *   and result). They are never deleted or rewritten.
 */
final class ScanRepository
{
    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Queue a job.
     *
     * @param array{ips:list<string>,hostnames:list<string>,ports:list<int>} $payload Targets and ports at queue time.
     */
    public function queue(int $clientId, string $trigger, ?int $userId, bool $outsideWindow, ?string $reason, array $payload): int
    {
        $this->db->prepare(
            "INSERT INTO scan_jobs (client_id, job_type, trigger_type, requested_by, outside_window, override_reason, status, payload, created_at)
             VALUES (:c, 'ports', :t, :u, :o, :r, 'queued', :p, UTC_TIMESTAMP())"
        )->execute(['c' => $clientId, 't' => $trigger, 'u' => $userId, 'o' => $outsideWindow ? 1 : 0, 'r' => $reason,
                    'p' => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
        return (int) $this->db->lastInsertId();
    }

    /**
     * A job by ID (payload and summary decoded), or null.
     *
     * @return array<string,mixed>|null
     */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM scan_jobs WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : self::decode($row);
    }

    /**
     * The client's queued or running job, if any.
     *
     * @return array<string,mixed>|null
     */
    public function openJob(int $clientId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM scan_jobs WHERE client_id = :c AND status IN ('queued','running') ORDER BY id LIMIT 1");
        $stmt->execute(['c' => $clientId]);
        $row = $stmt->fetch();
        return $row === false ? null : self::decode($row);
    }

    /**
     * All queued jobs, oldest first.
     *
     * @return list<array<string,mixed>>
     */
    public function queuedJobs(): array
    {
        return array_map([self::class, 'decode'], $this->db->query("SELECT * FROM scan_jobs WHERE status = 'queued' ORDER BY id LIMIT 200")->fetchAll());
    }

    /**
     * Recent jobs of a client.
     *
     * @return list<array<string,mixed>>
     */
    public function recentJobs(int $clientId, int $limit = 5): array
    {
        $stmt = $this->db->prepare('SELECT j.*, u.username AS requested_by_username FROM scan_jobs j LEFT JOIN users u ON u.id = j.requested_by
                                    WHERE j.client_id = :c ORDER BY j.id DESC LIMIT :lim');
        $stmt->bindValue('c', $clientId, PDO::PARAM_INT);
        $stmt->bindValue('lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return array_map([self::class, 'decode'], $stmt->fetchAll());
    }

    /** When the client's last scheduled job that wasn't cancelled or failed was queued (UTC), or null. */
    public function lastScheduledAt(int $clientId): ?string
    {
        // Cancelled (e.g. during a pause) and failed jobs don't count: the weekly scan is still due.
        $stmt = $this->db->prepare("SELECT MAX(created_at) FROM scan_jobs WHERE client_id = :c AND trigger_type = 'scheduled' AND status NOT IN ('cancelled','failed')");
        $stmt->execute(['c' => $clientId]);
        $v = $stmt->fetchColumn();
        return $v === null || $v === false ? null : (string) $v;
    }

    /** Claim a queued job for running. False if someone else took it (or it was cancelled). */
    public function claim(int $jobId): bool
    {
        $stmt = $this->db->prepare("UPDATE scan_jobs SET status = 'running', started_at = UTC_TIMESTAMP() WHERE id = :id AND status = 'queued'");
        $stmt->execute(['id' => $jobId]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Finish a job.
     *
     * @param array<string,mixed> $summary Counts and messages (no secrets).
     */
    public function finish(int $jobId, string $status, array $summary): void
    {
        $this->db->prepare('UPDATE scan_jobs SET status = :s, finished_at = UTC_TIMESTAMP(), summary = :j WHERE id = :id')
            ->execute(['s' => $status, 'j' => json_encode($summary, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR), 'id' => $jobId]);
    }

    /**
     * Cancel a job: a queued job is cancelled at once; a running job gets a
     * cancel request that the worker acts on within seconds.
     *
     * @return string 'cancelled', 'requested' or 'not_open'.
     */
    public function cancel(int $jobId): string
    {
        $stmt = $this->db->prepare("UPDATE scan_jobs SET status = 'cancelled', finished_at = UTC_TIMESTAMP() WHERE id = :id AND status = 'queued'");
        $stmt->execute(['id' => $jobId]);
        if ($stmt->rowCount() === 1) {
            return 'cancelled';
        }
        $stmt = $this->db->prepare("UPDATE scan_jobs SET cancel_requested = 1 WHERE id = :id AND status = 'running'");
        $stmt->execute(['id' => $jobId]);
        return $stmt->rowCount() === 1 ? 'requested' : 'not_open';
    }

    /** True if someone asked to cancel this running job. */
    public function cancelRequested(int $jobId): bool
    {
        $stmt = $this->db->prepare('SELECT cancel_requested FROM scan_jobs WHERE id = :id');
        $stmt->execute(['id' => $jobId]);
        return (int) $stmt->fetchColumn() === 1;
    }

    /** Append a scan-log row. Returns its ID (to finish it later). */
    public function logStart(int $jobId, int $clientId, string $target, ?string $hostname, string $ports, string $result, string $detail = ''): int
    {
        $this->db->prepare(
            'INSERT INTO scan_log (job_id, client_id, target, hostname, ports, result, detail, started_at) VALUES (:j, :c, :t, :h, :p, :r, :d, UTC_TIMESTAMP())'
        )->execute(['j' => $jobId, 'c' => $clientId, 't' => $target, 'h' => $hostname, 'p' => mb_substr($ports, 0, 1000), 'r' => $result, 'd' => mb_substr($detail, 0, 500)]);
        return (int) $this->db->lastInsertId();
    }

    /** Record the outcome of a logged host (only if it isn't finished yet). */
    public function logFinish(int $logId, string $result, string $detail): void
    {
        $this->db->prepare('UPDATE scan_log SET result = :r, detail = :d, finished_at = UTC_TIMESTAMP() WHERE id = :id AND finished_at IS NULL')
            ->execute(['r' => $result, 'd' => mb_substr($detail, 0, 500), 'id' => $logId]);
    }

    /**
     * Recent scan-log rows for a client.
     *
     * @return list<array<string,mixed>>
     */
    public function logForClient(int $clientId, int $limit = 50): array
    {
        $stmt = $this->db->prepare('SELECT * FROM scan_log WHERE client_id = :c ORDER BY id DESC LIMIT :lim');
        $stmt->bindValue('c', $clientId, PDO::PARAM_INT);
        $stmt->bindValue('lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Store one host's scan result in a transaction: upsert the asset, mark
     * open services, and (only for a complete scan) close services on ports
     * that were scanned but are no longer open.
     *
     * @param list<string> $hostnames Hostnames that resolved to this IP in this job.
     * @param list<int>    $scannedPorts
     * @param list<array{port:int,service:string,product:string,version:string,extra:string,cpe:string}> $open
     */
    public function recordHost(int $clientId, ?int $siteId, string $ip, array $hostnames, array $scannedPorts, array $open, bool $complete, int $jobId): void
    {
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare('SELECT id, hostnames FROM assets WHERE client_id = :c AND ip = :ip FOR UPDATE');
            $stmt->execute(['c' => $clientId, 'ip' => $ip]);
            $asset = $stmt->fetch();
            if ($asset === false) {
                $this->db->prepare(
                    'INSERT INTO assets (client_id, site_id, ip, hostnames, first_seen, last_seen, last_scanned) VALUES (:c, :s, :ip, :h, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())'
                )->execute(['c' => $clientId, 's' => $siteId, 'ip' => $ip, 'h' => mb_substr(implode(',', $hostnames), 0, 1000)]);
                $assetId = (int) $this->db->lastInsertId();
            } else {
                $assetId = (int) $asset['id'];
                $names = array_values(array_unique(array_filter(array_merge(explode(',', (string) $asset['hostnames']), $hostnames))));
                $this->db->prepare('UPDATE assets SET hostnames = :h, last_seen = UTC_TIMESTAMP(), last_scanned = UTC_TIMESTAMP() WHERE id = :id')
                    ->execute(['h' => mb_substr(implode(',', $names), 0, 1000), 'id' => $assetId]);
            }
            $upsert = $this->db->prepare(
                "INSERT INTO services (asset_id, port, protocol, is_open, service_name, product, version, extra_info, cpe, first_seen, last_seen, last_job_id)
                 VALUES (:a, :p, 'tcp', 1, :s, :pr, :v, :x, :cpe, UTC_TIMESTAMP(), UTC_TIMESTAMP(), :j)
                 ON DUPLICATE KEY UPDATE first_seen = IF(is_open = 0, UTC_TIMESTAMP(), first_seen), is_open = 1, closed_at = NULL,
                    service_name = VALUES(service_name), product = VALUES(product), version = VALUES(version), extra_info = VALUES(extra_info),
                    cpe = VALUES(cpe), last_seen = UTC_TIMESTAMP(), last_job_id = VALUES(last_job_id)"
            );
            $openPorts = [];
            foreach ($open as $svc) {
                $openPorts[] = $svc['port'];
                $upsert->execute(['a' => $assetId, 'p' => $svc['port'], 's' => $svc['service'], 'pr' => $svc['product'], 'v' => $svc['version'],
                                  'x' => $svc['extra'], 'cpe' => $svc['cpe'], 'j' => $jobId]);
            }
            if ($complete) {
                $close = $this->db->prepare("UPDATE services SET is_open = 0, closed_at = UTC_TIMESTAMP(), last_job_id = :j
                                             WHERE asset_id = :a AND protocol = 'tcp' AND port = :p AND is_open = 1");
                foreach (array_diff($scannedPorts, $openPorts) as $port) {
                    $close->execute(['j' => $jobId, 'a' => $assetId, 'p' => $port]);
                }
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Open services of a client, with their asset.
     *
     * @return list<array<string,mixed>>
     */
    public function openServices(int $clientId): array
    {
        $stmt = $this->db->prepare(
            'SELECT s.*, a.ip, a.hostnames, a.last_scanned FROM services s JOIN assets a ON a.id = s.asset_id
             WHERE a.client_id = :c AND s.is_open = 1 ORDER BY INET6_ATON(a.ip), s.port'
        );
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Payload and summary JSON decoded.
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function decode(array $row): array
    {
        $row['payload'] = json_decode((string) $row['payload'], true) ?: [];
        $row['summary'] = json_decode((string) ($row['summary'] ?? ''), true) ?: [];
        return $row;
    }
}
