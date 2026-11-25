<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

use PDO;

/**
 * Database access for vulnerability data and service-to-CVE matches.
 *
 * Security assumptions: values come from FeedParser (validated). All queries use bound parameters.
 */
final class VulnRepository
{
    public const QUERY_TTL_DAYS = 7;

    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /** Make sure a CPE query is known (pending until fetched), and note that an open service still needs it. */
    public function ensureQuery(string $query): void
    {
        $this->db->prepare("INSERT INTO cpe_queries (query, status, created_at, last_needed) VALUES (:q, 'pending', UTC_TIMESTAMP(), UTC_TIMESTAMP())
                            ON DUPLICATE KEY UPDATE last_needed = UTC_TIMESTAMP()")->execute(['q' => $query]);
    }

    /**
     * Status of a CPE query, or null.
     *
     * @return array<string,mixed>|null
     */
    public function query(string $query): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM cpe_queries WHERE query = :q');
        $stmt->execute(['q' => $query]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Queries that need fetching: pending, failed, or older than the TTL. Only
     * queries an open service needed in the last 30 days count, and a query
     * that failed 5 times in a row (e.g. NVD rejects it) is not retried until a
     * successful fetch resets it. Pending ones come first.
     *
     * @return list<string>
     */
    public function dueQueries(int $limit): array
    {
        $stmt = $this->db->prepare(
            "SELECT query FROM cpe_queries
             WHERE last_needed > UTC_TIMESTAMP() - INTERVAL 30 DAY
               AND (status = 'pending' OR (status = 'error' AND fail_count < 5) OR (status = 'ok' AND fetched_at < UTC_TIMESTAMP() - INTERVAL :ttl DAY)
                    OR (status = 'ok' AND platforms_checked = 0))
             ORDER BY status = 'pending' DESC, platforms_checked, fetched_at LIMIT :lim"
        );
        $stmt->bindValue('ttl', self::QUERY_TTL_DAYS, PDO::PARAM_INT);
        $stmt->bindValue('lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    /**
     * Store a fetched query result (replaces previous CVE links) in one transaction.
     *
     * @param list<array<string,mixed>> $cves Parsed CVEs.
     * @param string $note Shown with the query, e.g. when NVD had more results than were read.
     */
    public function storeQueryResult(string $query, array $cves, string $note = ''): void
    {
        $this->db->beginTransaction();
        try {
            $upsert = $this->db->prepare(
                'INSERT INTO cves (cve_id, summary, cvss_score, cvss_severity, cvss_version, published, last_modified, fetched_at)
                 VALUES (:id, :s, :score, :sev, :ver, :pub, :mod, UTC_TIMESTAMP())
                 ON DUPLICATE KEY UPDATE summary = VALUES(summary), cvss_score = VALUES(cvss_score), cvss_severity = VALUES(cvss_severity),
                    cvss_version = VALUES(cvss_version), published = VALUES(published), last_modified = VALUES(last_modified), fetched_at = UTC_TIMESTAMP()'
            );
            $this->db->prepare('DELETE FROM cpe_query_cves WHERE query = :q')->execute(['q' => $query]);
            $link = $this->db->prepare('INSERT IGNORE INTO cpe_query_cves (query, cve_id, platforms) VALUES (:q, :id, :p)');
            foreach ($cves as $c) {
                $upsert->execute(['id' => $c['cve_id'], 's' => $c['summary'], 'score' => $c['cvss_score'], 'sev' => $c['cvss_severity'],
                                  'ver' => $c['cvss_version'], 'pub' => $c['published'], 'mod' => $c['last_modified']]);
                $link->execute(['q' => $query, 'id' => $c['cve_id'], 'p' => mb_substr(implode(',', (array) ($c['platforms'] ?? [])), 0, 200)]);
            }
            $this->db->prepare("UPDATE cpe_queries SET status = 'ok', result_count = :n, error = :note, fail_count = 0, fetched_at = UTC_TIMESTAMP(), platforms_checked = 1 WHERE query = :q")
                ->execute(['n' => count($cves), 'note' => mb_substr($note, 0, 300), 'q' => $query]);
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /** Record a failed fetch. Previously stored results stay usable. */
    public function markQueryError(string $query, string $error): void
    {
        $this->db->prepare("UPDATE cpe_queries SET status = IF(fetched_at IS NULL, 'error', status), error = :e, fail_count = fail_count + 1 WHERE query = :q")
            ->execute(['e' => mb_substr($error, 0, 300), 'q' => $query]);
    }

    /**
     * CVE IDs linked to a query.
     *
     * @return list<string>
     */
    public function cvesForQuery(string $query): array
    {
        $stmt = $this->db->prepare('SELECT cve_id FROM cpe_query_cves WHERE query = :q');
        $stmt->execute(['q' => $query]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    /**
     * The platform limits of a query's CVEs (1.49): cve_id => list of OS families it is only vulnerable on.
     * CVEs vulnerable on any platform are left out.
     *
     * @return array<string,list<string>>
     */
    public function platformsForQuery(string $query): array
    {
        $stmt = $this->db->prepare("SELECT cve_id, platforms FROM cpe_query_cves WHERE query = :q AND platforms <> ''");
        $stmt->execute(['q' => $query]);
        $out = [];
        foreach ($stmt->fetchAll() as $r) {
            $out[(string) $r['cve_id']] = array_values(array_filter(explode(',', (string) $r['platforms'])));
        }
        return $out;
    }

    /**
     * Which of these CVEs are in the KEV catalog.
     *
     * @param list<string> $cveIds
     * @return list<string>
     */
    public function kevSubset(array $cveIds): array
    {
        if ($cveIds === []) {
            return [];
        }
        $out = [];
        foreach (array_chunk($cveIds, 500) as $chunk) {
            $stmt = $this->db->prepare('SELECT cve_id FROM kev_catalog WHERE cve_id IN (' . implode(',', array_fill(0, count($chunk), '?')) . ')');
            $stmt->execute($chunk);
            $out = array_merge($out, $stmt->fetchAll(PDO::FETCH_COLUMN));
        }
        return $out;
    }

    /**
     * Replace a service's matches with a new set (in one transaction).
     *
     * @param array<string,string> $matches cve_id => 'confirmed'|'possible'
     */
    public function setServiceMatches(int $serviceId, string $cpe, array $matches): void
    {
        $this->db->beginTransaction();
        try {
            if ($matches === []) {
                $this->db->prepare('DELETE FROM service_vulns WHERE service_id = :s')->execute(['s' => $serviceId]);
            } else {
                $ids = array_keys($matches);
                $this->db->prepare('DELETE FROM service_vulns WHERE service_id = ? AND cve_id NOT IN (' . implode(',', array_fill(0, count($ids), '?')) . ')')
                    ->execute(array_merge([$serviceId], $ids));
                $upsert = $this->db->prepare(
                    'INSERT INTO service_vulns (service_id, cve_id, confidence, cpe, first_seen, last_seen) VALUES (:s, :c, :conf, :cpe, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                     ON DUPLICATE KEY UPDATE confidence = VALUES(confidence), cpe = VALUES(cpe), last_seen = UTC_TIMESTAMP()'
                );
                foreach ($matches as $cve => $conf) {
                    $upsert->execute(['s' => $serviceId, 'c' => $cve, 'conf' => $conf, 'cpe' => $cpe]);
                }
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Remove a service's matches unless they came from one of these queries
     * (i.e. the product or version changed and the new answer isn't there yet).
     *
     * @param list<string> $queries
     */
    public function clearServiceMatchesUnless(int $serviceId, array $queries): void
    {
        $this->db->prepare('DELETE FROM service_vulns WHERE service_id = ? AND cpe NOT IN (' . implode(',', array_fill(0, count($queries), '?')) . ')')
            ->execute(array_merge([$serviceId], $queries));
    }

    /** Unix time until which NVD asked us not to send requests (0 if none). */
    public function nvdBlockedUntil(): int
    {
        $v = $this->db->query("SELECT UNIX_TIMESTAMP(blocked_until) FROM feed_status WHERE name = 'nvd'")->fetchColumn();
        return $v === false || $v === null ? 0 : (int) $v;
    }

    /** Record an NVD back-off deadline. */
    public function setNvdBlockedUntil(int $unixTime): void
    {
        $this->db->prepare("INSERT INTO feed_status (name, blocked_until) VALUES ('nvd', FROM_UNIXTIME(:t)) ON DUPLICATE KEY UPDATE blocked_until = FROM_UNIXTIME(:t2)")
            ->execute(['t' => $unixTime, 't2' => $unixTime]);
    }

    /** When the last NVD request was sent by any process (microtime), or 0. */
    public function nvdLastRequest(): float
    {
        $v = $this->db->query("SELECT last_request FROM feed_status WHERE name = 'nvd'")->fetchColumn();
        return $v === false || $v === null ? 0.0 : (float) $v;
    }

    /** Store the time of an NVD request. */
    public function setNvdLastRequest(float $time): void
    {
        $this->db->prepare("INSERT INTO feed_status (name, last_request) VALUES ('nvd', :t) ON DUPLICATE KEY UPDATE last_request = :t2")
            ->execute(['t' => $time, 't2' => $time]);
    }

    /** Run $fn while holding the NVD pacing lock (per install), so concurrent processes take turns. */
    public function withNvdPaceLock(callable $fn): void
    {
        $lock = $this->db->quote('msp_sentinel_nvd_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
        $this->db->query("SELECT GET_LOCK({$lock}, 120)");
        try {
            $fn();
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /**
     * Why a client's services may have fewer matches than expected: products
     * waiting for data, failed lookups, and open services with no product information.
     *
     * @return array{waiting:int, failed:int, no_product:int}
     */
    public function coverage(int $clientId): array
    {
        $stmt = $this->db->prepare("SELECT s.cpe FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id = :c AND s.is_open = 1");
        $stmt->execute(['c' => $clientId]);
        $out = ['waiting' => 0, 'failed' => 0, 'no_product' => 0];
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $raw) {
            $cpe = Cpe::parse((string) $raw);
            if ($cpe === null) {
                $out['no_product']++;
                continue;
            }
            $q = $this->query(Cpe::matchString($cpe));
            if ($q === null || ($q['fetched_at'] === null && $q['status'] === 'pending')) {
                $out['waiting']++;
            } elseif ($q['fetched_at'] === null) {
                $out['failed']++;
            }
        }
        return $out;
    }

    /**
     * Open services ("ip:port") of a client whose vulnerability data is not
     * available yet (pending or failed lookups). Their vulnerability findings
     * must not be auto-resolved: absence of data is not evidence of a fix.
     *
     * @return array<string,true>
     */
    public function servicesAwaitingData(int $clientId): array
    {
        $stmt = $this->db->prepare("SELECT a.ip, s.port, s.cpe FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id = :c AND s.is_open = 1");
        $stmt->execute(['c' => $clientId]);
        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            $cpe = Cpe::parse((string) $row['cpe']);
            if ($cpe === null) {
                continue;
            }
            $q = $this->query(Cpe::matchString($cpe));
            if ($q === null || $q['fetched_at'] === null) {
                $out[$row['ip'] . ':' . $row['port']] = true;
            }
        }
        return $out;
    }

    /**
     * Replace the KEV catalog (in one transaction).
     *
     * @param list<array<string,mixed>> $rows Parsed KEV rows.
     */
    public function replaceKev(array $rows): void
    {
        $this->db->beginTransaction();
        try {
            $this->db->exec('DELETE FROM kev_catalog');
            $ins = $this->db->prepare('INSERT INTO kev_catalog (cve_id, vendor, product, name, date_added, due_date, ransomware, required_action)
                                       VALUES (:cve_id, :vendor, :product, :name, :date_added, :due_date, :ransomware, :required_action)');
            foreach ($rows as $r) {
                $ins->execute($r);
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Store EPSS scores.
     *
     * @param list<array<string,mixed>> $rows
     */
    public function storeEpss(array $rows): void
    {
        $stmt = $this->db->prepare('INSERT INTO epss_scores (cve_id, score, percentile, score_date) VALUES (:cve_id, :score, :percentile, :score_date)
                                    ON DUPLICATE KEY UPDATE score = VALUES(score), percentile = VALUES(percentile), score_date = VALUES(score_date)');
        foreach ($rows as $r) {
            $stmt->execute($r);
        }
    }

    /**
     * CVEs matched to open services (for the EPSS refresh).
     *
     * @return list<string>
     */
    public function matchedCveIds(): array
    {
        return $this->db->query('SELECT DISTINCT sv.cve_id FROM service_vulns sv JOIN services s ON s.id = sv.service_id AND s.is_open = 1')->fetchAll(PDO::FETCH_COLUMN);
    }

    /** Record the outcome of a feed refresh. */
    public function feedStatus(string $name, bool $ok, string $message, int $count = 0): void
    {
        $this->db->prepare('INSERT INTO feed_status (name, last_attempt, last_success, message, item_count) VALUES (:n, UTC_TIMESTAMP(), IF(:ok = 1, UTC_TIMESTAMP(), NULL), :m, :c)
                            ON DUPLICATE KEY UPDATE last_attempt = UTC_TIMESTAMP(), last_success = IF(:ok2 = 1, UTC_TIMESTAMP(), last_success), message = VALUES(message),
                            item_count = IF(:ok3 = 1, VALUES(item_count), item_count)')
            ->execute(['n' => $name, 'ok' => $ok ? 1 : 0, 'ok2' => $ok ? 1 : 0, 'ok3' => $ok ? 1 : 0, 'm' => mb_substr($message, 0, 300), 'c' => $count]);
    }

    /**
     * All feed status rows, keyed by name.
     *
     * @return array<string,array<string,mixed>>
     */
    public function feedStatuses(): array
    {
        $out = [];
        foreach ($this->db->query('SELECT * FROM feed_status')->fetchAll() as $row) {
            $out[(string) $row['name']] = $row;
        }
        return $out;
    }

    /**
     * Vulnerabilities on a client's open services, with KEV, CVSS and EPSS data,
     * most important first: KEV, then CVSS score, then EPSS.
     *
     * @return list<array<string,mixed>>
     */
    public function forClient(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT sv.cve_id, sv.confidence, sv.cpe, sv.first_seen, s.id AS service_id, s.port, s.product, s.version, a.ip,
                    c.summary, c.cvss_score, c.cvss_severity, c.published,
                    k.cve_id IS NOT NULL AS in_kev, k.date_added AS kev_added, k.ransomware, e.score AS epss, e.percentile AS epss_percentile
             FROM service_vulns sv
             JOIN services s ON s.id = sv.service_id AND s.is_open = 1
             JOIN assets a ON a.id = s.asset_id
             LEFT JOIN cves c ON c.cve_id = sv.cve_id
             LEFT JOIN kev_catalog k ON k.cve_id = sv.cve_id
             LEFT JOIN epss_scores e ON e.cve_id = sv.cve_id
             WHERE a.client_id = :c
             ORDER BY in_kev DESC, sv.confidence = 'confirmed' DESC, c.cvss_score IS NULL, c.cvss_score DESC, e.score DESC, sv.cve_id"
        );
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Distinct known-exploited CVEs on open services of non-archived clients:
     * confirmed, and possible (version unknown, or a distribution build that may be patched).
     *
     * @return array{confirmed_kev:int, possible_kev:int}
     */
    public function kevCounts(?array $clientIds = null): array
    {
        $row = $this->db->query(
            "SELECT COUNT(DISTINCT IF(sv.confidence = 'confirmed', sv.cve_id, NULL)) AS confirmed_kev,
                    COUNT(DISTINCT IF(sv.confidence <> 'confirmed', sv.cve_id, NULL)) AS possible_kev
             FROM service_vulns sv JOIN kev_catalog k ON k.cve_id = sv.cve_id
             JOIN services s ON s.id = sv.service_id AND s.is_open = 1 JOIN assets a ON a.id = s.asset_id
             JOIN clients c ON c.id = a.client_id AND c.is_archived = 0 WHERE 1 = 1" . \Sentinel\Auth\ClientAccess::sql('a.client_id', $clientIds) // 1.41
        )->fetch();
        return ['confirmed_kev' => (int) ($row['confirmed_kev'] ?? 0), 'possible_kev' => (int) ($row['possible_kev'] ?? 0)];
    }
}
