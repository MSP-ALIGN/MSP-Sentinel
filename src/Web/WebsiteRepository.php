<?php

declare(strict_types=1);

namespace Sentinel\Web;

use PDO;

/**
 * Stores website check results, detected components and email record checks,
 * and reads them back for findings and the client page.
 *
 * Security assumptions: inputs are results built by WebsiteChecker and
 * EmailChecker from untrusted responses (codes and short cleaned strings);
 * every query uses bound parameters. Only rows for open services are read.
 */
final class WebsiteRepository
{
    /** Uses the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Save the checks for a web page and its detected components (components no longer seen are removed).
     *
     * @param array<string,mixed> $checks From WebsiteChecker::analyse() plus 'exposed'.
     */
    public function saveChecks(int $assetId, int $port, array $checks): void
    {
        $stmt = $this->db->prepare('SELECT id FROM web_pages WHERE asset_id = :a AND port = :p');
        $stmt->execute(['a' => $assetId, 'p' => $port]);
        $pageId = $stmt->fetchColumn();
        if ($pageId === false) {
            return;
        }
        $pageId = (int) $pageId;
        $components = $checks['components'] ?? [];
        unset($checks['components']);
        $this->db->beginTransaction();
        try {
            $this->db->prepare('UPDATE web_pages SET checks = :c, checks_at = UTC_TIMESTAMP() WHERE id = :id')
                ->execute(['c' => json_encode($checks, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), 'id' => $pageId]);
            $names = [];
            $up = $this->db->prepare(
                'INSERT INTO web_components (web_page_id, kind, name, version, cpe, first_seen, last_seen) VALUES (:p, :k, :n, :v, :cpe, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                 ON DUPLICATE KEY UPDATE kind = VALUES(kind), version = VALUES(version), cpe = VALUES(cpe), last_seen = UTC_TIMESTAMP()'
            );
            foreach (array_slice($components, 0, 20) as $c) {
                $base = WebsiteChecker::CPES[$c['name']] ?? null;
                if ($base === null) {
                    continue;
                }
                $cpe = $c['version'] !== '' ? $base . ':' . $c['version'] : $base;
                $up->execute(['p' => $pageId, 'k' => $c['kind'], 'n' => $c['name'], 'v' => $c['version'], 'cpe' => $cpe]);
                $names[] = $c['name'];
            }
            if ($names === []) {
                $this->db->prepare('DELETE FROM web_components WHERE web_page_id = :p')->execute(['p' => $pageId]);
            } else {
                $this->db->prepare('DELETE FROM web_components WHERE web_page_id = ? AND name NOT IN (' . implode(',', array_fill(0, count($names), '?')) . ')')
                    ->execute(array_merge([$pageId], $names));
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * The stored checks of one web page (decoded), or [] if none.
     *
     * @return array<string,mixed>
     */
    public function previousChecks(int $assetId, int $port): array
    {
        $stmt = $this->db->prepare('SELECT checks FROM web_pages WHERE asset_id = :a AND port = :p');
        $stmt->execute(['a' => $assetId, 'p' => $port]);
        return json_decode((string) $stmt->fetchColumn(), true) ?: [];
    }

    /**
     * Website check results for a client's open web services.
     *
     * @return list<array<string,mixed>> Rows with ip, port, scheme, host_header, checks (decoded), components.
     */
    public function checksForClient(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT w.id, w.asset_id, w.port, w.scheme, w.host_header, w.checks, w.checks_at, a.ip FROM web_pages w JOIN assets a ON a.id = w.asset_id
             JOIN services s ON s.asset_id = w.asset_id AND s.port = w.port AND s.protocol = 'tcp' AND s.is_open = 1
             WHERE a.client_id = :c AND w.checks IS NOT NULL ORDER BY INET6_ATON(a.ip), w.port"
        );
        $stmt->execute(['c' => $clientId]);
        $rows = [];
        foreach ($stmt->fetchAll() as $r) {
            $r['checks'] = json_decode((string) $r['checks'], true) ?: [];
            $c = $this->db->prepare('SELECT name, version, kind FROM web_components WHERE web_page_id = :p ORDER BY kind, name');
            $c->execute(['p' => $r['id']]);
            $r['components'] = $c->fetchAll();
            $rows[] = $r;
        }
        return $rows;
    }

    /**
     * Vulnerability matches for a client's detected components (open services only).
     *
     * @return list<array<string,mixed>>
     */
    public function componentVulns(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT cv.cve_id, cv.confidence, wc.name, wc.version, w.port, a.ip, a.id AS asset_id,
                    c.summary, c.cvss_score, c.cvss_severity, (k.cve_id IS NOT NULL) AS in_kev
             FROM component_vulns cv JOIN web_components wc ON wc.id = cv.component_id JOIN web_pages w ON w.id = wc.web_page_id
             JOIN assets a ON a.id = w.asset_id
             JOIN services s ON s.asset_id = w.asset_id AND s.port = w.port AND s.protocol = 'tcp' AND s.is_open = 1
             LEFT JOIN cves c ON c.cve_id = cv.cve_id LEFT JOIN kev_catalog k ON k.cve_id = cv.cve_id
             WHERE a.client_id = :c ORDER BY in_kev DESC, c.cvss_score DESC, cv.cve_id"
        );
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Components (with a CPE) of one client or all clients, for vulnerability matching.
     *
     * @return list<array{id:int, cpe:string, version:string}>
     */
    public function componentsToMatch(?int $clientId): array
    {
        $sql = 'SELECT wc.id, wc.cpe, wc.version FROM web_components wc JOIN web_pages w ON w.id = wc.web_page_id JOIN assets a ON a.id = w.asset_id WHERE wc.cpe <> \'\''
            . ($clientId !== null ? ' AND a.client_id = ' . (int) $clientId : '');
        return array_map(static fn (array $r): array => ['id' => (int) $r['id'], 'cpe' => (string) $r['cpe'], 'version' => (string) $r['version']],
            $this->db->query($sql)->fetchAll());
    }

    /**
     * Replace a component's matches.
     *
     * @param array<string,string> $matches cve_id => confidence
     */
    public function setComponentMatches(int $componentId, string $cpe, array $matches): void
    {
        $this->db->beginTransaction();
        try {
            $this->db->prepare('DELETE FROM component_vulns WHERE component_id = :c')->execute(['c' => $componentId]);
            $ins = $this->db->prepare('INSERT INTO component_vulns (component_id, cve_id, confidence, cpe, first_seen, last_seen) VALUES (:c, :v, :conf, :cpe, UTC_TIMESTAMP(), UTC_TIMESTAMP())');
            foreach ($matches as $cve => $conf) {
                $ins->execute(['c' => $componentId, 'v' => $cve, 'conf' => $conf === 'confirmed' ? 'confirmed' : 'possible', 'cpe' => $cpe]);
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /** Remove a component's matches that were made for a different CPE (an earlier version). */
    public function clearComponentMatchesUnless(int $componentId, string $cpe): void
    {
        $this->db->prepare('DELETE FROM component_vulns WHERE component_id = :c AND cpe <> :cpe')->execute(['c' => $componentId, 'cpe' => $cpe]);
    }

    /**
     * When each of a client's domains was last checked successfully.
     *
     * @return array<string,string> domain => checked_at (UTC)
     */
    public function emailCheckedTimes(int $clientId): array
    {
        $stmt = $this->db->prepare('SELECT domain, checked_at FROM email_checks WHERE client_id = :c');
        $stmt->execute(['c' => $clientId]);
        return array_map('strval', $stmt->fetchAll(\PDO::FETCH_KEY_PAIR));
    }

    /**
     * Save email checks for a client's domains. Domains not in $inScope are removed; a domain whose DNS
     * failed this time keeps its last good result (and its old checked_at, so it is retried next job).
     *
     * @param list<array<string,mixed>> $results From EmailChecker::check().
     * @param list<string> $inScope Every domain currently in scope (checked now or not).
     */
    public function saveEmail(int $clientId, array $results, array $inScope): void
    {
        $domains = $inScope;
        $up = $this->db->prepare(
            'INSERT INTO email_checks (client_id, domain, has_mx, result, checked_at) VALUES (:c, :d, :mx, :r, UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE has_mx = VALUES(has_mx), result = VALUES(result), checked_at = UTC_TIMESTAMP()'
        );
        foreach ($results as $r) {
            if ($r['error'] !== '' || !in_array($r['domain'], $inScope, true)) {
                continue; // keep the last good result when DNS failed this time
            }
            $up->execute(['c' => $clientId, 'd' => $r['domain'], 'mx' => $r['has_mx'] ? 1 : 0, 'r' => json_encode($r, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)]);
        }
        if ($domains === []) {
            $this->db->prepare('DELETE FROM email_checks WHERE client_id = :c')->execute(['c' => $clientId]);
        } else {
            $this->db->prepare('DELETE FROM email_checks WHERE client_id = ? AND domain NOT IN (' . implode(',', array_fill(0, count($domains), '?')) . ')')
                ->execute(array_merge([$clientId], $domains));
        }
    }

    /**
     * Email checks of a client.
     *
     * @return list<array<string,mixed>> Decoded results with checked_at.
     */
    public function emailForClient(int $clientId): array
    {
        $stmt = $this->db->prepare('SELECT domain, has_mx, result, checked_at FROM email_checks WHERE client_id = :c ORDER BY domain');
        $stmt->execute(['c' => $clientId]);
        return array_map(static fn (array $r): array => (json_decode((string) $r['result'], true) ?: []) + ['checked_at' => $r['checked_at']], $stmt->fetchAll());
    }
}
