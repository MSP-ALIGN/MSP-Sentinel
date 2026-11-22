<?php

declare(strict_types=1);

namespace Sentinel\Dashboard;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use Sentinel\Core\Settings;
use Sentinel\Scanning\PortProfile;
use Sentinel\Scanning\ScanWindow;

/**
 * Numbers for the main dashboard and each client's overview.
 *
 * Risk score (0-100, higher is worse), explained in Help:
 *   20 for each open known-exploited Fail, 10 for each other open Fail,
 *   2 for each open Warning; capped at 100. Accepted risks and false
 *   positives don't count. Level: At risk (any open Fail), Needs attention
 *   (open Warnings only) or Good (nothing open), the same as in reports.
 *
 * Ranking puts the level first (At risk before Needs attention before Good),
 * then the score, so many Warnings never outrank a Fail.
 *
 * Certificates and TLS counts only include services that are still open.
 *
 * Security assumptions: read-only queries; every value placed in SQL is an
 * integer cast or a constant. Archived clients are left out. Every value returned is scan
 * data or admin input (untrusted) and is escaped by the views. Callers
 * pass a client ID only after the route has authorised the user; every
 * signed-in role may see every client today.
 */
final class DashboardData
{
    /** Uses the database and settings (for the kill switch and worker heartbeat). */
    public function __construct(private readonly PDO $db, private readonly Settings $settings)
    {
    }

    /** Score from counts (see class notes). */
    public static function score(int $kevFail, int $fail, int $warn): int
    {
        return min(100, 20 * $kevFail + 10 * max(0, $fail - $kevFail) + 2 * $warn);
    }

    /** Level from counts: risk, attention or good. */
    public static function level(int $fail, int $warn): string
    {
        return $fail > 0 ? 'risk' : ($warn > 0 ? 'attention' : 'good');
    }

    /**
     * Every active client with its counts, score and level, worst first.
     *
     * @return list<array{id:int, name:string, fail:int, warn:int, kev:int, score:int, level:string, paused:bool, last_scan:?string}>
     */
    public function clients(?int $onlyId = null): array
    {
        $sql = "SELECT c.id, c.name, c.scanning_paused,
                       COALESCE(SUM(f.status = 'open' AND f.severity = 'fail'), 0) AS fail,
                       COALESCE(SUM(f.status = 'open' AND f.severity = 'warn'), 0) AS warn,
                       COALESCE(SUM(f.status = 'open' AND f.severity = 'fail' AND k.cve_id IS NOT NULL), 0) AS kev,
                       (SELECT MAX(j.finished_at) FROM scan_jobs j WHERE j.client_id = c.id AND j.finished_at IS NOT NULL AND j.job_type <> 'verify') AS last_scan
                FROM clients c
                LEFT JOIN findings f ON f.client_id = c.id AND f.status = 'open'
                LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
                WHERE c.is_archived = 0" . ($onlyId !== null ? ' AND c.id = ' . (int) $onlyId : '') . '
                GROUP BY c.id, c.name, c.scanning_paused';
        $rows = [];
        foreach ($this->db->query($sql)->fetchAll() as $r) {
            $fail = (int) $r['fail'];
            $warn = (int) $r['warn'];
            $kev = (int) $r['kev'];
            $rows[] = ['id' => (int) $r['id'], 'name' => (string) $r['name'], 'fail' => $fail, 'warn' => $warn, 'kev' => $kev,
                       'score' => self::score($kev, $fail, $warn), 'level' => self::level($fail, $warn),
                       'paused' => (int) $r['scanning_paused'] === 1, 'last_scan' => $r['last_scan']];
        }
        $rank = ['risk' => 2, 'attention' => 1, 'good' => 0];
        usort($rows, static fn (array $a, array $b): int => [$rank[$b['level']], $b['score'], $b['fail'], $b['warn'], $a['name']] <=> [$rank[$a['level']], $a['score'], $a['fail'], $a['warn'], $b['name']]);
        return $rows;
    }

    /**
     * Open Fail/Warning per day for the last $days days (recorded daily counts), ending with today's live counts.
     *
     * @return list<array{day:string, fail:int, warn:int}>
     */
    public function trend(int $days = 90, ?int $clientId = null, int $failNow = 0, int $warnNow = 0): array
    {
        $stmt = $this->db->prepare(
            'SELECT s.day, SUM(s.fail_open) AS fail, SUM(s.warn_open) AS warn FROM finding_stats s JOIN clients c ON c.id = s.client_id AND c.is_archived = 0
             WHERE s.day >= UTC_DATE() - INTERVAL ' . max(1, min(366, $days)) . ' DAY AND s.day < UTC_DATE()'
            . ($clientId !== null ? ' AND s.client_id = ' . (int) $clientId : '') . ' GROUP BY s.day ORDER BY s.day'
        );
        $stmt->execute();
        $out = [];
        foreach ($stmt->fetchAll() as $r) {
            $out[] = ['day' => (string) $r['day'], 'fail' => (int) $r['fail'], 'warn' => (int) $r['warn']];
        }
        $out[] = ['day' => gmdate('Y-m-d'), 'fail' => $failNow, 'warn' => $warnNow];
        return $out;
    }

    /**
     * Recent events: findings opened, reopened, resolved or triaged, and finished scans.
     *
     * @return list<array{at:string, kind:string, severity:?string, title:string, client:string, client_id:int, link:string}>
     */
    public function activity(int $limit = 12, ?int $clientId = null): array
    {
        $limit = max(1, min(50, $limit));
        $clientSql = $clientId !== null ? ' AND c.id = ' . (int) $clientId : '';
        // For one client, look only at that client's findings (uses the client index) instead of walking all events.
        $eventScope = $clientId !== null ? ' AND e.finding_id IN (SELECT id FROM findings WHERE client_id = ' . (int) $clientId . ')' : '';
        $events = $this->db->query(
            "SELECT e.created_at AS at, e.event AS kind, f.severity, f.title, c.name AS client, c.id AS client_id, f.id AS ref
             FROM finding_events e JOIN findings f ON f.id = e.finding_id JOIN clients c ON c.id = f.client_id AND c.is_archived = 0
             WHERE e.event IN ('opened','reopened','resolved','triaged_accepted','triaged_false_positive','triaged_open'){$eventScope}{$clientSql}
             ORDER BY e.id DESC LIMIT {$limit}"
        )->fetchAll();
        $scans = $this->db->query(
            "SELECT j.finished_at AS at, CONCAT('scan_', j.status) AS kind, NULL AS severity, j.job_type AS title, c.name AS client, c.id AS client_id, j.id AS ref
             FROM scan_jobs j JOIN clients c ON c.id = j.client_id AND c.is_archived = 0
             WHERE j.finished_at IS NOT NULL{$clientSql} ORDER BY j.id DESC LIMIT {$limit}"
        )->fetchAll();
        $all = array_merge($events, $scans);
        usort($all, static fn (array $a, array $b): int => strcmp((string) $b['at'], (string) $a['at']));
        return array_map(static fn (array $r): array => [
            'at' => (string) $r['at'], 'kind' => (string) $r['kind'], 'severity' => $r['severity'], 'title' => (string) $r['title'],
            'client' => (string) $r['client'], 'client_id' => (int) $r['client_id'],
            'link' => str_starts_with((string) $r['kind'], 'scan_') ? '/clients/' . (int) $r['client_id'] . '/scans' : '/findings/' . (int) $r['ref'],
        ], array_slice($all, 0, $limit));
    }

    /**
     * Attack surface: hosts, open services and how many fall in each category.
     *
     * @return array{hosts:int, services:int, tls:int, web:int, categories:list<array{label:string, count:int, risk:bool}>}
     */
    public function surface(?int $clientId = null): array
    {
        $clientSql = $clientId !== null ? ' AND a.client_id = ' . (int) $clientId : '';
        $join = ' JOIN clients c ON c.id = a.client_id AND c.is_archived = 0';
        $hosts = (int) $this->db->query("SELECT COUNT(*) FROM assets a{$join} WHERE 1=1{$clientSql}")->fetchColumn();
        $ports = $this->db->query("SELECT s.port FROM services s JOIN assets a ON a.id = s.asset_id{$join} WHERE s.is_open = 1{$clientSql}")->fetchAll(PDO::FETCH_COLUMN);
        $tls = (int) $this->db->query("SELECT COUNT(*) FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id{$join}
            JOIN services s ON s.asset_id = t.asset_id AND s.port = t.port AND s.protocol = 'tcp' AND s.is_open = 1 WHERE 1=1{$clientSql}")->fetchColumn();
        $web = (int) $this->db->query("SELECT COUNT(*) FROM web_pages w JOIN assets a ON a.id = w.asset_id{$join} WHERE 1=1{$clientSql}")->fetchColumn();
        $groups = [
            'remote' => [__('Remote access'), [22, 23, 3389, 5900, 5985, 5986], true],
            'data' => [__('Databases'), [1433, 1521, 3306, 5432, 6379, 9200, 27017], true],
            'windows' => [__('Windows sharing'), [135, 139, 445], true],
            'web' => [__('Web'), [80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9443, 10000, 10443, 4433, 4443], false],
            'mail' => [__('Mail'), [25, 110, 143, 465, 587, 993, 995], false],
            'other' => [__('Other'), [], false],
        ];
        $counts = array_fill_keys(array_keys($groups), 0);
        foreach ($ports as $p) {
            $p = (int) $p;
            $hit = 'other';
            foreach ($groups as $k => [, $list]) {
                if (in_array($p, $list, true)) {
                    $hit = $k;
                    break;
                }
            }
            if ($hit === 'other' && isset(PortProfile::HIGH_RISK[$p])) {
                $hit = 'remote';
            }
            $counts[$hit]++;
        }
        $cats = [];
        foreach ($groups as $k => [$label, , $risk]) {
            $cats[] = ['label' => $label, 'count' => $counts[$k], 'risk' => $risk];
        }
        return ['hosts' => $hosts, 'services' => count($ports), 'tls' => $tls, 'web' => $web, 'categories' => $cats];
    }

    /**
     * The worst open findings (Fail first, known-exploited first).
     *
     * @return list<array<string,mixed>>
     */
    public function topExposures(int $limit = 6, ?int $clientId = null): array
    {
        return $this->db->query(
            "SELECT f.id, f.severity, f.title, f.target, c.name AS client, c.id AS client_id, (k.cve_id IS NOT NULL) AS kev
             FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
             WHERE f.status = 'open'" . ($clientId !== null ? ' AND c.id = ' . (int) $clientId : '') . "
             ORDER BY f.severity = 'fail' DESC, (k.cve_id IS NOT NULL) DESC, f.finding_type = 'port' DESC, f.first_seen DESC
             LIMIT " . max(1, min(20, $limit))
        )->fetchAll();
    }

    /**
     * Certificates expired or expiring within $days days.
     *
     * @return list<array{endpoint:string, name:string, client:string, client_id:int, days:int}>
     */
    public function certificates(int $days = 30, ?int $clientId = null): array
    {
        $rows = $this->db->query(
            "SELECT a.ip, t.port, t.sni, t.subject_cn, t.not_after, c.name AS client, c.id AS client_id
             FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id JOIN clients c ON c.id = a.client_id AND c.is_archived = 0
             JOIN services s ON s.asset_id = t.asset_id AND s.port = t.port AND s.protocol = 'tcp' AND s.is_open = 1
             WHERE t.not_after IS NOT NULL AND t.not_after < UTC_TIMESTAMP() + INTERVAL " . max(1, min(365, $days)) . ' DAY'
            . ($clientId !== null ? ' AND c.id = ' . (int) $clientId : '') . ' ORDER BY t.not_after LIMIT 12'
        )->fetchAll();
        return array_map(static fn (array $r): array => [
            'endpoint' => $r['ip'] . ':' . $r['port'], 'name' => (string) ($r['sni'] ?: $r['subject_cn'] ?: '?'), 'client' => (string) $r['client'],
            'client_id' => (int) $r['client_id'], 'days' => (int) floor((strtotime($r['not_after'] . ' UTC') - time()) / 86400),
        ], $rows);
    }

    /** How many certificates on open services expire within $days days (or already have): the full count, not limited. */
    public function certificateCount(int $days): int
    {
        return (int) $this->db->query(
            "SELECT COUNT(*) FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id JOIN clients c ON c.id = a.client_id AND c.is_archived = 0
             JOIN services s ON s.asset_id = t.asset_id AND s.port = t.port AND s.protocol = 'tcp' AND s.is_open = 1
             WHERE t.not_after IS NOT NULL AND t.not_after < UTC_TIMESTAMP() + INTERVAL " . max(0, min(365, $days)) . ' DAY'
        )->fetchColumn();
    }

    /**
     * Operations status: kill switch, worker heartbeat, feeds, scans running or queued, next window opening.
     *
     * @return array<string,mixed>
     */
    public function ops(): array
    {
        $tick = $this->settings->fresh('worker_last_tick');
        $feeds = $this->db->query('SELECT name, last_success FROM feed_status')->fetchAll(PDO::FETCH_KEY_PAIR);
        $running = (int) $this->db->query("SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'")->fetchColumn();
        $queued = (int) $this->db->query("SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'")->fetchColumn();
        $next = null;
        $openNow = 0;
        $paused = $this->settings->fresh('scanning_paused') === '1';
        // Demo clients are never scanned, so they have no scan window here.
        foreach ($this->db->query('SELECT id, name, timezone, scan_window_start, scan_window_end, scanning_paused FROM clients WHERE is_archived = 0 AND is_demo = 0')->fetchAll() as $c) {
            $w = ScanWindow::nextChange($c);
            if ($w === null || (int) $c['scanning_paused'] === 1) {
                continue;
            }
            if ($w['open']) {
                $openNow++;
            } elseif ($next === null || $w['at'] < $next['at']) {
                $next = ['at' => $w['at'], 'client' => (string) $c['name']];
            }
        }
        $age = static fn (?string $t): ?int => $t === null || $t === '' ? null : time() - (int) strtotime($t . ' UTC');
        return [
            'paused' => $paused,
            'worker_age' => $age($tick),
            'feed_age' => ['kev' => $age($feeds['kev'] ?? null), 'nvd' => $age($feeds['nvd'] ?? null), 'epss' => $age($feeds['epss'] ?? null)],
            'running' => $running,
            'queued' => $queued,
            'windows_open' => $paused ? 0 : $openNow,
            'next_window' => $paused || $next === null ? null : ['client' => $next['client'], 'in' => max(0, $next['at']->getTimestamp() - time())],
        ];
    }

    /**
     * One client's window state for its overview.
     *
     * @param array<string,mixed> $client
     * @return array{open:bool, in:int}|null
     */
    public static function window(array $client): ?array
    {
        $w = ScanWindow::nextChange($client);
        return $w === null ? null : ['open' => $w['open'], 'in' => max(0, $w['at']->getTimestamp() - (new DateTimeImmutable('now', new DateTimeZone('UTC')))->getTimestamp())];
    }
}
