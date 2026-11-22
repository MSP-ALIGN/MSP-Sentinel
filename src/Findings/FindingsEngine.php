<?php

declare(strict_types=1);

namespace Sentinel\Findings;

use PDO;
use Sentinel\Scanning\EndpointRepository;
use Sentinel\Scanning\ExposureRules;
use Sentinel\Scanning\PortProfile;
use Sentinel\Vulns\VulnRepository;

/**
 * Builds each client's findings from what is currently known (open services,
 * TLS endpoints, web pages, vulnerability matches), graded with
 * ExposureRules. Only Fail and Warning items become findings.
 *
 * Lifecycle, per finding (identified by a stable key such as "vuln:203.0.113.5:22:CVE-..."):
 * - first seen                       -> open
 * - seen again                       -> last_seen moves; open, accepted and false positive stay as they are,
 *                                       except a false positive whose evidence changed (e.g. another version) reopens
 * - no longer seen                   -> resolved (with the date)
 * - seen again after being resolved  -> the same finding reopens, flagged "reappeared"; if it had been accepted
 *                                       or marked false positive and the evidence is unchanged, that decision is restored
 *
 * "No longer seen" only happens when a check really saw the problem gone:
 * services are only closed by a complete scan of that host, TLS and web rows
 * only change on successful checks, and vulnerability matches only change when
 * data exists. A host that simply wasn't scanned keeps its findings, and a
 * vulnerability finding isn't resolved while its service's new data is pending.
 * Evidence fingerprints use only stable facts (port and service name; page
 * category; CPE; certificate subject and expiry).
 *
 * Security assumptions: titles and details come from scan data (untrusted)
 * and are escaped by the views. Every state change is written to finding_events.
 */
final class FindingsEngine
{
    /** WARN-level ports that aren't in PortProfile::HIGH_RISK. */
    private const WARN_PORTS = [21 => 'FTP (unencrypted file transfer)'];

    /** Uses the stores of the earlier steps. */
    public function __construct(
        private readonly PDO $db,
        private readonly EndpointRepository $endpoints,
        private readonly VulnRepository $vulns,
    ) {
    }

    /**
     * Recompute one client's findings.
     *
     * Runs under a per-client lock (so two refreshes, e.g. the feeds job and a
     * scan job, never interleave), and reads the current issues INSIDE the
     * lock, so a decision is never made on a stale snapshot.
     *
     * @return array{opened:int, reopened:int, resolved:int, current:int, opened_ids:list<int>, reopened_ids:list<int>, resolved_ids:list<int>, escalated_ids:list<int>}
     */
    public function refreshClient(int $clientId): array
    {
        $lock = $this->db->quote('msp_sentinel_findings_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16) . '_' . $clientId);
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 60)")->fetchColumn() !== 1) {
            throw new \RuntimeException('Another findings refresh for this client is still running.');
        }
        try {
            return $this->refreshLocked($clientId);
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /**
     * The refresh itself (caller holds the client lock).
     *
     * @return array{opened:int, reopened:int, resolved:int, current:int}
     */
    private function refreshLocked(int $clientId): array
    {
        $current = $this->currentIssues($clientId);
        // Vulnerability findings of services still waiting for NVD data are left alone:
        // missing data is not evidence that a problem was fixed.
        $awaiting = $this->vulns->servicesAwaitingData($clientId);
        $stats = ['opened' => 0, 'reopened' => 0, 'resolved' => 0, 'current' => count($current), 'opened_ids' => [], 'reopened_ids' => [], 'resolved_ids' => [], 'escalated_ids' => []];
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare('SELECT * FROM findings WHERE client_id = :c FOR UPDATE');
            $stmt->execute(['c' => $clientId]);
            $existing = [];
            foreach ($stmt->fetchAll() as $row) {
                $existing[(string) $row['finding_key']] = $row;
            }
            $update = $this->db->prepare(
                'UPDATE findings SET severity = :sev, title = :t, detail = :d, target = :tg, evidence = :ev, asset_id = :a, cve_id = :cve,
                        status = :st, last_seen = UTC_TIMESTAMP(), resolved_at = IF(:resolved = 1, resolved_at, NULL),
                        resolved_from = IF(:resolved2 = 1, resolved_from, NULL),
                        reappeared = IF(:reap = 1, 1, reappeared), reopened_count = reopened_count + :inc
                 WHERE id = :id'
            );
            foreach ($current as $key => $issue) {
                $row = $existing[$key] ?? null;
                if ($row === null) {
                    $stats['opened_ids'][] = $this->insert($clientId, $key, $issue);
                    $stats['opened']++;
                    continue;
                }
                $id = (int) $row['id'];
                $status = (string) $row['status'];
                $newStatus = $status;
                $sameEvidence = $row['evidence'] === $issue['evidence'];
                if ($status === 'resolved') {
                    // Seen again. If a decision was made before it resolved and the evidence is the same,
                    // that decision still applies; otherwise it is open again.
                    $previous = (string) ($row['resolved_from'] ?? 'open');
                    $newStatus = in_array($previous, ['accepted', 'false_positive'], true) && $sameEvidence ? $previous : 'open';
                    $this->event($id, 'reopened', null, $newStatus === 'open'
                        ? __('Seen again after it was resolved.')
                        : __('Seen again after it was resolved. The earlier decision ({status}) still applies because the evidence is unchanged.', ['status' => $previous]));
                    $stats['reopened']++;
                    if ($newStatus === 'open') {
                        $stats['reopened_ids'][] = $id; // only findings that need attention again trigger alerts
                    }
                } elseif ($status === 'false_positive' && !$sameEvidence) {
                    $newStatus = 'open';
                    $this->event($id, 'evidence_changed', null, __('Marked as a false positive, but the evidence changed ({old} → {new}), so it was reopened.',
                        ['old' => mb_substr((string) $row['evidence'], 0, 120), 'new' => mb_substr($issue['evidence'], 0, 120)]));
                    $stats['reopened']++;
                    $stats['reopened_ids'][] = $id;
                }
                if ($row['severity'] !== $issue['severity']) {
                    $this->event($id, 'severity_changed', null, __('Severity changed from {old} to {new}.', ['old' => $row['severity'], 'new' => $issue['severity']]));
                    if ($issue['severity'] === 'fail' && $newStatus === 'open') {
                        $stats['escalated_ids'][] = $id; // an open Warning became a Fail: alert like a new Fail
                    }
                }
                $update->execute([
                    'sev' => $issue['severity'], 't' => $issue['title'], 'd' => $issue['detail'], 'tg' => $issue['target'], 'ev' => $issue['evidence'],
                    'a' => $issue['asset_id'], 'cve' => $issue['cve_id'], 'st' => $newStatus, 'resolved' => 0, 'resolved2' => 0,
                    'reap' => $status === 'resolved' ? 1 : 0, 'inc' => $status === 'resolved' || $newStatus !== $status ? 1 : 0, 'id' => $id,
                ]);
            }
            $resolve = $this->db->prepare("UPDATE findings SET resolved_from = status, status = 'resolved', resolved_at = UTC_TIMESTAMP() WHERE id = :id");
            foreach ($existing as $key => $row) {
                if (isset($current[$key]) || $row['status'] === 'resolved') {
                    continue;
                }
                if ($row['finding_type'] === 'vuln' && isset($awaiting[$row['target']])) {
                    continue; // new version, data not there yet: decide when it is
                }
                $resolve->execute(['id' => $row['id']]);
                $this->event((int) $row['id'], 'resolved', null, __('No longer seen by the latest checks.'));
                $stats['resolved']++;
                $stats['resolved_ids'][] = (int) $row['id'];
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
        return $stats;
    }

    /**
     * Recompute findings for every non-archived client. A problem with one
     * client is logged and the others still get refreshed.
     *
     * @param callable(int,array):void|null $onResult Called with each client's refresh result (e.g. to send alerts).
     * @return int Number of clients refreshed successfully.
     */
    public function refreshAll(?callable $onResult = null): int
    {
        $ok = 0;
        foreach ($this->db->query('SELECT id FROM clients WHERE is_archived = 0')->fetchAll(PDO::FETCH_COLUMN) as $id) {
            try {
                $result = $this->refreshClient((int) $id);
                if ($onResult !== null) {
                    $onResult((int) $id, $result);
                }
                $ok++;
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] findings refresh failed for client ' . $id . ': ' . $ex->getMessage());
            }
        }
        return $ok;
    }

    /**
     * The Fail/Warning issues currently known for a client, keyed by finding key.
     *
     * @return array<string,array{type:string,severity:string,title:string,detail:string,target:string,evidence:string,asset_id:?int,cve_id:?string}>
     */
    public function currentIssues(int $clientId): array
    {
        $issues = [];
        $add = static function (string $key, array $issue) use (&$issues): void {
            // Long keys (IPv6 + long hostnames) keep a readable prefix plus a hash of the whole key, so they never collide.
            if (strlen($key) > 190) {
                $key = substr($key, 0, 120) . '#' . hash('sha256', $key);
            }
            foreach (['title' => 300, 'detail' => 1000, 'target' => 320, 'evidence' => 500] as $field => $max) {
                $issue[$field] = mb_substr((string) $issue[$field], 0, $max);
            }
            // If two sources produce the same key, keep the more severe one.
            if (!isset($issues[$key]) || ($issues[$key]['severity'] === 'warn' && $issue['severity'] === 'fail')) {
                $issues[$key] = $issue + ['asset_id' => null, 'cve_id' => null];
            }
        };

        // Exposed high-risk services
        $stmt = $this->db->prepare(
            "SELECT s.port, s.service_name, s.product, s.version, a.ip, a.id AS asset_id FROM services s JOIN assets a ON a.id = s.asset_id
             WHERE a.client_id = :c AND s.is_open = 1 AND s.protocol = 'tcp'"
        );
        $stmt->execute(['c' => $clientId]);
        foreach ($stmt->fetchAll() as $s) {
            $port = (int) $s['port'];
            $name = PortProfile::HIGH_RISK[$port] ?? self::WARN_PORTS[$port] ?? null;
            if ($name === null) {
                continue;
            }
            $add("port:{$s['ip']}:{$port}", [
                'type' => 'port', 'severity' => isset(PortProfile::HIGH_RISK[$port]) ? 'fail' : 'warn',
                'title' => __('{service} open to the internet', ['service' => $name]),
                'detail' => __('Port {port}/tcp is reachable from the internet. Reported service: {svc}.', ['port' => $port, 'svc' => trim($s['service_name'] . ' ' . $s['product'] . ' ' . $s['version']) ?: '?']),
                'target' => "{$s['ip']}:{$port}", 'evidence' => $port . '|' . $s['service_name'], 'asset_id' => (int) $s['asset_id'],
            ]);
        }

        // Certificates
        foreach ($this->endpoints->tlsForClient($clientId) as $t) {
            foreach (ExposureRules::tlsIssues($t) as $issue) {
                if ($issue['severity'] === 'info') {
                    continue;
                }
                $target = $t['ip'] . ':' . $t['port'] . ($t['sni'] !== '' ? ' (' . $t['sni'] . ')' : '');
                $add("tls:{$t['ip']}:{$t['port']}:{$t['sni']}:{$issue['code']}", [
                    'type' => 'tls', 'severity' => $issue['severity'], 'title' => $issue['text'],
                    'detail' => __('Certificate {cn} issued by {issuer}, valid until {until} UTC.', ['cn' => $t['subject_cn'] ?: '?', 'issuer' => $t['issuer'] ?: '?', 'until' => $t['not_after'] ?? '?']),
                    'target' => $target, 'evidence' => $issue['code'] . '|' . $t['subject_cn'] . '|' . $t['not_after'], 'asset_id' => (int) $t['asset_id'],
                ]);
            }
        }

        // Exposed admin pages and portals
        foreach ($this->endpoints->webForClient($clientId) as $w) {
            $issue = ExposureRules::webIssue($w['category']);
            if ($issue === null || $issue['severity'] === 'info') {
                continue;
            }
            $add("web:{$w['ip']}:{$w['port']}:{$w['category']}", [
                'type' => 'web', 'severity' => $issue['severity'], 'title' => $issue['text'],
                'detail' => __('Page title: "{title}" (HTTP {code}).', ['title' => $w['title'] ?: '?', 'code' => $w['status_code'] ?? '?']),
                'target' => "{$w['scheme']}://{$w['ip']}:{$w['port']}", 'evidence' => (string) $w['category'], 'asset_id' => (int) $w['asset_id'],
            ]);
        }

        // Vulnerabilities
        foreach ($this->vulns->forClient($clientId) as $v) {
            $sev = ExposureRules::vulnSeverity($v);
            if ($sev === 'info') {
                continue;
            }
            $kev = (int) $v['in_kev'] === 1;
            $how = match ($v['confidence']) {
                'confirmed' => __('confirmed for the reported version'),
                'distro' => __('distribution build, the fix may be backported'),
                default => __('product found, version unknown'),
            };
            $add("vuln:{$v['ip']}:{$v['port']}:{$v['cve_id']}", [
                'type' => 'vuln', 'severity' => $sev,
                'title' => ($kev ? __('Known exploited: ') : '') . $v['cve_id'] . ' (' . ($v['cvss_score'] ?? '?') . ' ' . ucfirst(strtolower((string) $v['cvss_severity'])) . ')',
                'detail' => trim(trim($v['product'] . ' ' . $v['version']) . ': ' . $how . '. ' . mb_strimwidth((string) $v['summary'], 0, 600, '…')),
                'target' => "{$v['ip']}:{$v['port']}", 'evidence' => $v['confidence'] . '|' . $v['cpe'], 'asset_id' => null, 'cve_id' => (string) $v['cve_id'],
            ]);
        }
        return $issues;
    }

    /** Insert a new open finding and its "opened" event. Returns the new ID. */
    private function insert(int $clientId, string $key, array $issue): int
    {
        $this->db->prepare(
            'INSERT INTO findings (client_id, asset_id, finding_key, finding_type, severity, title, detail, target, evidence, cve_id, status, first_seen, last_seen)
             VALUES (:c, :a, :k, :type, :sev, :t, :d, :tg, :ev, :cve, \'open\', UTC_TIMESTAMP(), UTC_TIMESTAMP())'
        )->execute([
            'c' => $clientId, 'a' => $issue['asset_id'], 'k' => $key, 'type' => $issue['type'], 'sev' => $issue['severity'],
            't' => mb_substr($issue['title'], 0, 300), 'd' => mb_substr($issue['detail'], 0, 1000), 'tg' => mb_substr($issue['target'], 0, 320),
            'ev' => mb_substr($issue['evidence'], 0, 500), 'cve' => $issue['cve_id'],
        ]);
        $id = (int) $this->db->lastInsertId();
        $this->event($id, 'opened', null, null);
        return $id;
    }

    /** Append a history event. */
    private function event(int $findingId, string $event, ?int $userId, ?string $note): void
    {
        $this->db->prepare('INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, :e, :u, :n, UTC_TIMESTAMP())')
            ->execute(['f' => $findingId, 'e' => $event, 'u' => $userId, 'n' => $note]);
    }
}
