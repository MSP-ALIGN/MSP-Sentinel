<?php

declare(strict_types=1);

namespace Sentinel\Findings;

use PDO;
use Sentinel\Scanning\EndpointRepository;
use Sentinel\Scanning\ExposureRules;
use Sentinel\Scanning\PortProfile;
use Sentinel\Vulns\VulnRepository;
use Sentinel\Web\WebsiteRepository;

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
        private readonly ?WebsiteRepository $website = null,
        private readonly ?FixWorkflow $workflow = null,
        private readonly ?\Sentinel\Inventory\InventoryRepository $inventory = null,
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
            $result = $this->refreshLocked($clientId);
            $this->workflow?->recomputeDue($clientId); // due dates follow severity and KEV changes
            return $result;
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
        $awaitingDevices = $this->inventory?->devicesAwaitingData($clientId) ?? [];
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
                // updated_at first: MariaDB evaluates SET left to right, and it must only move on a real change.
                'UPDATE findings SET updated_at = IF(:chg = 1, UTC_TIMESTAMP(), updated_at), severity = :sev, title = :t, detail = :d, target = :tg, evidence = :ev, asset_id = :a, cve_id = :cve,
                        device_id = :dev,
                        status = :st, last_seen = UTC_TIMESTAMP(), resolved_at = IF(:resolved = 1, resolved_at, NULL),
                        resolved_from = IF(:resolved2 = 1, resolved_from, NULL),
                        reappeared = IF(:reap = 1, 1, reappeared), reopened_count = reopened_count + :inc,
                        opened_at = IF(:reopen = 1, UTC_TIMESTAMP(), opened_at), due_custom = IF(:reopen2 = 1, 0, due_custom)
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
                if ($newStatus === 'open' && $status !== 'open' && (int) ($row['due_custom'] ?? 0) === 1) {
                    $this->event($id, 'due_changed', null, __('Due date follows the policy again (the finding came back).'));
                }
                $update->execute([
                    'sev' => $issue['severity'], 't' => $issue['title'], 'd' => $issue['detail'], 'tg' => $issue['target'], 'ev' => $issue['evidence'],
                    'a' => $issue['asset_id'], 'cve' => $issue['cve_id'], 'dev' => $issue['device_id'], 'st' => $newStatus, 'resolved' => 0, 'resolved2' => 0,
                    'chg' => ($row['severity'] !== $issue['severity'] || $row['title'] !== $issue['title'] || $row['detail'] !== $issue['detail']
                        || $row['target'] !== $issue['target'] || !$sameEvidence || $newStatus !== $status) ? 1 : 0,
                    'reap' => $status === 'resolved' ? 1 : 0, 'inc' => $status === 'resolved' || $newStatus !== $status ? 1 : 0, 'id' => $id,
                    // Seen again after being resolved, or a false positive whose evidence changed: a new problem, so a new
                    // fix deadline starts now (and an admin-set date no longer applies; the history says so below).
                    'reopen' => $reopen = ($newStatus === 'open' && $status !== 'open') ? 1 : 0, 'reopen2' => $reopen,
                ]);
            }
            $resolve = $this->db->prepare("UPDATE findings SET resolved_from = status, status = 'resolved', resolved_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP() WHERE id = :id");
            foreach ($existing as $key => $row) {
                if (isset($current[$key]) || $row['status'] === 'resolved') {
                    continue;
                }
                if ($row['finding_type'] === 'vuln' && isset($awaiting[$row['target']])) {
                    continue; // new version, data not there yet: decide when it is
                }
                if ($row['finding_type'] === 'vuln' && $row['device_id'] !== null && isset($awaitingDevices[(int) $row['device_id']])
                    && str_starts_with((string) $row['finding_key'], 'devvuln:')) {
                    continue; // installed software was updated and its new version has no data yet
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
                $issues[$key] = $issue + ['asset_id' => null, 'cve_id' => null, 'source' => 'external', 'device_id' => null];
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
        // Website checks (headers, cookies, HTTPS, exposed files) on open web services.
        if ($this->website !== null) {
            foreach ($this->website->checksForClient($clientId) as $w) {
                $target = ($w['scheme'] ?? 'http') . '://' . $w['ip'] . ':' . $w['port'];
                $codes = array_merge((array) ($w['checks']['issues'] ?? []), (array) ($w['checks']['exposed'] ?? []));
                foreach (array_unique($codes) as $code) {
                    $rule = ExposureRules::websiteIssue((string) $code);
                    if ($rule['severity'] === 'info') {
                        continue;
                    }
                    $detail = $code === 'insecure_cookies' && !empty($w['checks']['cookies'])
                        ? __('Cookies: {list}.', ['list' => implode(', ', (array) $w['checks']['cookies'])])
                        : ($w['host_header'] !== '' ? __('Checked as {host}.', ['host' => $w['host_header']]) : '');
                    $add("site:{$w['ip']}:{$w['port']}:{$code}", [
                        'type' => 'web', 'severity' => $rule['severity'], 'title' => $rule['text'], 'detail' => $detail,
                        'target' => $target, 'evidence' => (string) $code, 'asset_id' => (int) $w['asset_id'],
                    ]);
                }
            }
            // Known vulnerabilities in detected CMS and JavaScript libraries.
            foreach ($this->website->componentVulns($clientId) as $v) {
                $sev = ExposureRules::vulnSeverity(['confidence' => $v['confidence'], 'in_kev' => $v['in_kev'], 'cvss_score' => $v['cvss_score'], 'cvss_severity' => $v['cvss_severity']]);
                if ($sev === 'info') {
                    continue;
                }
                $kev = (int) $v['in_kev'] === 1;
                $add("webvuln:{$v['ip']}:{$v['port']}:{$v['name']}:{$v['cve_id']}", [
                    'type' => 'vuln', 'severity' => $sev,
                    'title' => ($kev ? __('Known exploited: ') : '') . $v['cve_id'] . ' ' . __('in {component}', ['component' => trim($v['name'] . ' ' . $v['version'])])
                        . ' (' . ($v['cvss_score'] ?? '?') . ' ' . ucfirst(strtolower((string) $v['cvss_severity'])) . ')',
                    'detail' => trim(($v['confidence'] === 'confirmed' ? __('confirmed for the version on the page') : __('product found, version unknown')) . '. ' . mb_strimwidth((string) $v['summary'], 0, 600, '…')),
                    'target' => "{$v['ip']}:{$v['port']}", 'evidence' => $v['confidence'] . '|' . $v['name'] . ' ' . $v['version'], 'asset_id' => (int) $v['asset_id'], 'cve_id' => (string) $v['cve_id'],
                ]);
            }
            // Breached addresses of the client's verified domains (1.33): a breach in the last 12 months is a Fail.
            foreach (\Sentinel\Breach\BreachMonitor::forClient($this->db, $clientId) as $b) {
                $list = array_values(array_filter($b['breaches'], 'is_array'));
                if ($list === []) {
                    continue;
                }
                $recent = array_filter($list, static fn (array $x): bool => \Sentinel\Breach\BreachMonitor::recent((string) ($x['date'] ?? '')));
                $latest = $list[0];
                $add('breach:' . $b['email'], [
                    'type' => 'breach', 'severity' => $recent !== [] ? 'fail' : 'warn',
                    // The address is masked in the title and target (alerts, chat webhooks, lists); in full only in the detail.
                    'title' => __('{email} appeared in {n} data breach(es) (latest: {name}{date})', ['email' => \Sentinel\Breach\BreachMonitor::masked($b['email']), 'n' => count($list),
                        'name' => (string) ($latest['name'] ?? '?'), 'date' => (string) ($latest['date'] ?? '') !== '' ? ', ' . substr((string) $latest['date'], 0, 7) : '']),
                    'detail' => $b['email'] . ': ' . implode('; ', array_map(static fn (array $x): string => (string) ($x['name'] ?? '?') . ((string) ($x['date'] ?? '') !== '' ? ' (' . $x['date'] . ')' : '')
                        . ((array) ($x['data'] ?? []) !== [] ? ': ' . implode(', ', array_slice((array) $x['data'], 0, 8)) : ''), array_slice($list, 0, 20))),
                    'target' => \Sentinel\Breach\BreachMonitor::masked($b['email']),
                    // Sorted names: a new breach changes the evidence (and reopens a false positive); the provider's order doesn't.
                    'evidence' => (static function (array $l): string {
                        $n = array_map(static fn (array $x): string => (string) ($x['name'] ?? ''), $l);
                        sort($n);
                        return implode('|', $n);
                    })($list),
                ]);
            }
            // DNS: zone transfers and subdomain takeover (1.28).
            foreach ($this->website->domainChecksForClient($clientId) as $dc) {
                $r = $dc['result'];
                if ($dc['kind'] === 'zone') {
                    foreach ((array) ($r['nameservers'] ?? []) as $ns) {
                        if (($ns['status'] ?? '') !== 'open') {
                            continue;
                        }
                        $add('dns:' . $dc['name'] . ':' . $ns['ns'] . ':zone_transfer', [
                            'type' => 'dns', 'severity' => 'fail',
                            'title' => __('DNS zone transfer allowed: anyone can list every name in {d}', ['d' => $dc['name']]),
                            'detail' => __('Nameserver {ns} ({ip}) handed out {n} record(s) of the zone, for example: {sample}.', ['ns' => $ns['ns'], 'ip' => $ns['ip'],
                                'n' => (int) ($ns['records'] ?? 0), 'sample' => implode(', ', array_slice((array) ($ns['sample'] ?? []), 0, 8))]),
                            'target' => $dc['name'], 'evidence' => 'zone_transfer|' . $ns['ns'],
                        ]);
                    }
                } elseif (is_array($r['finding'] ?? null)) {
                    $f = $r['finding'];
                    $add('dns:' . $dc['name'] . ':takeover', [
                        'type' => 'dns', 'severity' => 'fail',
                        'title' => __('{h} can be taken over: it points at an unclaimed {p} name', ['h' => $dc['name'], 'p' => (string) ($f['provider'] ?? '?')]),
                        'detail' => (string) ($f['evidence'] ?? ''), 'target' => $dc['name'], 'evidence' => 'takeover|' . (string) ($f['cname'] ?? '') . '|' . (string) ($f['reason'] ?? ''),
                    ]);
                }
            }
            // Email security records (SPF, DMARC) for in-scope domains that receive mail.
            foreach ($this->website->emailForClient($clientId) as $e) {
                foreach ((array) ($e['issues'] ?? []) as $code) {
                    $rule = ExposureRules::emailIssue((string) $code);
                    if ($rule['severity'] === 'info') {
                        continue;
                    }
                    $add("email:{$e['domain']}:{$code}", [
                        'type' => 'email', 'severity' => $rule['severity'], 'title' => $rule['text'],
                        'detail' => trim(($e['spf'] ?? '') !== '' ? 'SPF: ' . $e['spf'] : '') . ((($e['dmarc'] ?? '') !== '') ? ' DMARC: ' . $e['dmarc'] : ''),
                        'target' => (string) $e['domain'], 'evidence' => (string) $code . '|' . ($e['spf_all'] ?? '') . '|' . ($e['dmarc_policy'] ?? ''), 'asset_id' => null,
                    ]);
                }
            }
        }
        // Internal devices from inventory sources (NinjaOne, later the agent): unsupported OS, antivirus,
        // encryption, missing patches, and known vulnerabilities in installed software (same grading as external).
        if ($this->inventory !== null) {
            $patches = $this->inventory->patchesByDevice($clientId);
            foreach ($this->inventory->devicesForClient($clientId) as $d) {
                foreach (\Sentinel\Inventory\DeviceRules::issues($d, $patches[(int) $d['id']] ?? []) as $issue) {
                    if ($issue['severity'] === 'info') {
                        continue;
                    }
                    $add("dev:{$d['source']}:{$d['source_id']}:{$issue['code']}", [
                        'type' => \Sentinel\Inventory\DeviceRules::type($issue['code']), 'severity' => $issue['severity'], 'title' => $issue['text'],
                        'detail' => $issue['detail'], 'target' => (string) ($d['name'] !== '' ? $d['name'] : $d['source_id']),
                        // Evidence: the code plus what makes it this problem (OS build, patch list), so a false positive reopens when it changes.
                        'evidence' => $issue['code'] . '|' . $d['os_build'] . '|' . mb_substr($issue['detail'], 0, 200),
                        'source' => (string) $d['source'], 'device_id' => (int) $d['id'],
                    ]);
                }
            }
            // Risky internal protocols (on-premises agent): SMBv1, SMB signing, RDP without NLA, Telnet, FTP, SNMP defaults, HTTP logins.
            foreach ($this->inventory->agentDevicesWithPorts($clientId) as $d) {
                foreach (\Sentinel\Agent\ProtocolRules::issues($d, $d['ports']) as $issue) {
                    $add("proto:{$d['source']}:{$d['source_id']}:{$issue['code']}", [
                        'type' => 'device', 'severity' => $issue['severity'], 'title' => $issue['text'], 'detail' => $issue['detail'],
                        'target' => (string) $d['name'], 'evidence' => $issue['code'], 'source' => (string) $d['source'], 'device_id' => (int) $d['id'],
                    ]);
                }
            }
            // Active Directory (on-premises agent, per site): what the last successful directory read found, and devices
            // heard sending LLMNR/NetBIOS name requests. Stored results only change on a successful read or listen.
            $dirs = $this->db->prepare("SELECT d.site_id, d.domain, d.results, s.name AS site_name FROM site_directory d JOIN sites s ON s.id = d.site_id WHERE d.client_id = :c AND d.results IS NOT NULL");
            $dirs->execute(['c' => $clientId]);
            foreach ($dirs->fetchAll() as $d) {
                foreach (\Sentinel\Agent\DirectoryRules::issues((array) json_decode((string) $d['results'], true)) as $issue) {
                    $add("ad:{$d['site_id']}:{$issue['code']}", [
                        'type' => 'directory', 'severity' => $issue['severity'], 'title' => $issue['text'], 'detail' => $issue['detail'],
                        'target' => (string) $d['domain'], 'evidence' => $issue['evidence'], 'source' => 'agent',
                    ]);
                }
            }
            $heard = $this->db->prepare('SELECT id, name, llmnr_results FROM sites WHERE client_id = :c AND llmnr_results IS NOT NULL');
            $heard->execute(['c' => $clientId]);
            $sitesHeard = $heard->fetchAll();
            if ($sitesHeard !== []) {
                $names = $this->db->prepare("SELECT ip_addresses, name FROM devices WHERE client_id = :c AND source = 'agent' AND removed_at IS NULL");
                $names->execute(['c' => $clientId]);
                $byIp = [];
                foreach ($names->fetchAll() as $dev) {
                    $byIp[(string) $dev['ip_addresses']] = (string) $dev['name'] !== (string) $dev['ip_addresses'] ? (string) $dev['name'] : '';
                }
                foreach ($sitesHeard as $site) {
                    $issue = \Sentinel\Agent\DirectoryRules::nameIssue((array) json_decode((string) $site['llmnr_results'], true), static fn (string $ip): string => $byIp[$ip] ?? '');
                    if ($issue !== null) {
                        $add("names:{$site['id']}:{$issue['code']}", [
                            'type' => 'directory', 'severity' => $issue['severity'], 'title' => $issue['text'], 'detail' => $issue['detail'],
                            'target' => (string) $site['name'], 'evidence' => $issue['evidence'], 'source' => 'agent',
                        ]);
                    }
                }
            }
            // Certificates of internal services (on-premises agent): only problems that matter inside a network
            // (expired, old TLS, weak key); self-signed and name mismatches are normal on internal devices.
            foreach ($this->inventory->internalTls($clientId) as $t) {
                foreach (\Sentinel\Agent\AgentService::internalTlsIssues($t['tls']) as $issue) {
                    $add("dport:{$t['source']}:{$t['source_id']}:{$t['port']}:{$issue['code']}", [
                        'type' => 'tls', 'severity' => $issue['severity'], 'title' => $issue['text'],
                        'detail' => __('Certificate {cn} issued by {issuer}, valid until {until} UTC.', ['cn' => $t['tls']['subject_cn'] ?: '?', 'issuer' => $t['tls']['issuer'] ?: '?', 'until' => $t['tls']['not_after'] ?? '?']),
                        'target' => $t['device_name'] . ':' . $t['port'], 'evidence' => $issue['code'] . '|' . ($t['tls']['subject_cn'] ?? '') . '|' . ($t['tls']['not_after'] ?? ''),
                        'source' => (string) $t['source'], 'device_id' => (int) $t['device_id'],
                    ]);
                }
            }
            // One finding per device and program (not per CVE): it lists the CVEs and takes the grade of the worst one,
            // so a few months of browser updates can't turn into thousands of findings.
            $groups = [];
            foreach ($this->inventory->softwareVulns($clientId) as $v) {
                $sev = ExposureRules::vulnSeverity(['confidence' => $v['confidence'], 'in_kev' => $v['in_kev'], 'cvss_score' => $v['cvss_score'], 'cvss_severity' => $v['cvss_severity']]);
                if ($sev === 'info') {
                    continue;
                }
                $g = &$groups[$v['source'] . ':' . $v['source_id'] . ':' . $v['product']];
                $g ??= ['v' => $v, 'sev' => 'warn', 'cves' => [], 'kev' => 0, 'worst' => $v];
                $g['cves'][$v['cve_id']] = true;
                $g['sev'] = $sev === 'fail' ? 'fail' : $g['sev'];
                $g['kev'] += (int) $v['in_kev'];
                $rank = static fn (array $x): array => [(int) $x['in_kev'], (float) ($x['cvss_score'] ?? 0)];
                if ($rank($v) > $rank($g['worst'])) {
                    $g['worst'] = $v;
                }
                unset($g);
            }
            foreach ($groups as $key => $g) {
                $v = $g['v'];
                $w = $g['worst'];
                $cves = array_keys($g['cves']);
                sort($cves);
                $n = count($cves);
                $add("devvuln:{$key}", [
                    'type' => 'vuln', 'severity' => $g['sev'],
                    'title' => ($g['kev'] > 0 ? __('Known exploited: ') : '') . __('{component}: {n} known CVE(s)', ['n' => $n, 'component' => trim($v['product'] . ' ' . $v['version'])])
                        . ' ' . __('(worst: {cve}, {score} {sev})', ['cve' => $w['cve_id'], 'score' => $w['cvss_score'] ?? '?', 'sev' => ucfirst(strtolower((string) $w['cvss_severity']))]),
                    'detail' => trim(match ($v['confidence']) { 'confirmed' => __('confirmed for the installed version'), 'distro' => __('distribution build, the fix may be backported'), default => __('product found, version unknown') }
                        . '. ' . __('CVEs: {list}', ['list' => implode(', ', array_slice($cves, 0, 30)) . ($n > 30 ? ' …' : '')]) . ' ' . __('Update {product} to the latest version.', ['product' => $v['product']])),
                    'target' => (string) $v['device_name'], 'evidence' => $v['confidence'] . '|' . $v['product'] . ' ' . $v['version'], 'cve_id' => (string) $w['cve_id'],
                    'source' => (string) $v['source'], 'device_id' => (int) $v['device_id'],
                ]);
            }
        }
        return $issues;
    }

    /** Insert a new open finding and its "opened" event. Returns the new ID. */
    private function insert(int $clientId, string $key, array $issue): int
    {
        $this->db->prepare(
            'INSERT INTO findings (client_id, asset_id, finding_key, finding_type, severity, title, detail, target, evidence, cve_id, status, first_seen, last_seen, opened_at, source, device_id)
             VALUES (:c, :a, :k, :type, :sev, :t, :d, :tg, :ev, :cve, \'open\', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), :src, :dev)'
        )->execute([
            'c' => $clientId, 'a' => $issue['asset_id'], 'k' => $key, 'type' => $issue['type'], 'sev' => $issue['severity'],
            'src' => (string) $issue['source'], 'dev' => $issue['device_id'],
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
