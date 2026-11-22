<?php

declare(strict_types=1);

namespace Sentinel\Demo;

use PDO;
use Sentinel\Core\App;
use Sentinel\Scope\IpRange;

/**
 * Demo data: made-up clients with a realistic spread of results, for trying Sentinel out on a test server.
 *
 * What it loads: four clients (all marked is_demo), each with an authorisation, scan history, open services,
 * certificates, web pages and website checks, email records and vulnerability matches; one client also has an
 * on-premises agent with devices and risky protocols, and inventory devices with patches and installed
 * software. Findings are then built by the real FindingsEngine, so they look exactly like real ones. Some are
 * assigned, accepted, marked false positive, overdue or resolved, and there are 90 days of trend history and two
 * reports.
 *
 * What makes it safe:
 * - Only made-up names (*.example) and documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
 *   for external targets, and 10.20.0.0/24 for the made-up internal site. No real client data.
 * - Every demo client has is_demo = 1, and ScanRepository::queue, AgentRepository::queueJob, discovery, the
 *   scheduler, inventory sync and vulnerability matching all refuse or skip demo clients. Nothing here ever
 *   contacts a host.
 * - No user accounts are created (findings are assigned to the admin who loads the data). Demo clients never
 *   alert anyone: AlertService, EventPublisher, fix reminders and monthly reports skip them.
 * - remove() deletes only rows that belong to demo clients (is_demo = 1). The CVE and KEV rows it adds are real,
 *   public reference data (and only added when missing), so they stay; the daily feeds keep them current.
 *
 * Untrusted input: none. Everything here is fixed data in this file; the acting user ID comes from the caller,
 * which has already checked that the user is an admin (web) or is the server administrator (CLI).
 */
final class DemoData
{
    /** Marker in the notes of every demo client (shown on the client page). */
    public const NOTE = 'Demo client with made-up data (loaded by MSP Sentinel demo data). Never scanned.';

    public function __construct(private readonly PDO $db, private readonly int $userId)
    {
    }

    /** Whether any demo client exists. */
    public function isLoaded(): bool
    {
        return (int) $this->db->query('SELECT COUNT(*) FROM clients WHERE is_demo = 1')->fetchColumn() > 0;
    }

    /**
     * Load the demo data. Refuses when it is already loaded (remove it first).
     *
     * @return array{clients:int, findings:int, devices:int, reports:int}
     */
    public function load(): array
    {
        // One load at a time (two admins clicking at once would otherwise create two demo sets).
        $lock = $this->db->quote('msp_sentinel_demo_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 5)")->fetchColumn() !== 1) {
            throw new \RuntimeException('Demo data is being loaded already.');
        }
        try {
            return $this->loadLocked();
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /**
     * The load itself (caller holds the demo lock).
     *
     * @return array{clients:int, findings:int, devices:int, reports:int}
     */
    private function loadLocked(): array
    {
        if ($this->isLoaded()) {
            throw new \RuntimeException('Demo data is already loaded. Remove it first.');
        }
        $this->ensureReferenceData();
        // Not one transaction (the findings engine and agent ingest run their own), so a failure part-way
        // removes whatever was loaded, leaving no half-loaded demo behind.
        try {
            $ids = [];
            foreach (self::clients() as $spec) {
                $ids[] = $this->loadClient($spec);
            }
            // Findings come from the real engine; then the workflow states, history and reports are layered on top.
            foreach ($ids as $id) {
                App::findingsEngine()->refreshClient($id);
            }
            $this->resolvedHistory($ids);
            $this->workflowStates($ids);
            $this->trendHistory($ids);
            $reports = $this->reports($ids[0]);
        } catch (\Throwable $ex) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            try {
                $this->remove();
            } catch (\Throwable $cleanup) {
                // Keep the original error; the cleanup problem is logged (remove it later with --remove).
                error_log('MSP Sentinel demo data: cleanup after a failed load also failed: ' . $cleanup->getMessage());
            }
            throw $ex;
        }
        $in = implode(',', $ids);
        return [
            'clients' => count($ids),
            'findings' => (int) $this->db->query("SELECT COUNT(*) FROM findings WHERE client_id IN ({$in})")->fetchColumn(),
            'devices' => (int) $this->db->query("SELECT COUNT(*) FROM devices WHERE client_id IN ({$in})")->fetchColumn(),
            'reports' => $reports,
        ];
    }

    /**
     * Remove every demo client and everything that belongs to it, children first, in one transaction.
     *
     * @return array{clients:int}
     */
    public function remove(): array
    {
        $ids = array_map('intval', $this->db->query('SELECT id FROM clients WHERE is_demo = 1')->fetchAll(PDO::FETCH_COLUMN));
        if ($ids === []) {
            return ['clients' => 0];
        }
        $in = implode(',', $ids); // integers from the database
        $this->db->beginTransaction();
        try {
            foreach ([
                "DELETE e FROM finding_events e JOIN findings f ON f.id = e.finding_id WHERE f.client_id IN ({$in})",
                "DELETE FROM findings WHERE client_id IN ({$in})",
                "DELETE FROM finding_stats WHERE client_id IN ({$in})",
                "DELETE FROM reports WHERE client_id IN ({$in})",
                "DELETE FROM report_runs WHERE client_id IN ({$in})",
                "DELETE FROM scan_log WHERE client_id IN ({$in})",
                "DELETE FROM scan_jobs WHERE client_id IN ({$in})",
                "DELETE sv FROM service_vulns sv JOIN services s ON s.id = sv.service_id JOIN assets a ON a.id = s.asset_id WHERE a.client_id IN ({$in})",
                "DELETE s FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id IN ({$in})",
                "DELETE cv FROM component_vulns cv JOIN web_components c ON c.id = cv.component_id JOIN web_pages w ON w.id = c.web_page_id JOIN assets a ON a.id = w.asset_id WHERE a.client_id IN ({$in})",
                "DELETE c FROM web_components c JOIN web_pages w ON w.id = c.web_page_id JOIN assets a ON a.id = w.asset_id WHERE a.client_id IN ({$in})",
                "DELETE w FROM web_pages w JOIN assets a ON a.id = w.asset_id WHERE a.client_id IN ({$in})",
                "DELETE t FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id WHERE a.client_id IN ({$in})",
                "DELETE FROM assets WHERE client_id IN ({$in})",
                "DELETE FROM email_checks WHERE client_id IN ({$in})",
                "DELETE FROM target_suggestions WHERE client_id IN ({$in})",
                "DELETE FROM discovery_runs WHERE client_id IN ({$in})",
                "DELETE sv FROM software_vulns sv JOIN device_software s ON s.id = sv.software_id JOIN devices d ON d.id = s.device_id WHERE d.client_id IN ({$in})",
                "DELETE s FROM device_software s JOIN devices d ON d.id = s.device_id WHERE d.client_id IN ({$in})",
                "DELETE p FROM device_patches p JOIN devices d ON d.id = p.device_id WHERE d.client_id IN ({$in})",
                "DELETE p FROM device_ports p JOIN devices d ON d.id = p.device_id WHERE d.client_id IN ({$in})",
                "DELETE FROM devices WHERE client_id IN ({$in})",
                "DELETE FROM agent_jobs WHERE client_id IN ({$in})",
                "DELETE FROM agents WHERE client_id IN ({$in})",
                "DELETE e FROM agent_enrolments e JOIN sites s ON s.id = e.site_id WHERE s.client_id IN ({$in})",
                "DELETE FROM internal_authorisations WHERE client_id IN ({$in})",
                "DELETE FROM source_links WHERE client_id IN ({$in})",
                "DELETE FROM api_token_clients WHERE client_id IN ({$in})",
                "DELETE FROM scope_entries WHERE client_id IN ({$in})",
                "DELETE FROM scan_authorisations WHERE client_id IN ({$in})",
                "DELETE FROM sites WHERE client_id IN ({$in})",
                "DELETE FROM clients WHERE id IN ({$in}) AND is_demo = 1",
            ] as $sql) {
                $this->db->exec($sql);
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
        return ['clients' => count($ids)];
    }

    // ------------------------------------------------------------------ loading

    /** One client: authorisation, external results, scans, discovery, and its agent site if it has one. */
    private function loadClient(array $spec): int
    {
        // Client names are unique: if a real client already has this name, the demo one gets a suffix.
        $taken = $this->db->prepare('SELECT COUNT(*) FROM clients WHERE name = :n');
        foreach (['', ' (demo)', ' (demo 2)', ' (demo 3)'] as $suffix) {
            $taken->execute(['n' => $spec['name'] . $suffix]);
            if ((int) $taken->fetchColumn() === 0) {
                $spec['name'] .= $suffix;
                break;
            }
        }
        $this->db->prepare(
            "INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, created_by, created_at, updated_at, is_demo, report_monthly)
             VALUES (:n, :tz, '22:00:00', '05:00:00', :notes, '', '', :u, UTC_TIMESTAMP() - INTERVAL 120 DAY, UTC_TIMESTAMP(), 1, 0)"
        )->execute(['n' => $spec['name'], 'tz' => $spec['timezone'], 'notes' => self::NOTE, 'u' => $this->userId]);
        $clientId = (int) $this->db->lastInsertId();
        $this->db->prepare("INSERT INTO sites (client_id, name, is_default, created_at, updated_at) VALUES (:c, 'Main office', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())")
            ->execute(['c' => $clientId]);
        $siteId = (int) $this->db->lastInsertId();

        // Authorisation (the repository writes the scope entries); ranges parsed directly, because the scope
        // parser rightly refuses documentation ranges outside the test suite.
        $entries = [];
        foreach ($spec['scope'] as $value) {
            $range = str_contains($value, '/') || filter_var($value, FILTER_VALIDATE_IP) !== false ? IpRange::parse($value) : null;
            $entries[] = ['type' => $range === null ? 'domain' : (str_contains($value, '/') ? 'cidr' : 'ip'), 'value' => $value, 'range' => $range];
        }
        App::authorisations()->create($clientId, [
            'approved_by_name' => $spec['approver'][0], 'approved_by_role' => $spec['approver'][1],
            'approved_on' => gmdate('Y-m-d', strtotime('-100 days')), 'valid_from' => gmdate('Y-m-d', strtotime('-100 days')),
            'valid_until' => gmdate('Y-m-d', strtotime($spec['valid_until'])), 'document_ref' => 'DEMO-' . strtoupper(substr($spec['domain'], 0, 4)) . '-001',
            'notes' => 'Made-up authorisation for the demo data.',
        ], $entries, $this->userId);

        foreach ($spec['hosts'] as $host) {
            $this->loadHost($clientId, $host);
        }
        foreach ($spec['email'] as $email) {
            $this->db->prepare('INSERT INTO email_checks (client_id, domain, has_mx, result, checked_at) VALUES (:c, :d, :mx, :r, UTC_TIMESTAMP() - INTERVAL 1 DAY)')
                ->execute(['c' => $clientId, 'd' => $email['domain'], 'mx' => $email['has_mx'] ? 1 : 0, 'r' => json_encode($email + [
                    'spf' => '', 'spf_all' => '', 'dmarc' => '', 'dmarc_policy' => '', 'dkim' => [], 'issues' => [], 'info' => [], 'error' => '',
                ], JSON_UNESCAPED_SLASHES)]);
        }
        $this->scanHistory($clientId, $spec);
        foreach ($spec['suggestions'] as [$kind, $value, $source, $detail, $third]) {
            $this->db->prepare("INSERT INTO target_suggestions (client_id, kind, value, source, detail, third_party_hint, status, first_seen, last_seen)
                                VALUES (:c, :k, :v, :s, :d, :t, 'pending', UTC_TIMESTAMP() - INTERVAL 6 DAY, UTC_TIMESTAMP() - INTERVAL 6 DAY)")
                ->execute(['c' => $clientId, 'k' => $kind, 'v' => $value, 's' => $source, 'd' => $detail, 't' => $third ? 1 : 0]);
        }
        $this->db->prepare("INSERT INTO discovery_runs (client_id, trigger_type, status, started_at, finished_at, summary)
                            VALUES (:c, 'scheduled', 'ok', UTC_TIMESTAMP() - INTERVAL 6 DAY, UTC_TIMESTAMP() - INTERVAL 6 DAY + INTERVAL 40 SECOND, :s)")
            ->execute(['c' => $clientId, 's' => json_encode(['new' => count($spec['suggestions']), 'messages' => []])]);
        if (isset($spec['agent'])) {
            $this->loadAgentSite($clientId, $siteId, $spec);
        }
        if (isset($spec['inventory'])) {
            $this->loadInventory($clientId, $siteId, $spec['inventory']);
        }
        return $clientId;
    }

    /** One external host: asset, open services (with vulnerability matches), certificates and web pages. */
    private function loadHost(int $clientId, array $h): void
    {
        $this->db->prepare('INSERT INTO assets (client_id, ip, hostnames, first_seen, last_seen, last_scanned, updated_at)
                            VALUES (:c, :ip, :hn, UTC_TIMESTAMP() - INTERVAL 90 DAY, UTC_TIMESTAMP() - INTERVAL 2 DAY, UTC_TIMESTAMP() - INTERVAL 2 DAY, UTC_TIMESTAMP())')
            ->execute(['c' => $clientId, 'ip' => $h['ip'], 'hn' => $h['hostname']]);
        $assetId = (int) $this->db->lastInsertId();
        foreach ($h['services'] as $s) {
            // services.cpe stays empty: demo services are never matched or looked up (the matcher skips demo
            // clients anyway); the example matches are written to service_vulns directly.
            $this->db->prepare("INSERT INTO services (asset_id, port, protocol, is_open, service_name, product, version, extra_info, cpe, first_seen, last_seen)
                                VALUES (:a, :p, 'tcp', 1, :n, :pr, :v, '', '', UTC_TIMESTAMP() - INTERVAL :age DAY, UTC_TIMESTAMP() - INTERVAL 2 DAY)")
                ->execute(['a' => $assetId, 'p' => $s['port'], 'n' => $s['name'], 'pr' => $s['product'] ?? '', 'v' => $s['version'] ?? '', 'age' => $s['age'] ?? 80]);
            $serviceId = (int) $this->db->lastInsertId();
            foreach ($s['cves'] ?? [] as [$cve, $confidence, $cpe]) {
                $this->db->prepare('INSERT INTO service_vulns (service_id, cve_id, confidence, cpe, first_seen, last_seen) VALUES (:s, :cve, :conf, :cpe, UTC_TIMESTAMP() - INTERVAL 30 DAY, UTC_TIMESTAMP())')
                    ->execute(['s' => $serviceId, 'cve' => $cve, 'conf' => $confidence, 'cpe' => $cpe]);
            }
        }
        foreach ($h['tls'] ?? [] as $t) {
            $this->db->prepare(
                "INSERT INTO tls_endpoints (asset_id, port, sni, subject_cn, sans, issuer, not_before, not_after, self_signed, chain_trusted, hostname_match,
                                            key_type, key_bits, signature_alg, protocol, accepts_tls10, accepts_tls11, first_seen, last_checked)
                 VALUES (:a, :p, :sni, :cn, :sans, :iss, UTC_TIMESTAMP() - INTERVAL :nb DAY, UTC_TIMESTAMP() + INTERVAL :na DAY, :ss, :ct, :hm,
                         :kt, :kb, 'sha256WithRSAEncryption', :proto, :t10, :t11, UTC_TIMESTAMP() - INTERVAL 90 DAY, UTC_TIMESTAMP() - INTERVAL 1 DAY)"
            )->execute(['a' => $assetId, 'p' => $t['port'], 'sni' => $t['sni'], 'cn' => $t['cn'], 'sans' => $t['cn'], 'iss' => $t['issuer'],
                        'nb' => $t['issued_days_ago'], 'na' => $t['expires_in_days'], 'ss' => (int) ($t['self_signed'] ?? 0), 'ct' => (int) ($t['trusted'] ?? 1),
                        'hm' => (int) ($t['match'] ?? 1), 'kt' => $t['key_type'] ?? 'RSA', 'kb' => $t['key_bits'] ?? 2048, 'proto' => $t['protocol'] ?? 'TLSv1.3',
                        't10' => (int) ($t['tls10'] ?? 0), 't11' => (int) ($t['tls11'] ?? 0)]);
        }
        foreach ($h['web'] ?? [] as $w) {
            $checks = isset($w['issues']) ? json_encode(['scheme' => $w['scheme'], 'status' => $w['status'], 'issues' => $w['issues'], 'info' => [],
                'exposed' => $w['exposed'] ?? [], 'cookies' => $w['cookies'] ?? [], 'components' => array_map(static fn (array $c): array => ['kind' => $c[0], 'name' => $c[1], 'version' => $c[2]], $w['components'] ?? [])],
                JSON_UNESCAPED_SLASHES) : null;
            $this->db->prepare(
                "INSERT INTO web_pages (asset_id, port, scheme, host_header, status_code, title, server_header, category, matched, first_seen, last_checked, checks, checks_at)
                 VALUES (:a, :p, :sch, :host, :code, :title, :server, :cat, :m, UTC_TIMESTAMP() - INTERVAL 80 DAY, UTC_TIMESTAMP() - INTERVAL 1 DAY, :checks, IF(:checks2 IS NULL, NULL, UTC_TIMESTAMP() - INTERVAL 1 DAY))"
            )->execute(['a' => $assetId, 'p' => $w['port'], 'sch' => $w['scheme'], 'host' => $h['hostname'], 'code' => $w['status'], 'title' => $w['title'],
                        'server' => $w['server'] ?? '', 'cat' => $w['category'] ?? '', 'm' => $w['category'] ?? '', 'checks' => $checks, 'checks2' => $checks]);
            $pageId = (int) $this->db->lastInsertId();
            foreach ($w['components'] ?? [] as [$kind, $name, $version, $cves]) {
                // No CPE: demo components are never matched or looked up; their example matches are written directly.
                $this->db->prepare("INSERT INTO web_components (web_page_id, kind, name, version, cpe, first_seen, last_seen) VALUES (:p, :k, :n, :v, '', UTC_TIMESTAMP() - INTERVAL 60 DAY, UTC_TIMESTAMP())")
                    ->execute(['p' => $pageId, 'k' => $kind, 'n' => $name, 'v' => $version]);
                $componentId = (int) $this->db->lastInsertId();
                foreach ($cves as $cve) {
                    $this->db->prepare("INSERT INTO component_vulns (component_id, cve_id, confidence, cpe, first_seen, last_seen) VALUES (:c, :cve, 'confirmed', '', UTC_TIMESTAMP() - INTERVAL 30 DAY, UTC_TIMESTAMP())")
                        ->execute(['c' => $componentId, 'cve' => $cve]);
                }
            }
        }
    }

    /** Finished weekly scans and daily certificate checks over the last weeks, with a short scan log. */
    private function scanHistory(int $clientId, array $spec): void
    {
        $hosts = count($spec['hosts']);
        $open = array_sum(array_map(static fn (array $h): int => count($h['services']), $spec['hosts']));
        foreach ([23, 16, 9, 2] as $daysAgo) {
            $this->db->prepare(
                "INSERT INTO scan_jobs (client_id, job_type, trigger_type, status, payload, summary, created_at, started_at, finished_at)
                 VALUES (:c, 'ports', 'scheduled', 'done', '{}', :s, UTC_TIMESTAMP() - INTERVAL :d DAY, UTC_TIMESTAMP() - INTERVAL :d2 DAY, UTC_TIMESTAMP() - INTERVAL :d3 DAY + INTERVAL 14 MINUTE)"
            )->execute(['c' => $clientId, 's' => json_encode(['hosts_scanned' => $hosts, 'hosts_skipped' => 0, 'hosts_failed' => 0, 'open_ports' => $open, 'messages' => []]),
                        'd' => $daysAgo, 'd2' => $daysAgo, 'd3' => $daysAgo]);
        }
        $jobId = (int) $this->db->lastInsertId();
        foreach ($spec['hosts'] as $h) {
            $ports = implode(',', array_map(static fn (array $s): int => (int) $s['port'], $h['services']));
            $this->db->prepare("INSERT INTO scan_log (job_id, client_id, target, hostname, ports, result, detail, started_at, finished_at)
                                VALUES (:j, :c, :t, :h, :p, 'scanned', :d, UTC_TIMESTAMP() - INTERVAL 2 DAY, UTC_TIMESTAMP() - INTERVAL 2 DAY + INTERVAL 3 MINUTE)")
                ->execute(['j' => $jobId, 'c' => $clientId, 't' => $h['ip'], 'h' => $h['hostname'], 'p' => $ports, 'd' => count($h['services']) . ' open port(s)']);
        }
        $this->db->prepare(
            "INSERT INTO scan_jobs (client_id, job_type, trigger_type, status, payload, summary, created_at, started_at, finished_at)
             VALUES (:c, 'tls', 'scheduled', 'done', '{}', :s, UTC_TIMESTAMP() - INTERVAL 1 DAY, UTC_TIMESTAMP() - INTERVAL 1 DAY, UTC_TIMESTAMP() - INTERVAL 1 DAY + INTERVAL 2 MINUTE)"
        )->execute(['c' => $clientId, 's' => json_encode(['endpoints_checked' => array_sum(array_map(static fn (array $h): int => count($h['tls'] ?? []) + count($h['web'] ?? []), $spec['hosts'])), 'hosts_skipped' => 0, 'messages' => []])]);
    }

    /**
     * An on-premises agent site: signed internal authorisation, an enrolled agent (its token is thrown away, so no
     * real agent can ever use it), and one full scan ingested through the real AgentService code.
     */
    private function loadAgentSite(int $clientId, int $siteId, array $spec): void
    {
        $a = $spec['agent'];
        $authId = App::agents()->createAuthorisation($clientId, $siteId, $spec['timezone'], [
            'approved_by_name' => $spec['approver'][0], 'approved_by_role' => $spec['approver'][1], 'approved_on' => gmdate('Y-m-d', strtotime('-60 days')),
            'valid_from' => gmdate('Y-m-d', strtotime('-60 days')), 'valid_until' => gmdate('Y-m-d', strtotime('+305 days')),
            'document_ref' => 'DEMO-INT-001', 'notes' => 'Made-up internal authorisation for the demo data.',
        ], [$a['range']], $this->userId);
        $code = App::agents()->createEnrolment($clientId, $siteId, $this->userId);
        $enrolled = App::agents()->enrol($code, $a['hostname'], App::version(), $a['ip']) ?? throw new \RuntimeException('Could not create the demo agent.');
        unset($code); // the one-time code and $enrolled['token'] are discarded: nothing can ever authenticate as this agent
        $agentId = (int) $enrolled['agent_id'];
        $this->db->prepare('UPDATE agents SET last_seen_at = UTC_TIMESTAMP() - INTERVAL 3 MINUTE, last_ip = :ip WHERE id = :id')->execute(['ip' => $a['ip'], 'id' => $agentId]);

        // The job row is written here (queueJob refuses demo clients on purpose) and ingested like a real result.
        $this->db->prepare(
            "INSERT INTO agent_jobs (agent_id, client_id, site_id, authorisation_id, kind, trigger_type, status, ports, created_at, sent_at, expires_at)
             VALUES (:a, :c, :s, :auth, 'full', 'scheduled', 'ingesting', '[]', UTC_TIMESTAMP() - INTERVAL 1 DAY, UTC_TIMESTAMP() - INTERVAL 1 DAY, UTC_TIMESTAMP() + INTERVAL 1 DAY)"
        )->execute(['a' => $agentId, 'c' => $clientId, 's' => $siteId, 'auth' => $authId]);
        $jobId = (int) $this->db->lastInsertId();
        $job = $this->db->query("SELECT * FROM agent_jobs WHERE id = {$jobId}")->fetch();
        $agent = $this->db->query("SELECT * FROM agents WHERE id = {$agentId}")->fetch();
        App::agentService()->ingest($job, $agent, ['status' => 'done', 'hosts' => $a['hosts'], 'messages' => []]);
        $this->db->prepare('UPDATE agent_jobs SET finished_at = UTC_TIMESTAMP() - INTERVAL 1 DAY + INTERVAL 52 MINUTE WHERE id = :id')->execute(['id' => $jobId]);
    }

    /** Inventory devices as an RMM would report them (OS, antivirus, encryption, patches, installed software). */
    private function loadInventory(int $clientId, int $siteId, array $devices): void
    {
        foreach ($devices as $i => $d) {
            $this->db->prepare(
                "INSERT INTO devices (client_id, site_id, source, source_id, name, dns_name, device_class, os_name, os_build, os_release, ip_addresses, last_contact,
                                      av_product, av_state, av_definitions, encryption, first_seen, last_seen)
                 VALUES (:c, :s, 'ninjaone', :sid, :n, :dns, :cls, :os, :build, :rel, :ips, UTC_TIMESTAMP() - INTERVAL 2 HOUR,
                         :av, :avs, :avd, :enc, UTC_TIMESTAMP() - INTERVAL 100 DAY, UTC_TIMESTAMP() - INTERVAL 2 HOUR)"
            )->execute(['c' => $clientId, 's' => $siteId, 'sid' => 'demo-' . ($i + 1), 'n' => $d['name'], 'dns' => strtolower($d['name']) . '.corp.riverside.example',
                        'cls' => $d['class'], 'os' => $d['os'], 'build' => $d['build'], 'rel' => $d['release'], 'ips' => $d['ip'],
                        'av' => $d['av'][0], 'avs' => $d['av'][1], 'avd' => $d['av'][2], 'enc' => $d['encryption']]);
            $deviceId = (int) $this->db->lastInsertId();
            foreach ($d['patches'] ?? [] as $j => [$name, $kb, $severity, $status, $age]) {
                $this->db->prepare('INSERT INTO device_patches (device_id, patch_id, name, kb, severity, status, detected_at, first_seen, last_seen)
                                    VALUES (:d, :pid, :n, :kb, :sev, :st, UTC_TIMESTAMP() - INTERVAL :age DAY, UTC_TIMESTAMP() - INTERVAL :age2 DAY, UTC_TIMESTAMP())')
                    ->execute(['d' => $deviceId, 'pid' => 'demo-' . ($i + 1) . '-' . ($j + 1), 'n' => $name, 'kb' => $kb, 'sev' => $severity, 'st' => $status, 'age' => $age, 'age2' => $age]);
            }
            foreach ($d['software'] ?? [] as [$name, $publisher, $version, $product, $cves]) {
                // No CPE: never matched or looked up (example matches below), so the demo stays as loaded.
                $this->db->prepare("INSERT INTO device_software (device_id, name, publisher, version, product, cpe, name_hash, match_pending, first_seen, last_seen, distro)
                                    VALUES (:d, :n, :p, :v, :pr, '', :h, 0, UTC_TIMESTAMP() - INTERVAL 60 DAY, UTC_TIMESTAMP(), 0)")
                    ->execute(['d' => $deviceId, 'n' => $name, 'p' => $publisher, 'v' => $version, 'pr' => $product, 'h' => hash('sha256', $name)]);
                $softwareId = (int) $this->db->lastInsertId();
                foreach ($cves as $cve) {
                    $this->db->prepare("INSERT INTO software_vulns (software_id, cve_id, confidence, cpe, first_seen, last_seen) VALUES (:s, :c, 'confirmed', '', UTC_TIMESTAMP() - INTERVAL 20 DAY, UTC_TIMESTAMP())")
                        ->execute(['s' => $softwareId, 'c' => $cve]);
                }
            }
        }
    }

    /** A few problems that were found earlier and fixed since: they show as resolved, with their history. */
    private function resolvedHistory(array $ids): void
    {
        foreach ($ids as $clientId) {
            $asset = (int) $this->db->query("SELECT id FROM assets WHERE client_id = {$clientId} ORDER BY id LIMIT 1")->fetchColumn();
            // Telnet and FTP were open, then closed by a later complete scan.
            foreach ([[23, 'telnet'], [21, 'ftp']] as [$port, $name]) {
                $this->db->prepare("INSERT INTO services (asset_id, port, protocol, is_open, service_name, product, version, extra_info, first_seen, last_seen)
                                    VALUES (:a, :p, 'tcp', 1, :n, '', '', '', UTC_TIMESTAMP() - INTERVAL 60 DAY, UTC_TIMESTAMP() - INTERVAL 20 DAY)")
                    ->execute(['a' => $asset, 'p' => $port, 'n' => $name]);
            }
            App::findingsEngine()->refreshClient($clientId);
            $this->db->exec("UPDATE services SET is_open = 0, closed_at = UTC_TIMESTAMP() - INTERVAL 16 DAY WHERE asset_id = {$asset} AND port IN (21, 23)");
            App::findingsEngine()->refreshClient($clientId);
            $this->db->exec("UPDATE findings SET first_seen = UTC_TIMESTAMP() - INTERVAL 60 DAY, opened_at = UTC_TIMESTAMP() - INTERVAL 60 DAY,
                                    resolved_at = UTC_TIMESTAMP() - INTERVAL 16 DAY, last_seen = UTC_TIMESTAMP() - INTERVAL 17 DAY
                             WHERE client_id = {$clientId} AND status = 'resolved'");
            $this->db->exec("UPDATE finding_events e JOIN findings f ON f.id = e.finding_id SET e.created_at = IF(e.event = 'resolved', f.resolved_at, f.first_seen)
                             WHERE f.client_id = {$clientId} AND f.status = 'resolved'");
        }
    }

    /**
     * Spread the open findings over the last two months, then give some of them owners, decisions and due dates,
     * through the real workflow code (so the history reads like real use).
     */
    private function workflowStates(array $ids): void
    {
        $in = implode(',', $ids);
        // Older findings first seen weeks ago; due dates follow the policy from the opened date, so some become overdue.
        $this->db->exec("UPDATE findings SET first_seen = UTC_TIMESTAMP() - INTERVAL (5 + (id * 7) % 55) DAY, opened_at = UTC_TIMESTAMP() - INTERVAL (5 + (id * 7) % 55) DAY
                         WHERE client_id IN ({$in}) AND status = 'open'");
        $this->db->exec("UPDATE finding_events e JOIN findings f ON f.id = e.finding_id SET e.created_at = f.first_seen
                         WHERE f.client_id IN ({$in}) AND f.status = 'open' AND e.event = 'opened'");
        App::fixWorkflow()->recomputeDue();
        $open = $this->db->query("SELECT id, severity, finding_type FROM findings WHERE client_id IN ({$in}) AND status = 'open' ORDER BY severity, id")->fetchAll();
        foreach ($open as $n => $f) {
            $id = (int) $f['id'];
            match ($n % 7) {
                0, 3 => App::fixWorkflow()->assign($id, $this->userId, $this->userId, 'Demo: taking this one.'),
                5 => App::findings()->triage($id, 'accepted', 'Demo: accepted risk, the client is replacing this device next quarter.', $this->userId),
                6 => $f['severity'] === 'warn'
                    ? App::findings()->triage($id, 'false_positive', 'Demo: checked by hand, the service is behind a separate login.', $this->userId)
                    : App::fixWorkflow()->setDue($id, gmdate('Y-m-d', strtotime('+21 days')), $this->userId, 'Demo: agreed with the client to fix it in the next maintenance window.'),
                default => null,
            };
        }
    }

    /** 90 days of open-findings counts per client, trending down to today's numbers (the dashboard trend chart). */
    private function trendHistory(array $ids): void
    {
        $stmt = $this->db->prepare("INSERT INTO finding_stats (client_id, day, fail_open, warn_open, recorded_at) VALUES (:c, UTC_DATE() - INTERVAL :d DAY, :f, :w, UTC_TIMESTAMP())
                                    ON DUPLICATE KEY UPDATE fail_open = VALUES(fail_open), warn_open = VALUES(warn_open)");
        foreach ($ids as $clientId) {
            $now = $this->db->query("SELECT COALESCE(SUM(status = 'open' AND severity = 'fail'), 0) AS f, COALESCE(SUM(status = 'open' AND severity = 'warn'), 0) AS w
                                     FROM findings WHERE client_id = {$clientId}")->fetch();
            for ($d = 90; $d >= 0; $d--) {
                // Higher in the past, stepping down as problems were fixed (deterministic, no randomness).
                $extra = intdiv($d, 18);
                $stmt->execute(['c' => $clientId, 'd' => $d, 'f' => (int) $now['f'] + $extra, 'w' => (int) $now['w'] + intdiv($d, 9)]);
            }
        }
    }

    /** An executive and a technical report for the first client, for last month. */
    private function reports(int $clientId): int
    {
        $client = App::clients()->find($clientId) ?? throw new \RuntimeException('Demo client vanished.');
        $start = gmdate('Y-m-01', strtotime('first day of last month'));
        $end = gmdate('Y-m-t', strtotime('last day of last month'));
        $name = (string) $this->db->query('SELECT display_name FROM users WHERE id = ' . $this->userId)->fetchColumn();
        foreach (['executive', 'technical'] as $kind) {
            App::reportService()->generate($client, $kind, $start, $end, $this->userId, $name !== '' ? $name : 'Demo');
        }
        return 2;
    }

    /**
     * Real, public CVE and KEV entries the demo refers to, added only when missing (a server with feeds already
     * has them). Summaries are short paraphrases of the public descriptions.
     */
    private function ensureReferenceData(): void
    {
        $cve = $this->db->prepare("INSERT IGNORE INTO cves (cve_id, summary, cvss_score, cvss_severity, cvss_version, published, last_modified, fetched_at)
                                   VALUES (:id, :s, :score, :sev, '3.1', :pub, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        foreach (self::CVES as $id => [$score, $sev, $published, $summary]) {
            $cve->execute(['id' => $id, 's' => $summary, 'score' => $score, 'sev' => $sev, 'pub' => $published]);
        }
        $kev = $this->db->prepare('INSERT IGNORE INTO kev_catalog (cve_id, vendor, product, name, date_added, due_date, ransomware, required_action)
                                   VALUES (:id, :v, :p, :n, :added, :due, :r, :act)');
        foreach (self::KEV as $id => [$vendor, $product, $name, $added, $due, $ransomware]) {
            $kev->execute(['id' => $id, 'v' => $vendor, 'p' => $product, 'n' => $name, 'added' => $added, 'due' => $due, 'r' => $ransomware,
                           'act' => 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.']);
        }
    }

    /** @var array<string, array{0:float,1:string,2:string,3:string}> CVE => [CVSS, severity, published, summary] */
    private const CVES = [
        'CVE-2021-34473' => [9.8, 'CRITICAL', '2021-07-14', 'Microsoft Exchange Server remote code execution vulnerability (part of the "ProxyShell" chain).'],
        'CVE-2018-13379' => [9.8, 'CRITICAL', '2019-06-04', 'Path traversal in the Fortinet FortiOS SSL VPN web portal lets an unauthenticated attacker download system files, including credentials.'],
        'CVE-2021-41773' => [7.5, 'HIGH', '2021-10-05', 'Path traversal in Apache HTTP Server 2.4.49 can expose files outside the document root, and may allow code execution.'],
        'CVE-2024-6387' => [8.1, 'HIGH', '2024-07-01', 'Signal handler race condition in OpenSSH sshd ("regreSSHion") that can allow unauthenticated remote code execution.'],
        'CVE-2023-48795' => [5.9, 'MEDIUM', '2023-12-18', 'SSH transport protocol prefix truncation ("Terrapin") that can downgrade connection security.'],
        'CVE-2019-8942' => [8.8, 'HIGH', '2019-02-20', 'WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution by authors through crafted image metadata.'],
        'CVE-2020-11023' => [6.1, 'MEDIUM', '2020-04-29', 'jQuery before 3.5.0 can run untrusted code when passing HTML containing <option> elements to its DOM manipulation methods.'],
        'CVE-2020-11022' => [6.1, 'MEDIUM', '2020-04-29', 'jQuery before 3.5.0 can run untrusted code when passing HTML from untrusted sources to its DOM manipulation methods.'],
        'CVE-2023-4863' => [8.8, 'HIGH', '2023-09-12', 'Heap buffer overflow in libwebp in Google Chrome before 116.0.5845.187 allows a crafted HTML page to corrupt memory.'],
        'CVE-2025-0411' => [7.0, 'HIGH', '2025-01-25', '7-Zip before 24.09 does not pass the Mark-of-the-Web to files extracted from crafted archives.'],
    ];

    /** @var array<string, array{0:string,1:string,2:string,3:string,4:string,5:string}> CVE => [vendor, product, name, added, due, ransomware] */
    private const KEV = [
        'CVE-2021-34473' => ['Microsoft', 'Exchange Server', 'Microsoft Exchange Server Remote Code Execution Vulnerability', '2021-11-03', '2021-11-17', 'Known'],
        'CVE-2018-13379' => ['Fortinet', 'FortiOS', 'Fortinet FortiOS SSL VPN Path Traversal Vulnerability', '2021-11-03', '2022-05-03', 'Known'],
        'CVE-2021-41773' => ['Apache', 'HTTP Server', 'Apache HTTP Server Path Traversal Vulnerability', '2021-11-03', '2021-11-17', 'Unknown'],
        'CVE-2020-11023' => ['JQuery', 'JQuery', 'JQuery Cross-Site Scripting (XSS) Vulnerability', '2025-01-23', '2025-02-13', 'Unknown'],
        'CVE-2023-4863' => ['Google', 'Chromium WebP', 'Google Chromium WebP Heap-Based Buffer Overflow Vulnerability', '2023-09-13', '2023-10-04', 'Unknown'],
        'CVE-2025-0411' => ['7-Zip', '7-Zip', '7-Zip Mark of the Web Bypass Vulnerability', '2025-02-06', '2025-02-27', 'Unknown'],
    ];

    /**
     * The demo clients. Made-up names, *.example domains and documentation addresses only.
     *
     * @return list<array<string,mixed>>
     */
    private static function clients(): array
    {
        $win = static fn (string $name, string $cls, string $os, string $build, string $rel, string $ip, array $av, string $enc, array $patches = [], array $software = []): array =>
            ['name' => $name, 'class' => $cls, 'os' => $os, 'build' => $build, 'release' => $rel, 'ip' => $ip, 'av' => $av, 'encryption' => $enc, 'patches' => $patches, 'software' => $software];
        $okAv = ['Example EDR', 'ok', 'current'];
        $chrome = ['Google Chrome', 'Google LLC', '116.0.5845.96', 'chrome', ['CVE-2023-4863']];
        $sevenzip = ['7-Zip 23.01 (x64)', 'Igor Pavlov', '23.01', '7-zip', ['CVE-2025-0411']];
        return [
            [
                'name' => 'Riverside Example Ltd', 'domain' => 'riverside.example', 'timezone' => 'Europe/London', 'valid_until' => '+265 days',
                'approver' => ['Alex Example', 'Managing Director'],
                'scope' => ['203.0.113.8/29', 'riverside.example', 'www.riverside.example', 'vpn.riverside.example'],
                'hosts' => [
                    ['ip' => '203.0.113.10', 'hostname' => 'www.riverside.example', 'services' => [
                        ['port' => 80, 'name' => 'http', 'product' => 'Apache httpd', 'version' => '2.4.49', 'cves' => [['CVE-2021-41773', 'confirmed', 'cpe:/a:apache:http_server:2.4.49']]],
                        ['port' => 443, 'name' => 'https', 'product' => 'Apache httpd', 'version' => '2.4.49', 'cves' => [['CVE-2021-41773', 'confirmed', 'cpe:/a:apache:http_server:2.4.49']]],
                        ['port' => 22, 'name' => 'ssh', 'product' => 'OpenSSH', 'version' => '8.9p1', 'cves' => [['CVE-2024-6387', 'confirmed', 'cpe:/a:openbsd:openssh:8.9'], ['CVE-2023-48795', 'confirmed', 'cpe:/a:openbsd:openssh:8.9']]],
                    ], 'tls' => [
                        ['port' => 443, 'sni' => 'www.riverside.example', 'cn' => 'www.riverside.example', 'issuer' => 'Example Public CA R3', 'issued_days_ago' => 85, 'expires_in_days' => 5],
                    ], 'web' => [
                        ['port' => 443, 'scheme' => 'https', 'status' => 200, 'title' => 'Riverside Example Ltd - Home', 'server' => 'Apache/2.4.49',
                         'issues' => ['missing_hsts', 'missing_csp', 'insecure_cookies'], 'cookies' => ['wp_session (no Secure)'], 'exposed' => ['exposed_git'],
                         'components' => [['cms', 'WordPress', '5.0', ['CVE-2019-8942']], ['library', 'jQuery', '1.12.4', ['CVE-2020-11023', 'CVE-2020-11022']]]],
                        ['port' => 80, 'scheme' => 'http', 'status' => 200, 'title' => 'Riverside Example Ltd - Home', 'server' => 'Apache/2.4.49', 'issues' => ['no_https_redirect']],
                    ]],
                    ['ip' => '203.0.113.11', 'hostname' => 'vpn.riverside.example', 'services' => [
                        ['port' => 443, 'name' => 'https', 'product' => 'Fortinet SSL VPN', 'version' => '6.0.4', 'cves' => [['CVE-2018-13379', 'confirmed', 'cpe:/o:fortinet:fortios:6.0.4']]],
                        ['port' => 8443, 'name' => 'https-alt', 'product' => 'Fortinet admin', 'version' => ''],
                    ], 'tls' => [
                        ['port' => 443, 'sni' => 'vpn.riverside.example', 'cn' => 'vpn.riverside.example', 'issuer' => 'Example Public CA R3', 'issued_days_ago' => 40, 'expires_in_days' => 50, 'tls10' => 1, 'tls11' => 1, 'protocol' => 'TLSv1.2'],
                        ['port' => 8443, 'sni' => '', 'cn' => 'FortiGate', 'issuer' => 'FortiGate', 'issued_days_ago' => 900, 'expires_in_days' => -30, 'self_signed' => 1, 'trusted' => 0, 'match' => 0, 'key_bits' => 1024],
                    ], 'web' => [
                        ['port' => 443, 'scheme' => 'https', 'status' => 200, 'title' => 'SSL VPN Login', 'category' => 'vpn_portal'],
                        ['port' => 8443, 'scheme' => 'https', 'status' => 200, 'title' => 'Firewall Administration', 'category' => 'firewall_admin'],
                    ]],
                    ['ip' => '203.0.113.12', 'hostname' => 'rds.riverside.example', 'services' => [
                        ['port' => 3389, 'name' => 'ms-wbt-server', 'product' => 'Microsoft Terminal Services', 'version' => ''],
                    ]],
                ],
                'email' => [['domain' => 'riverside.example', 'has_mx' => true, 'spf' => 'v=spf1 include:mail.example +all', 'spf_all' => '+', 'issues' => ['spf_pass_all', 'dmarc_missing']]],
                'suggestions' => [
                    ['hostname', 'mail.riverside.example', 'crtsh', 'Seen in certificate transparency logs.', false],
                    ['hostname', 'old-intranet.riverside.example', 'crtsh', 'Seen in certificate transparency logs (certificate expired 2024).', false],
                    ['hostname', 'shop.riverside.example', 'dns', 'Points to a hosted shop platform.', true],
                ],
                'agent' => ['hostname' => 'sentinel-agent-01', 'ip' => '10.20.0.5', 'range' => '10.20.0.0/24', 'hosts' => [
                    ['ip' => '10.20.0.10', 'mac' => '02:00:5e:10:00:10', 'hostname' => 'FS01', 'scanned' => true, 'ports' => [
                        ['port' => 445, 'service' => 'microsoft-ds', 'product' => 'Microsoft Windows SMB', 'checks' => ['smb1' => true, 'signing_required' => false]],
                        ['port' => 3389, 'service' => 'ms-wbt-server', 'checks' => ['nla_required' => true]],
                    ]],
                    ['ip' => '10.20.0.20', 'mac' => '02:00:5e:10:00:20', 'hostname' => 'PRN-OFFICE', 'scanned' => true, 'snmp' => ['public' => true, 'private' => true], 'ports' => [
                        ['port' => 80, 'service' => 'http', 'product' => 'Printer web server', 'web' => ['ok' => true, 'status' => 200, 'title' => 'Printer login', 'scheme' => 'http', 'login_over_http' => true]],
                        ['port' => 21, 'service' => 'ftp', 'product' => 'Printer FTP'],
                    ]],
                    ['ip' => '10.20.0.2', 'mac' => '02:00:5e:10:00:02', 'hostname' => 'SW-CORE', 'scanned' => true, 'ports' => [
                        ['port' => 23, 'service' => 'telnet'],
                        ['port' => 443, 'service' => 'https', 'tls' => ['ok' => true, 'subject_cn' => 'SW-CORE', 'issuer' => 'SW-CORE', 'not_before' => gmdate('Y-m-d H:i:s', strtotime('-1200 days')),
                            'not_after' => gmdate('Y-m-d H:i:s', strtotime('-60 days')), 'self_signed' => 1, 'chain_trusted' => 0, 'key_type' => 'RSA', 'key_bits' => 1024, 'accepts_tls10' => 1]],
                    ]],
                    ['ip' => '10.20.0.30', 'mac' => '02:00:5e:10:00:30', 'hostname' => 'NAS01', 'scanned' => true, 'ports' => [
                        ['port' => 445, 'service' => 'microsoft-ds', 'checks' => ['smb1' => false, 'signing_required' => true]],
                        ['port' => 5000, 'service' => 'http', 'web' => ['ok' => true, 'status' => 200, 'title' => 'NAS', 'scheme' => 'http', 'login_over_http' => false]],
                    ]],
                    ['ip' => '10.20.0.40', 'mac' => '02:00:5e:10:00:40', 'hostname' => 'APP02', 'scanned' => true, 'ports' => [
                        ['port' => 3389, 'service' => 'ms-wbt-server', 'checks' => ['nla_required' => false]],
                    ]],
                ]],
                'inventory' => [
                    $win('RIV-LT-001', 'laptop', 'Windows 11 Pro', '26200', '25H2', '10.20.0.101', $okAv, 'on', [], [$chrome]),
                    $win('RIV-LT-002', 'laptop', 'Windows 11 Pro', '26200', '25H2', '10.20.0.102', $okAv, 'off', [['2026-10 Cumulative Update for Windows 11', 'KB5099999', 'critical', 'pending', 45]]),
                    $win('RIV-WS-003', 'workstation', 'Windows 10 Pro', '19045', '22H2', '10.20.0.103', ['Example AV', 'off', 'outdated'], 'off', [], [$chrome, $sevenzip]),
                    $win('RIV-SRV-01', 'server', 'Windows Server 2012 R2 Standard', '9600', '', '10.20.0.10', ['Example AV', 'ok', 'outdated'], 'off',
                        [['Security update for Windows Server', 'KB5088888', 'important', 'failed', 12]]),
                    $win('RIV-SRV-02', 'server', 'Windows Server 2022 Standard', '20348', '21H2', '10.20.0.40', $okAv, 'on', [], [$sevenzip]),
                    $win('RIV-LT-004', 'laptop', 'Windows 11 Pro', '26200', '25H2', '10.20.0.104', ['', 'missing', ''], 'on'),
                ],
            ],
            [
                'name' => 'Lakeshore Example Inc', 'domain' => 'lakeshore.example', 'timezone' => 'America/Chicago', 'valid_until' => '+180 days',
                'approver' => ['Sam Example', 'IT Manager'],
                'scope' => ['198.51.100.20/30', 'lakeshore.example', 'mail.lakeshore.example'],
                'hosts' => [
                    ['ip' => '198.51.100.21', 'hostname' => 'mail.lakeshore.example', 'services' => [
                        ['port' => 443, 'name' => 'https', 'product' => 'Microsoft Exchange OWA', 'version' => '15.1', 'cves' => [['CVE-2021-34473', 'possible', 'cpe:/a:microsoft:exchange_server']]],
                        ['port' => 25, 'name' => 'smtp', 'product' => 'Microsoft Exchange smtpd', 'version' => ''],
                    ], 'tls' => [
                        ['port' => 443, 'sni' => 'mail.lakeshore.example', 'cn' => 'mail.lakeshore.example', 'issuer' => 'Example Public CA R3', 'issued_days_ago' => 70, 'expires_in_days' => 20, 'tls10' => 1, 'protocol' => 'TLSv1.2'],
                    ], 'web' => [
                        ['port' => 443, 'scheme' => 'https', 'status' => 200, 'title' => 'Outlook', 'category' => 'login_page', 'issues' => ['missing_csp']],
                    ]],
                    ['ip' => '198.51.100.22', 'hostname' => 'remote.lakeshore.example', 'services' => [
                        ['port' => 443, 'name' => 'https', 'product' => 'Microsoft IIS httpd', 'version' => '10.0'],
                    ], 'tls' => [
                        ['port' => 443, 'sni' => 'remote.lakeshore.example', 'cn' => 'remote.lakeshore.example', 'issuer' => 'Example Public CA R3', 'issued_days_ago' => 30, 'expires_in_days' => 60],
                    ], 'web' => [
                        ['port' => 443, 'scheme' => 'https', 'status' => 200, 'title' => 'RD Web Access', 'category' => 'remote_desktop_web', 'issues' => ['missing_hsts']],
                    ]],
                ],
                'email' => [['domain' => 'lakeshore.example', 'has_mx' => true, 'spf' => 'v=spf1 mx ~all', 'spf_all' => '~', 'dmarc' => 'v=DMARC1; p=none', 'dmarc_policy' => 'none', 'issues' => ['spf_weak', 'dmarc_weak']]],
                'suggestions' => [['hostname', 'autodiscover.lakeshore.example', 'crtsh', 'Seen in certificate transparency logs.', false]],
            ],
            [
                'name' => 'Hillcrest Example Clinic', 'domain' => 'hillcrest.example', 'timezone' => 'America/New_York', 'valid_until' => '+330 days',
                'approver' => ['Robin Example', 'Practice Manager'],
                'scope' => ['192.0.2.30', '192.0.2.31', 'hillcrest.example', 'portal.hillcrest.example'],
                'hosts' => [
                    ['ip' => '192.0.2.30', 'hostname' => 'portal.hillcrest.example', 'services' => [
                        ['port' => 443, 'name' => 'https', 'product' => 'nginx', 'version' => ''],
                        ['port' => 80, 'name' => 'http', 'product' => 'nginx', 'version' => ''],
                    ], 'tls' => [
                        ['port' => 443, 'sni' => 'portal.hillcrest.example', 'cn' => 'portal.hillcrest.example', 'issuer' => 'Example Public CA R3', 'issued_days_ago' => 20, 'expires_in_days' => 70, 'key_type' => 'EC', 'key_bits' => 256],
                    ], 'web' => [
                        ['port' => 443, 'scheme' => 'https', 'status' => 200, 'title' => 'Patient portal', 'category' => 'login_page', 'issues' => []],
                    ]],
                    ['ip' => '192.0.2.31', 'hostname' => 'hillcrest.example', 'services' => [
                        ['port' => 443, 'name' => 'https', 'product' => 'nginx', 'version' => ''],
                    ], 'tls' => [
                        ['port' => 443, 'sni' => 'hillcrest.example', 'cn' => 'hillcrest.example', 'issuer' => 'Example Public CA R3', 'issued_days_ago' => 20, 'expires_in_days' => 70, 'key_type' => 'EC', 'key_bits' => 256],
                    ]],
                ],
                'email' => [['domain' => 'hillcrest.example', 'has_mx' => true, 'spf' => 'v=spf1 include:mail.example -all', 'spf_all' => '-', 'dmarc' => 'v=DMARC1; p=reject', 'dmarc_policy' => 'reject', 'issues' => []]],
                'suggestions' => [],
            ],
            [
                'name' => 'Bayview Example Co', 'domain' => 'bayview.example', 'timezone' => 'Australia/Sydney', 'valid_until' => '+12 days',
                'approver' => ['Jordan Example', 'Owner'],
                'scope' => ['198.51.100.40', 'bayview.example'],
                'hosts' => [
                    ['ip' => '198.51.100.40', 'hostname' => 'bayview.example', 'services' => [
                        ['port' => 443, 'name' => 'https', 'product' => 'nginx', 'version' => ''],
                        ['port' => 3306, 'name' => 'mysql', 'product' => 'MySQL', 'version' => '5.7.44'],
                    ], 'tls' => [
                        ['port' => 443, 'sni' => 'bayview.example', 'cn' => 'www.bayview.example', 'issuer' => 'Example Public CA R3', 'issued_days_ago' => 60, 'expires_in_days' => 30, 'match' => 0],
                    ], 'web' => [
                        ['port' => 443, 'scheme' => 'https', 'status' => 200, 'title' => 'Bayview Example Co', 'issues' => ['missing_hsts', 'directory_listing']],
                    ]],
                ],
                'email' => [['domain' => 'bayview.example', 'has_mx' => true, 'issues' => ['spf_missing', 'dmarc_missing']]],
                'suggestions' => [['ip', '198.51.100.41', 'dns', 'A record of www.bayview.example.', false]],
            ],
        ];
    }
}
