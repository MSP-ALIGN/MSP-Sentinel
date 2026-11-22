<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use PDO;
use Sentinel\Alerts\AlertService;
use Sentinel\Findings\FindingsEngine;
use Sentinel\Inventory\InventoryRepository;
use Sentinel\Scope\ScopeService;
use Sentinel\Scanning\ScanWindow;
use Sentinel\Vulns\VulnMatcher;

/**
 * The server side of on-premises agents: scheduling jobs, signing them for
 * the agent, and taking in results.
 *
 * Scope: a job is only ever signed for the agent's OWN site and client, with
 * that site's signed internal authorisation (re-verified at hand-out); its
 * targets are the authorisation's networks, or hosts inside them (resuming an
 * unfinished scan). The agent pinned its site and client at enrolment and
 * checks both signatures, its site and client, and that every target lies
 * inside the signed ranges. Results are accepted only for addresses inside
 * the job's authorisation, and not at all once it is revoked.
 *
 * Schedule (per site with an active agent and authorisation, not paused):
 * scheduled jobs start only inside the client's scan window and are stopped
 * when it closes; an unfinished full scan resumes with the hosts it didn't
 * reach in the next window. A full scan (discovery, ports, service versions,
 * certificates, start pages) is due weekly after the last complete one; a
 * light sweep (which devices are there) daily, for new-device alerts.
 * Admins' "Scan now" jobs ignore the window.
 *
 * Untrusted: everything in agent results. It is validated (addresses in
 * scope, numbers in range, known values), cleaned, shortened and capped.
 * Ports of a device are replaced only when the agent finished scanning it.
 */
final class AgentService
{
    public const FULL_DAYS = 7;
    public const LIGHT_HOURS = 20;
    public const JOB_HOURS = 12;
    public const MAX_HOSTS = 20000;
    public const MAX_PORTS_PER_HOST = 200;
    /** Most hosts a resumed full scan carries over. */
    public const MAX_RESUME = 5000;
    /** Devices no completed host scan has seen for this long are marked removed. */
    public const REMOVE_AFTER_DAYS = 30;
    /** Hosts saved per database transaction while taking in results. */
    private const BATCH = 250;
    /** Common internal service ports for full scans (TCP connect scan, gentle). */
    public const PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 515, 548, 587, 631, 636, 873, 993, 995, 1433, 1521, 2049,
        3000, 3306, 3389, 5000, 5432, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 10000, 27017];
    /** Certificate problems that are findings for internal devices (self-signed and name mismatches are normal inside). */
    private const INTERNAL_TLS = ['cert_expired' => 'warn', 'tls_old_protocol' => 'warn', 'cert_weak_key' => 'warn'];

    /** Uses the stores and services of the other steps. */
    public function __construct(
        private readonly PDO $db,
        private readonly AgentRepository $agents,
        private readonly Signer $signer,
        private readonly ScopeService $scope,
        private readonly InventoryRepository $inventory,
        private readonly ?VulnMatcher $matcher,
        private readonly ?FindingsEngine $findings,
        private readonly ?AlertService $alerts,
    ) {
    }

    /**
     * Queue due jobs for every site with an active agent (worker).
     *
     * @return int Jobs queued.
     */
    public function scheduleDue(): int
    {
        if ($this->scope->globallyPaused()) {
            return 0;
        }
        $count = 0;
        $sites = $this->db->query(
            "SELECT s.id AS site_id, s.client_id, c.timezone, c.scan_window_start, c.scan_window_end, c.scanning_paused, s.scanning_paused AS site_paused,
                    (SELECT MAX(a.id) FROM agents a WHERE a.site_id = s.id AND a.status = 'active') AS agent_id
             FROM sites s JOIN clients c ON c.id = s.client_id AND c.is_archived = 0
             WHERE EXISTS (SELECT 1 FROM agents a WHERE a.site_id = s.id AND a.status = 'active')"
        )->fetchAll();
        foreach ($sites as $s) {
            $siteId = (int) $s['site_id'];
            if ((int) $s['scanning_paused'] === 1 || (int) $s['site_paused'] === 1 || !ScanWindow::isOpen($s) || $this->agents->openJobs($siteId) > 0) {
                continue;
            }
            $auth = $this->agents->activeAuthorisation($siteId, ScopeService::today((string) $s['timezone']));
            if ($auth === null) {
                continue;
            }
            // An unfinished full scan of the last week resumes with the hosts it didn't reach.
            $lastFull = $this->db->prepare("SELECT status, summary, created_at FROM agent_jobs WHERE site_id = :s AND kind = 'full' AND status IN ('done','partial') ORDER BY id DESC LIMIT 1");
            $lastFull->execute(['s' => $siteId]);
            $lf = $lastFull->fetch() ?: null;
            $remaining = [];
            if ($lf !== null && $lf['status'] === 'partial' && strtotime($lf['created_at'] . ' UTC') > time() - self::FULL_DAYS * 86400) {
                $remaining = array_values(array_filter((array) (json_decode((string) $lf['summary'], true)['remaining'] ?? []), static fn ($ip): bool => is_string($ip)
                    && filter_var($ip, FILTER_VALIDATE_IP) !== false && InternalRanges::allWithin([$ip], $auth['ranges_list'])));
            }
            $doneFull = $this->db->prepare("SELECT MAX(created_at) FROM agent_jobs WHERE site_id = :s AND kind = 'full' AND status = 'done'");
            $doneFull->execute(['s' => $siteId]);
            $doneAt = $doneFull->fetchColumn();
            $lastAny = $this->db->prepare("SELECT MAX(created_at) FROM agent_jobs WHERE site_id = :s AND status NOT IN ('cancelled','expired','failed')");
            $lastAny->execute(['s' => $siteId]);
            $anyAt = $lastAny->fetchColumn();
            if ($remaining !== []) {
                $targets = array_map(static fn (string $ip): string => $ip . (str_contains($ip, ':') ? '/128' : '/32'), array_slice($remaining, 0, self::MAX_RESUME));
                $this->agents->queueJob((int) $s['agent_id'], (int) $s['client_id'], $siteId, (int) $auth['id'], 'full', 'scheduled', null, self::PORTS, self::JOB_HOURS, $targets);
                $count++;
            } elseif ($doneAt === null || $doneAt === false || strtotime($doneAt . ' UTC') < time() - self::FULL_DAYS * 86400) {
                $this->agents->queueJob((int) $s['agent_id'], (int) $s['client_id'], $siteId, (int) $auth['id'], 'full', 'scheduled', null, self::PORTS, self::JOB_HOURS);
                $count++;
            } elseif ($anyAt === null || $anyAt === false || strtotime($anyAt . ' UTC') < time() - self::LIGHT_HOURS * 3600) {
                $this->agents->queueJob((int) $s['agent_id'], (int) $s['client_id'], $siteId, (int) $auth['id'], 'light', 'scheduled', null, [], self::JOB_HOURS);
                $count++;
            }
        }
        return $count;
    }

    /**
     * True if a job may run now: scheduled jobs only inside the client's scan window ("Scan now" jobs any time).
     *
     * @param array<string,mixed> $job
     * @param array<string,mixed> $agent Authenticated agent with its client's window.
     */
    public static function inWindow(array $job, array $agent): bool
    {
        return $job['trigger_type'] === 'manual' || ScanWindow::isOpen($agent);
    }

    /**
     * The signed form of a job for its agent, or null when it may not run.
     *
     * @param array<string,mixed> $job   agent_jobs row.
     * @param array<string,mixed> $agent authenticated agent (with timezone).
     * @return array{payload:string, signature:string}|null
     */
    public function signedJob(array $job, array $agent): ?array
    {
        // Only the agent's own site and client: a job row pointing elsewhere (e.g. a changed database) is never signed.
        if ((int) $job['agent_id'] !== (int) $agent['id'] || (int) $job['site_id'] !== (int) $agent['site_id'] || (int) $job['client_id'] !== (int) $agent['client_id']) {
            return null;
        }
        $auth = $this->agents->activeAuthorisation((int) $job['site_id'], ScopeService::today((string) $agent['timezone']));
        if ($auth === null || (int) $auth['id'] !== (int) $job['authorisation_id']) {
            return null;
        }
        $targets = $auth['ranges_list'];
        if ($job['targets'] !== null && trim((string) $job['targets']) !== '') {
            $targets = array_values(array_filter(array_map('trim', explode("\n", (string) $job['targets']))));
            if ($targets === [] || !InternalRanges::allWithin($targets, $auth['ranges_list'])) {
                return null;
            }
        }
        $ports = array_values(array_filter(array_map('intval', explode(',', (string) $job['ports'])), static fn (int $p): bool => $p > 0 && $p < 65536));
        return $this->signer->sign([
            'v' => 1, 'type' => 'agent_job', 'job_id' => (int) $job['id'], 'agent_id' => (int) $agent['id'], 'site_id' => (int) $job['site_id'], 'client_id' => (int) $job['client_id'],
            'kind' => (string) $job['kind'], 'ports' => $ports, 'targets' => $targets,
            'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => str_replace(' ', 'T', (string) $job['expires_at']) . 'Z',
            'authorisation' => ['payload' => (string) $auth['signed_payload'], 'signature' => (string) $auth['signature']],
        ]);
    }

    /**
     * Take in a job's results from its agent (the caller has claimed the job with claimIngest()).
     *
     * @param array<string,mixed> $job   agent_jobs row (sent to this agent).
     * @param array<string,mixed> $agent authenticated agent.
     * @param array<string,mixed> $data  decoded results (untrusted).
     * @return array{accepted:int, rejected:int, new_devices:int, status:string}
     */
    public function ingest(array $job, array $agent, array $data): array
    {
        $status = in_array($data['status'] ?? '', ['done', 'partial', 'failed', 'cancelled'], true) ? (string) $data['status'] : 'failed';
        $auth = $this->db->prepare('SELECT signed_payload, signature, revoked_at FROM internal_authorisations WHERE id = :id');
        $auth->execute(['id' => (int) $job['authorisation_id']]);
        $a = $auth->fetch();
        $ranges = [];
        if ($a !== false && $a['revoked_at'] === null && Signer::verify((string) $a['signed_payload'], (string) $a['signature'], $this->signer->publicKey())) {
            $ranges = array_values(array_map('strval', (array) (json_decode((string) $a['signed_payload'], true)['ranges'] ?? [])));
        }
        $siteId = (int) $job['site_id'];
        $clientId = (int) $job['client_id'];
        $full = $job['kind'] === 'full';
        $messages = array_slice(array_map(static fn ($m): string => InventoryRepository::clean($m, 300), (array) ($data['messages'] ?? [])), 0, 10);
        if ($ranges === []) {
            // Revoked (or no longer valid) authorisation: nothing from this job is stored.
            $this->agents->finishJob((int) $job['id'], 'cancelled', ['messages' => [__('Results ignored: the internal authorisation was revoked or is no longer valid.')]]);
            return ['accepted' => 0, 'rejected' => count((array) ($data['hosts'] ?? [])), 'new_devices' => 0, 'status' => 'cancelled'];
        }
        $stats = ['accepted' => 0, 'rejected' => 0, 'new_devices' => 0, 'status' => $status];
        $hadDevices = (int) $this->db->query("SELECT COUNT(*) FROM devices WHERE source = 'agent' AND site_id = {$siteId}")->fetchColumn() > 0;
        $knownIps = $this->knownElsewhereIps($clientId);
        $new = [];
        $hosts = array_slice(array_values(array_filter((array) ($data['hosts'] ?? []), 'is_array')), 0, self::MAX_HOSTS);
        foreach (array_chunk($hosts, self::BATCH) as $batch) {
            $this->db->beginTransaction();
            try {
                foreach ($batch as $h) {
                    $ip = self::canonicalIp($h['ip'] ?? null);
                    if ($ip === null || !InternalRanges::allWithin([$ip], $ranges)) {
                        $stats['rejected']++; // never store anything outside the signed authorisation
                        continue;
                    }
                    $scanned = $full && ($h['scanned'] ?? false) === true && is_array($h['ports'] ?? null);
                    [$deviceId, $isNew] = $this->upsertDevice($clientId, $siteId, $ip, $h, $scanned);
                    if ($isNew) {
                        $new[] = ['ip' => $ip, 'hostname' => InventoryRepository::clean($h['hostname'] ?? '', 255), 'mac' => self::mac((string) ($h['mac'] ?? ''))];
                    }
                    if ($scanned) {
                        $this->savePorts($deviceId, $h['ports']); // only a finished host scan replaces what was known
                        $snmp = is_array($h['snmp'] ?? null) ? ['snmp_public' => $h['snmp']['public'] ?? null, 'snmp_private' => $h['snmp']['private'] ?? null] : null;
                        $this->db->prepare('UPDATE devices SET checks = :c WHERE id = :id')->execute(['c' => self::checks($snmp, ['snmp_public', 'snmp_private']), 'id' => $deviceId]);
                    }
                    $stats['accepted']++;
                }
                $this->db->commit();
            } catch (\Throwable $ex) {
                $this->db->rollBack();
                throw $ex;
            }
        }
        if ($full && $status === 'done') {
            $this->db->prepare("UPDATE devices SET removed_at = UTC_TIMESTAMP() WHERE source = 'agent' AND site_id = :s AND removed_at IS NULL
                                AND COALESCE(last_full_seen, first_seen) < UTC_TIMESTAMP() - INTERVAL " . self::REMOVE_AFTER_DAYS . ' DAY')->execute(['s' => $siteId]);
        }
        $remaining = [];
        if ($full && $status !== 'done') {
            foreach (array_slice((array) ($data['unscanned'] ?? []), 0, self::MAX_RESUME) as $ip) {
                $ip = self::canonicalIp($ip);
                if ($ip !== null && InternalRanges::allWithin([$ip], $ranges)) {
                    $remaining[] = $ip;
                }
            }
        }
        $stats['new_devices'] = count($new);
        $summary = ['hosts' => $stats['accepted'], 'rejected' => $stats['rejected'], 'new_devices' => count($new), 'messages' => $messages];
        if ($remaining !== []) {
            $summary['remaining'] = $remaining;
            $summary['messages'][] = __('{n} device(s) not scanned yet; the scan continues in the next scan window.', ['n' => count($remaining)]);
        }
        if (!$hadDevices && $new !== []) {
            $summary['messages'][] = __('First scan of this site: {n} device(s) recorded as the starting point (no new-device alerts).', ['n' => count($new)]);
        }
        $this->agents->finishJob((int) $job['id'], $status, $summary);
        if ($full && $this->matcher !== null) {
            try {
                $this->matcher->matchSoftware($this->inventory, $clientId, 3);
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] agent software matching failed: ' . $ex->getMessage());
            }
        }
        if ($this->findings !== null) {
            try {
                $result = $this->findings->refreshClient($clientId);
                $this->alerts?->findingsChanged($clientId, $result, $full);
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] findings refresh after agent results failed: ' . $ex->getMessage());
            }
        }
        // New devices: alert, except on a site's very first scan (the baseline) and for addresses NinjaOne already knows.
        // Device-supplied names (certificate CNs) are never used to silence an alert.
        if ($hadDevices && $new !== []) {
            $unknown = array_values(array_filter($new, static fn (array $d): bool => !isset($knownIps[$d['ip']])));
            if ($unknown !== []) {
                $this->alerts?->newDevices($clientId, (string) $agent['site_name'], $unknown);
            }
        }
        return $stats;
    }

    /**
     * Insert or update one device. The same MAC address at the same site is the same device even when its address
     * changed (DHCP), so it is not announced as new.
     *
     * @return array{0:int, 1:bool} device ID, and true if this device was never seen at this site before.
     */
    private function upsertDevice(int $clientId, int $siteId, string $ip, array $h, bool $scanned): array
    {
        $mac = self::mac((string) ($h['mac'] ?? ''));
        $hostname = InventoryRepository::clean($h['hostname'] ?? '', 255);
        $existing = null;
        if ($mac !== '') {
            $byMac = $this->db->prepare("SELECT id FROM devices WHERE source = 'agent' AND site_id = :s AND mac = :m ORDER BY last_seen DESC LIMIT 1");
            $byMac->execute(['s' => $siteId, 'm' => $mac]);
            $existing = $byMac->fetchColumn() ?: null;
        }
        if ($existing === null) {
            $byId = $this->db->prepare("SELECT id FROM devices WHERE source = 'agent' AND source_id = :sid");
            $byId->execute(['sid' => $siteId . ':' . $ip]);
            $existing = $byId->fetchColumn() ?: null;
        }
        if ($existing !== null) {
            $this->db->prepare("UPDATE devices SET client_id = :c, site_id = :site, ip_addresses = :ip, name = IF(:dns <> '', :n, IF(name = '' OR name = ip_addresses, :ip2, name)),
                                dns_name = IF(:dns2 <> '', :dns3, dns_name), mac = IF(:mac <> '', :mac2, mac), last_contact = UTC_TIMESTAMP(), last_seen = UTC_TIMESTAMP(),
                                last_full_seen = IF(:full = 1, UTC_TIMESTAMP(), last_full_seen), removed_at = NULL WHERE id = :id")
                ->execute(['c' => $clientId, 'site' => $siteId, 'ip' => $ip, 'dns' => $hostname, 'n' => $hostname, 'ip2' => $ip, 'dns2' => $hostname, 'dns3' => $hostname,
                           'mac' => $mac, 'mac2' => $mac, 'full' => $scanned ? 1 : 0, 'id' => (int) $existing]);
            return [(int) $existing, false];
        }
        $this->db->prepare(
            "INSERT INTO devices (client_id, site_id, source, source_id, name, dns_name, device_class, ip_addresses, mac, last_contact, first_seen, last_seen, last_full_seen, removed_at)
             VALUES (:c, :site, 'agent', :sid, :n, :dns, 'other', :ip, :mac, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), :full, NULL)"
        )->execute(['c' => $clientId, 'site' => $siteId, 'sid' => $siteId . ':' . $ip, 'n' => $hostname !== '' ? $hostname : $ip, 'dns' => $hostname, 'ip' => $ip, 'mac' => $mac,
                    'full' => $scanned ? gmdate('Y-m-d H:i:s') : null]);
        return [(int) $this->db->lastInsertId(), true];
    }

    /**
     * Replace a device's open ports (a finished host scan), with certificate and web page summaries,
     * and its "software" rows for vulnerability matching (service CPEs reported by nmap).
     *
     * @param list<mixed> $ports
     */
    private function savePorts(int $deviceId, array $ports): void
    {
        $up = $this->db->prepare(
            'INSERT INTO device_ports (device_id, port, service, product, version, extra_info, tls, web, checks, first_seen, last_seen)
             VALUES (:d, :p, :s, :pr, :v, :x, :tls, :web, :chk, UTC_TIMESTAMP(), UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE service = VALUES(service), product = VALUES(product), version = VALUES(version), extra_info = VALUES(extra_info),
                tls = VALUES(tls), web = VALUES(web), checks = VALUES(checks), last_seen = UTC_TIMESTAMP()'
        );
        $keep = [];
        $software = [];
        foreach (array_slice(array_values(array_filter($ports, 'is_array')), 0, self::MAX_PORTS_PER_HOST) as $p) {
            $port = (int) ($p['port'] ?? 0);
            if ($port < 1 || $port > 65535 || isset($keep[$port])) {
                continue;
            }
            $product = InventoryRepository::clean($p['product'] ?? '', 120);
            $version = InventoryRepository::clean($p['version'] ?? '', 80);
            $extra = InventoryRepository::clean($p['extra'] ?? '', 200);
            $up->execute(['d' => $deviceId, 'p' => $port, 's' => InventoryRepository::clean($p['service'] ?? '', 60), 'pr' => $product, 'v' => $version, 'x' => $extra,
                          'tls' => self::tls($p['tls'] ?? null), 'web' => self::web($p['web'] ?? null), 'chk' => self::checks($p['checks'] ?? null, ['smb1', 'signing_required', 'nla_required'])]);
            $keep[$port] = true;
            $cpe = \Sentinel\Vulns\Cpe::parse(is_string($p['cpe'] ?? null) ? $p['cpe'] : '');
            if ($cpe !== null && $cpe['part'] === 'a') {
                $software[] = ['name' => trim(($product !== '' ? $product : $cpe['product']) . ' (port ' . $port . ')'), 'version' => $version,
                               'cpe' => 'cpe:/a:' . $cpe['vendor'] . ':' . $cpe['product'] . ($cpe['version'] !== '' ? ':' . $cpe['version'] : ''),
                               'distro' => preg_match('/\b(ubuntu|debian|deb\d+u\d+|el\d+|centos|rhel|red ?hat|rocky|alma(linux)?|suse|sles|amzn|fedora|raspbian)\b|~deb\d|\+deb\d/i', $product . ' ' . $version . ' ' . $extra) === 1];
            }
        }
        $this->db->prepare('DELETE FROM device_ports WHERE device_id = ?' . ($keep === [] ? '' : ' AND port NOT IN (' . implode(',', array_keys($keep)) . ')'))->execute([$deviceId]);
        // Services as "software" rows, so installed-software matching (and its findings) covers them.
        $sw = $this->db->prepare('INSERT INTO device_software (device_id, name, publisher, version, product, cpe, distro, name_hash, match_pending, first_seen, last_seen)
                                  VALUES (:d, :n, \'\', :v, :pr, :cpe, :dist, :h, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                                  ON DUPLICATE KEY UPDATE match_pending = IF(cpe <> VALUES(cpe), 1, match_pending), cpe = VALUES(cpe), product = VALUES(product),
                                     distro = VALUES(distro), last_seen = UTC_TIMESTAMP(), id = LAST_INSERT_ID(id)');
        $ids = [];
        foreach ($software as $s) {
            $n = mb_substr($s['name'], 0, 255);
            $v = mb_substr($s['version'], 0, 100);
            $sw->execute(['d' => $deviceId, 'n' => $n, 'v' => $v, 'pr' => mb_substr($s['name'], 0, 80), 'cpe' => $s['cpe'], 'dist' => $s['distro'] ? 1 : 0, 'h' => hash('sha256', $n . "\0" . $v)]);
            $ids[] = (int) $this->db->lastInsertId();
        }
        $this->db->prepare('DELETE FROM device_software WHERE device_id = ?' . ($ids === [] ? '' : ' AND id NOT IN (' . implode(',', $ids) . ')'))->execute([$deviceId]);
    }

    /**
     * Addresses that inventory sources (NinjaOne) report for the client's current devices, loaded once per upload.
     *
     * @return array<string,true>
     */
    private function knownElsewhereIps(int $clientId): array
    {
        $stmt = $this->db->prepare("SELECT ip_addresses FROM devices WHERE client_id = :c AND source <> 'agent' AND removed_at IS NULL AND ip_addresses <> ''");
        $stmt->execute(['c' => $clientId]);
        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $list) {
            foreach (explode(',', (string) $list) as $ip) {
                $c = self::canonicalIp($ip);
                if ($c !== null) {
                    $out[$c] = true;
                }
            }
        }
        return $out;
    }

    /** A canonical IP address, or null. */
    private static function canonicalIp(mixed $ip): ?string
    {
        if (!is_string($ip) || filter_var(trim($ip), FILTER_VALIDATE_IP) === false) {
            return null;
        }
        return inet_ntop((string) inet_pton(trim($ip)));
    }

    public static function internalTlsIssues(array $tls): array
    {
        $out = [];
        foreach (\Sentinel\Scanning\ExposureRules::tlsIssues($tls + ['not_after' => null, 'not_before' => null, 'key_type' => '', 'signature_alg' => '', 'sni' => '']) as $i) {
            if (isset(self::INTERNAL_TLS[$i['code']])) {
                $out[] = ['code' => $i['code'], 'severity' => self::INTERNAL_TLS[$i['code']], 'text' => $i['text']];
            }
        }
        return $out;
    }

    /** A MAC address in canonical form (aa:bb:cc:dd:ee:ff), or ''. */
    private static function mac(string $mac): string
    {
        $mac = strtolower(str_replace('-', ':', trim($mac)));
        return preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', $mac) === 1 ? $mac : '';
    }

    /** Certificate summary from agent data: known keys only, typed and shortened (JSON), or null. */
    private static function tls(mixed $t): ?string
    {
        if (!is_array($t) || ($t['ok'] ?? false) !== true) {
            return null;
        }
        $date = static fn ($v): ?string => is_string($v) && preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $v) ? $v : null;
        return json_encode([
            'subject_cn' => InventoryRepository::clean((string) ($t['subject_cn'] ?? ''), 255), 'issuer' => InventoryRepository::clean((string) ($t['issuer'] ?? ''), 255),
            'not_before' => $date($t['not_before'] ?? null), 'not_after' => $date($t['not_after'] ?? null),
            'self_signed' => ($t['self_signed'] ?? 0) ? 1 : 0, 'chain_trusted' => ($t['chain_trusted'] ?? 0) ? 1 : 0,
            'key_type' => in_array($t['key_type'] ?? '', ['RSA', 'EC', 'DSA', 'Ed25519', ''], true) ? (string) ($t['key_type'] ?? '') : '',
            'key_bits' => max(0, min(16384, (int) ($t['key_bits'] ?? 0))), 'signature_alg' => InventoryRepository::clean((string) ($t['signature_alg'] ?? ''), 60),
            'accepts_tls10' => ($t['accepts_tls10'] ?? 0) ? 1 : 0, 'accepts_tls11' => ($t['accepts_tls11'] ?? 0) ? 1 : 0,
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /**
     * Protocol check results from agent data: only the given keys, each true, false or null (JSON), or null.
     *
     * @param list<string> $keys
     */
    private static function checks(mixed $c, array $keys): ?string
    {
        if (!is_array($c)) {
            return null;
        }
        $out = [];
        foreach ($keys as $k) {
            $out[$k] = is_bool($c[$k] ?? null) ? $c[$k] : null;
        }
        return json_encode($out);
    }

    /** Web page summary from agent data: status, title and category only (JSON), or null. */
    private static function web(mixed $w): ?string
    {
        if (!is_array($w) || ($w['ok'] ?? false) !== true) {
            return null;
        }
        $categories = ['firewall_admin', 'device_admin', 'vpn_portal', 'remote_desktop_web', 'login_page', 'other'];
        return json_encode([
            'status' => max(0, min(999, (int) ($w['status'] ?? 0))), 'title' => InventoryRepository::clean((string) ($w['title'] ?? ''), 200),
            'category' => in_array($w['category'] ?? '', $categories, true) ? (string) $w['category'] : 'other', 'scheme' => ($w['scheme'] ?? '') === 'https' ? 'https' : 'http',
            'login_over_http' => ($w['login_over_http'] ?? false) === true && ($w['scheme'] ?? '') !== 'https',
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
