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
 * Scope: every job carries the site's signed internal authorisation; the job
 * itself is signed when it is handed to the agent, and only after checking
 * again that the authorisation's signature verifies and is valid today. The
 * agent checks both signatures and that every target lies inside the signed
 * ranges, and refuses anything else. Results are accepted only for addresses
 * inside the job's authorisation.
 *
 * Schedule (per site with an active agent and authorisation, inside the
 * client's scan window, not paused): a full scan (discovery, ports, service
 * versions, certificates and web pages) weekly, and a light sweep (which
 * devices are there) daily, for new-device alerts.
 *
 * Untrusted: everything in agent results. It is validated (addresses in
 * scope, numbers in range, known values) and cleaned and shortened before
 * it is stored; counts are capped.
 */
final class AgentService
{
    public const FULL_DAYS = 7;
    public const LIGHT_HOURS = 20;
    public const JOB_HOURS = 12;
    public const MAX_HOSTS = 20000;
    public const MAX_PORTS_PER_HOST = 200;
    /** Devices not seen by any full scan for this long are marked removed. */
    public const REMOVE_AFTER_DAYS = 30;
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
            if ((int) $s['scanning_paused'] === 1 || (int) $s['site_paused'] === 1 || !ScanWindow::isOpen($s)) {
                continue;
            }
            $open = $this->db->prepare("SELECT COUNT(*) FROM agent_jobs WHERE site_id = :s AND status IN ('queued','sent')");
            $open->execute(['s' => $s['site_id']]);
            if ((int) $open->fetchColumn() > 0) {
                continue;
            }
            $auth = $this->agents->activeAuthorisation((int) $s['site_id'], ScopeService::today((string) $s['timezone']));
            if ($auth === null) {
                continue;
            }
            $last = $this->db->prepare("SELECT MAX(IF(kind = 'full', created_at, NULL)) AS full_at, MAX(created_at) AS any_at FROM agent_jobs WHERE site_id = :s AND status NOT IN ('cancelled','expired')");
            $last->execute(['s' => $s['site_id']]);
            $l = $last->fetch() ?: [];
            $kind = null;
            if ($l['full_at'] === null || strtotime($l['full_at'] . ' UTC') < time() - self::FULL_DAYS * 86400) {
                $kind = 'full';
            } elseif ($l['any_at'] === null || strtotime($l['any_at'] . ' UTC') < time() - self::LIGHT_HOURS * 3600) {
                $kind = 'light';
            }
            if ($kind !== null) {
                $this->agents->queueJob((int) $s['agent_id'], (int) $s['client_id'], (int) $s['site_id'], (int) $auth['id'], $kind, 'scheduled', null, $kind === 'full' ? self::PORTS : [], self::JOB_HOURS);
                $count++;
            }
        }
        return $count;
    }

    /**
     * The signed form of a job for its agent, or null when it may not run (authorisation no longer valid).
     *
     * @param array<string,mixed> $job   agent_jobs row.
     * @param array<string,mixed> $agent authenticated agent (with timezone).
     * @return array{payload:string, signature:string}|null
     */
    public function signedJob(array $job, array $agent): ?array
    {
        $auth = $this->agents->activeAuthorisation((int) $job['site_id'], ScopeService::today((string) $agent['timezone']));
        if ($auth === null || (int) $auth['id'] !== (int) $job['authorisation_id'] || (int) $job['agent_id'] !== (int) $agent['id']) {
            return null;
        }
        $ports = array_values(array_filter(array_map('intval', explode(',', (string) $job['ports'])), static fn (int $p): bool => $p > 0 && $p < 65536));
        return $this->signer->sign([
            'v' => 1, 'type' => 'agent_job', 'job_id' => (int) $job['id'], 'agent_id' => (int) $agent['id'], 'site_id' => (int) $job['site_id'],
            'kind' => (string) $job['kind'], 'ports' => $ports, 'targets' => $auth['ranges_list'],
            'issued_at' => gmdate('Y-m-d\TH:i:s\Z'), 'expires_at' => str_replace(' ', 'T', (string) $job['expires_at']) . 'Z',
            'authorisation' => ['payload' => (string) $auth['signed_payload'], 'signature' => (string) $auth['signature']],
        ]);
    }

    /**
     * Take in a job's results from its agent.
     *
     * @param array<string,mixed> $job   agent_jobs row (sent to this agent).
     * @param array<string,mixed> $agent authenticated agent.
     * @param array<string,mixed> $data  decoded results (untrusted).
     * @return array{accepted:int, rejected:int, new_devices:int, status:string}
     */
    public function ingest(array $job, array $agent, array $data): array
    {
        $status = in_array($data['status'] ?? '', ['done', 'partial', 'failed', 'cancelled'], true) ? (string) $data['status'] : 'failed';
        $auth = $this->db->prepare('SELECT signed_payload, signature FROM internal_authorisations WHERE id = :id');
        $auth->execute(['id' => (int) $job['authorisation_id']]);
        $a = $auth->fetch();
        $ranges = [];
        if ($a !== false && Signer::verify((string) $a['signed_payload'], (string) $a['signature'], $this->signer->publicKey())) {
            $ranges = array_values(array_map('strval', (array) (json_decode((string) $a['signed_payload'], true)['ranges'] ?? [])));
        }
        $siteId = (int) $job['site_id'];
        $clientId = (int) $job['client_id'];
        $full = $job['kind'] === 'full';
        $stats = ['accepted' => 0, 'rejected' => 0, 'new_devices' => 0, 'status' => $status];
        $hadDevices = (int) $this->db->query("SELECT COUNT(*) FROM devices WHERE source = 'agent' AND site_id = {$siteId}")->fetchColumn() > 0;
        $new = [];
        foreach (array_slice(array_values(array_filter((array) ($data['hosts'] ?? []), 'is_array')), 0, self::MAX_HOSTS) as $h) {
            $ip = (string) ($h['ip'] ?? '');
            $bin = @inet_pton($ip);
            if ($bin === false || $ranges === [] || !InternalRanges::allWithin([inet_ntop($bin)], $ranges)) {
                $stats['rejected']++; // never store anything outside the signed authorisation
                continue;
            }
            $ip = inet_ntop($bin);
            $isNew = $this->upsertDevice($clientId, $siteId, $ip, $h);
            if ($isNew) {
                $new[] = ['ip' => $ip, 'hostname' => InventoryRepository::clean((string) ($h['hostname'] ?? ''), 255), 'mac' => self::mac((string) ($h['mac'] ?? ''))];
            }
            if ($full && isset($h['ports']) && is_array($h['ports'])) {
                $this->savePorts($siteId, $ip, $h['ports']);
            }
            $stats['accepted']++;
        }
        // Full and complete: devices no full scan has seen for a long time are gone.
        if ($full && $status === 'done') {
            $this->db->prepare("UPDATE devices SET removed_at = UTC_TIMESTAMP() WHERE source = 'agent' AND site_id = :s AND removed_at IS NULL AND last_seen < UTC_TIMESTAMP() - INTERVAL " . self::REMOVE_AFTER_DAYS . ' DAY')
                ->execute(['s' => $siteId]);
        }
        $stats['new_devices'] = count($new);
        $summary = ['hosts' => $stats['accepted'], 'rejected' => $stats['rejected'], 'new_devices' => count($new),
                    'messages' => array_slice(array_map(static fn ($m): string => InventoryRepository::clean((string) $m, 300), (array) ($data['messages'] ?? [])), 0, 10)];
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
        // New devices: alert, except on a site's very first scan (that is the baseline) and for devices
        // NinjaOne already knows (same address or name).
        if ($hadDevices && $new !== []) {
            $unknown = array_values(array_filter($new, fn (array $d): bool => !$this->knownElsewhere($clientId, $d)));
            if ($unknown !== []) {
                $this->alerts?->newDevices($clientId, (string) $agent['site_name'], $unknown);
            }
        }
        return $stats;
    }

    /** Insert or update one device; true if this address was never seen at this site before. */
    private function upsertDevice(int $clientId, int $siteId, string $ip, array $h): bool
    {
        $sid = $siteId . ':' . $ip;
        $exists = $this->db->prepare("SELECT id FROM devices WHERE source = 'agent' AND source_id = :sid");
        $exists->execute(['sid' => $sid]);
        $known = $exists->fetchColumn() !== false;
        $hostname = InventoryRepository::clean((string) ($h['hostname'] ?? ''), 255);
        $this->db->prepare(
            "INSERT INTO devices (client_id, site_id, source, source_id, name, dns_name, device_class, ip_addresses, mac, last_contact, first_seen, last_seen, removed_at)
             VALUES (:c, :site, 'agent', :sid, :n, :dns, 'other', :ip, :mac, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), NULL)
             ON DUPLICATE KEY UPDATE client_id = VALUES(client_id), site_id = VALUES(site_id), name = IF(VALUES(dns_name) <> '', VALUES(name), name),
                dns_name = IF(VALUES(dns_name) <> '', VALUES(dns_name), dns_name), mac = IF(VALUES(mac) <> '', VALUES(mac), mac),
                last_contact = UTC_TIMESTAMP(), last_seen = UTC_TIMESTAMP(), removed_at = NULL"
        )->execute(['c' => $clientId, 'site' => $siteId, 'sid' => $sid, 'n' => $hostname !== '' ? $hostname : $ip, 'dns' => $hostname, 'ip' => $ip, 'mac' => self::mac((string) ($h['mac'] ?? ''))]);
        return !$known;
    }

    /**
     * Replace a device's open ports (full scans only), with certificate and web page summaries,
     * and its "software" rows for vulnerability matching (service CPEs reported by nmap).
     *
     * @param list<mixed> $ports
     */
    private function savePorts(int $siteId, string $ip, array $ports): void
    {
        $dev = $this->db->prepare("SELECT id FROM devices WHERE source = 'agent' AND source_id = :sid");
        $dev->execute(['sid' => $siteId . ':' . $ip]);
        $deviceId = (int) $dev->fetchColumn();
        if ($deviceId === 0) {
            return;
        }
        $up = $this->db->prepare(
            'INSERT INTO device_ports (device_id, port, service, product, version, extra_info, tls, web, first_seen, last_seen)
             VALUES (:d, :p, :s, :pr, :v, :x, :tls, :web, UTC_TIMESTAMP(), UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE service = VALUES(service), product = VALUES(product), version = VALUES(version), extra_info = VALUES(extra_info),
                tls = VALUES(tls), web = VALUES(web), last_seen = UTC_TIMESTAMP()'
        );
        $keep = [];
        $software = [];
        foreach (array_slice(array_values(array_filter($ports, 'is_array')), 0, self::MAX_PORTS_PER_HOST) as $p) {
            $port = (int) ($p['port'] ?? 0);
            if ($port < 1 || $port > 65535 || isset($keep[$port])) {
                continue;
            }
            $product = InventoryRepository::clean((string) ($p['product'] ?? ''), 120);
            $version = InventoryRepository::clean((string) ($p['version'] ?? ''), 80);
            $extra = InventoryRepository::clean((string) ($p['extra'] ?? ''), 200);
            $up->execute(['d' => $deviceId, 'p' => $port, 's' => InventoryRepository::clean((string) ($p['service'] ?? ''), 60), 'pr' => $product, 'v' => $version, 'x' => $extra,
                          'tls' => self::tls($p['tls'] ?? null), 'web' => self::web($p['web'] ?? null)]);
            $keep[$port] = true;
            $cpe = \Sentinel\Vulns\Cpe::parse((string) ($p['cpe'] ?? ''));
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
     * Internal certificate issues that are findings (rules shared with external checks, filtered for internal use).
     *
     * @param array<string,mixed> $tls Stored summary.
     * @return list<array{code:string, severity:string, text:string}>
     */
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

    /** True if an inventory source (NinjaOne) already knows this device (same address or host name). */
    private function knownElsewhere(int $clientId, array $d): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM devices WHERE client_id = :c AND source <> 'agent' AND removed_at IS NULL
                                    AND (FIND_IN_SET(:ip, ip_addresses) > 0 OR (:h <> '' AND (LOWER(name) = LOWER(:h2) OR LOWER(dns_name) = LOWER(:h3) OR LOWER(SUBSTRING_INDEX(:h4, '.', 1)) = LOWER(name))))");
        $stmt->execute(['c' => $clientId, 'ip' => $d['ip'], 'h' => $d['hostname'], 'h2' => $d['hostname'], 'h3' => $d['hostname'], 'h4' => $d['hostname']]);
        return (int) $stmt->fetchColumn() > 0;
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
        ], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
}
