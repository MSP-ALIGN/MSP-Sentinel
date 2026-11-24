<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

use PDO;

/**
 * Stores internal devices from inventory sources: a sync saves a whole
 * snapshot of one client's devices (with their software and missing
 * patches), and devices that are gone from a COMPLETE snapshot are marked as
 * removed (their findings then resolve). Also the client <-> organisation
 * links, and the software-to-CVE matches.
 *
 * Untrusted: every value in a snapshot comes from the outside source. It is
 * validated against fixed lists or cleaned (control characters removed) and
 * shortened to the column sizes; counts are capped so a huge answer can't
 * fill the database.
 */
final class InventoryRepository
{
    public const MAX_DEVICES = 5000;
    public const MAX_SOFTWARE = 1000;
    public const MAX_PATCHES = 500;
    /** Most program rows in one snapshot; beyond this the snapshot is saved as partial. */
    public const MAX_SOFTWARE_TOTAL = 200000;
    /** A complete snapshot that drops more than half of at least this many devices is treated as partial. */
    public const SHRINK_MIN_DEVICES = 4;

    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Save one client's snapshot from a source.
     *
     * @param array{devices:list<array<string,mixed>>, complete:bool} $snapshot
     * A "complete" snapshot that is empty, or drops more than half of the client's devices, is treated as
     * partial (nothing is removed): that usually means the source lost access, not that the devices are gone.
     *
     * @return array{devices:int, removed:int, software:int, patches:int, complete:bool, warning:string, linked:bool}
     */
    public function saveSnapshot(int $clientId, string $source, array $snapshot): array
    {
        $stats = ['devices' => 0, 'removed' => 0, 'software' => 0, 'patches' => 0, 'complete' => false, 'warning' => '', 'linked' => true];
        $devices = array_slice(array_values(array_filter((array) $snapshot['devices'], 'is_array')), 0, self::MAX_DEVICES);
        $complete = ($snapshot['complete'] ?? false) === true && count((array) $snapshot['devices']) <= self::MAX_DEVICES;
        $this->db->beginTransaction();
        try {
            // The link must still exist (an admin may have unlinked while the source was being read).
            $link = $this->db->prepare('SELECT id FROM source_links WHERE client_id = :c AND source = :s FOR UPDATE');
            $link->execute(['c' => $clientId, 's' => $source]);
            if ($link->fetchColumn() === false) {
                $this->db->rollBack();
                $stats['linked'] = false;
                return $stats;
            }
            $activeStmt = $this->db->prepare('SELECT COUNT(*) FROM devices WHERE client_id = :c AND source = :s AND removed_at IS NULL');
            $activeStmt->execute(['c' => $clientId, 's' => $source]);
            $active = (int) $activeStmt->fetchColumn();
            if ($complete && $active > 0 && (count($devices) === 0 || ($active >= self::SHRINK_MIN_DEVICES && count($devices) < $active / 2))) {
                $complete = false;
                $stats['warning'] = __('The source reported far fewer devices than before ({n} of {m}); nothing was removed. Check the source\'s access to this organisation.', ['n' => count($devices), 'm' => $active]);
            }
            $softwareLeft = self::MAX_SOFTWARE_TOTAL;
            $upDevice = $this->db->prepare(
                'INSERT INTO devices (client_id, source, source_id, name, dns_name, device_class, os_name, os_build, os_release, ip_addresses, last_contact,
                                      av_product, av_state, av_definitions, encryption, first_seen, last_seen, removed_at)
                 VALUES (:c, :s, :sid, :n, :dns, :cls, :os, :b, :r, :ip, :lc, :avp, :avs, :avd, :enc, UTC_TIMESTAMP(), UTC_TIMESTAMP(), NULL)
                 ON DUPLICATE KEY UPDATE client_id = VALUES(client_id), name = VALUES(name), dns_name = VALUES(dns_name), device_class = VALUES(device_class),
                    os_name = VALUES(os_name), os_build = VALUES(os_build), os_release = VALUES(os_release), ip_addresses = VALUES(ip_addresses),
                    last_contact = VALUES(last_contact), av_product = VALUES(av_product), av_state = VALUES(av_state), av_definitions = VALUES(av_definitions),
                    encryption = VALUES(encryption), last_seen = UTC_TIMESTAMP(), removed_at = NULL'
            );
            $find = $this->db->prepare('SELECT id FROM devices WHERE source = :s AND source_id = :sid');
            $seen = [];
            foreach ($devices as $d) {
                $sid = self::clean(($d['source_id'] ?? ''), 64);
                if ($sid === '' || isset($seen[$sid])) {
                    continue;
                }
                $lc = is_int($d['last_contact'] ?? null) && $d['last_contact'] > 0 && $d['last_contact'] < time() + 86400 ? gmdate('Y-m-d H:i:s', $d['last_contact']) : null;
                // Whole addresses only, as many as fit the column.
                $ips = [];
                foreach ((array) ($d['ip_addresses'] ?? []) as $ip) {
                    if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                        $ip = inet_ntop((string) inet_pton($ip)); // canonical, so addresses compare reliably
                        if (strlen(implode(',', [...$ips, $ip])) <= 500) {
                            $ips[] = $ip;
                        }
                    }
                }
                $upDevice->execute([
                    'c' => $clientId, 's' => $source, 'sid' => $sid, 'n' => self::clean(($d['name'] ?? ''), 255), 'dns' => self::clean(($d['dns_name'] ?? ''), 255),
                    'cls' => in_array($d['device_class'] ?? '', ['workstation', 'server'], true) ? $d['device_class'] : 'other',
                    'os' => self::clean(($d['os_name'] ?? ''), 255), 'b' => self::clean(($d['os_build'] ?? ''), 64), 'r' => self::clean(($d['os_release'] ?? ''), 64),
                    'ip' => implode(',', $ips), 'lc' => $lc,
                    'avp' => self::clean(($d['av_product'] ?? ''), 200), 'avs' => in_array($d['av_state'] ?? '', ['on', 'off', 'missing'], true) ? $d['av_state'] : '',
                    'avd' => in_array($d['av_definitions'] ?? '', ['current', 'outdated'], true) ? $d['av_definitions'] : '',
                    'enc' => in_array($d['encryption'] ?? '', ['on', 'off'], true) ? $d['encryption'] : '',
                ]);
                $find->execute(['s' => $source, 'sid' => $sid]);
                $deviceId = (int) $find->fetchColumn();
                $seen[$sid] = $deviceId;
                $stats['devices']++;
                $sw = array_slice((array) ($d['software'] ?? []), 0, max(0, min(self::MAX_SOFTWARE, $softwareLeft)));
                if (count((array) ($d['software'] ?? [])) > count($sw) && $softwareLeft < self::MAX_SOFTWARE) {
                    $complete = false; // too much data in total: keep it partial rather than drop programs silently
                }
                $saved = $this->saveSoftware($deviceId, $sw);
                $softwareLeft -= $saved;
                $stats['software'] += $saved;
                $stats['patches'] += $this->savePatches($deviceId, (array) ($d['patches'] ?? []));
            }
            // Gone from a complete snapshot: removed (kept for history; their findings resolve).
            if ($complete) {
                $params = ['c' => $clientId, 's' => $source];
                $not = '';
                if ($seen !== []) {
                    $not = ' AND id NOT IN (' . implode(',', array_map('intval', $seen)) . ')';
                }
                $stmt = $this->db->prepare("UPDATE devices SET removed_at = UTC_TIMESTAMP() WHERE client_id = :c AND source = :s AND removed_at IS NULL{$not}");
                $stmt->execute($params);
                $stats['removed'] = $stmt->rowCount();
            }
            $stats['complete'] = $complete;
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
        return $stats;
    }

    /**
     * Replace a device's software list (catalogue products get their CPE for matching).
     *
     * @param list<mixed> $software
     */
    private function saveSoftware(int $deviceId, array $software): int
    {
        // Keyed by a hash of the exact name and version; a changed catalogue identification re-queues matching.
        $up = $this->db->prepare(
            'INSERT INTO device_software (device_id, name, publisher, version, product, cpe, name_hash, match_pending, first_seen, last_seen)
             VALUES (:d, :n, :p, :v, :pr, :cpe, :h, :pend, UTC_TIMESTAMP(), UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE publisher = VALUES(publisher), product = VALUES(product),
                match_pending = IF(cpe <> VALUES(cpe), VALUES(match_pending), match_pending), cpe = VALUES(cpe), last_seen = UTC_TIMESTAMP(), id = LAST_INSERT_ID(id)'
        );
        $keep = [];
        foreach (array_slice(array_values(array_filter($software, 'is_array')), 0, self::MAX_SOFTWARE) as $s) {
            $name = self::clean(($s['name'] ?? ''), 255);
            if ($name === '') {
                continue;
            }
            $version = self::clean(($s['version'] ?? ''), 100);
            $id = SoftwareCatalog::identify($name, $version);
            $up->execute(['d' => $deviceId, 'n' => $name, 'p' => self::clean(($s['publisher'] ?? ''), 255), 'v' => $version,
                          'pr' => $id['product'] ?? '', 'cpe' => $id['cpe'] ?? '', 'h' => hash('sha256', $name . "\0" . $version), 'pend' => isset($id['cpe']) ? 1 : 0]);
            $keep[] = (int) $this->db->lastInsertId();
        }
        // Earlier versions are gone, but their matches are kept on the device until the new version has data
        // (see devicesAwaitingData), so findings don't resolve just because an update landed before NVD data did.
        $this->db->prepare('DELETE FROM device_software WHERE device_id = ?' . ($keep === [] ? '' : ' AND id NOT IN (' . implode(',', $keep) . ')'))->execute([$deviceId]);
        // A program no longer identified by the catalogue keeps no matches.
        $this->db->prepare("DELETE sv FROM software_vulns sv JOIN device_software s ON s.id = sv.software_id WHERE s.device_id = ? AND s.cpe = ''")->execute([$deviceId]);
        return count($keep);
    }

    /**
     * Replace a device's missing-patch list.
     *
     * @param list<mixed> $patches
     */
    private function savePatches(int $deviceId, array $patches): int
    {
        $up = $this->db->prepare(
            'INSERT INTO device_patches (device_id, patch_id, name, kb, severity, status, detected_at, first_seen, last_seen)
             VALUES (:d, :pid, :n, :kb, :sev, :st, :det, UTC_TIMESTAMP(), UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE name = VALUES(name), kb = VALUES(kb), severity = VALUES(severity), status = VALUES(status),
                detected_at = IF(detected_at IS NULL OR (VALUES(detected_at) IS NOT NULL AND VALUES(detected_at) < detected_at), VALUES(detected_at), detected_at), last_seen = UTC_TIMESTAMP(), id = LAST_INSERT_ID(id)'
        );
        $keep = [];
        foreach (array_slice(array_values(array_filter($patches, 'is_array')), 0, self::MAX_PATCHES) as $p) {
            $pid = self::clean(($p['patch_id'] ?? ''), 100);
            $status = in_array($p['status'] ?? '', ['pending', 'failed'], true) ? $p['status'] : null;
            if ($pid === '' || $status === null) {
                continue;
            }
            $det = is_int($p['detected_at'] ?? null) && $p['detected_at'] > 0 && $p['detected_at'] < time() + 86400 ? gmdate('Y-m-d H:i:s', $p['detected_at']) : null;
            $kb = preg_match('/^KB\d{6,8}$/i', (string) ($p['kb'] ?? '')) === 1 ? strtoupper((string) $p['kb']) : '';
            $up->execute(['d' => $deviceId, 'pid' => $pid, 'n' => self::clean(($p['name'] ?? ''), 300), 'kb' => $kb,
                          'sev' => strtolower(self::clean(($p['severity'] ?? ''), 20)), 'st' => $status, 'det' => $det]);
            $keep[] = (int) $this->db->lastInsertId();
        }
        $this->db->prepare('DELETE FROM device_patches WHERE device_id = ?' . ($keep === [] ? '' : ' AND id NOT IN (' . implode(',', $keep) . ')'))->execute([$deviceId]);
        return count($keep);
    }

    /**
     * SQL: the device (alias $a) is not shown merged into another (1.38.1/1.39). A merge counts only while its target
     * still exists, is current and belongs to the same client, so a removed, deleted or moved target never hides the
     * agent's device, even before refreshMerges() releases it. $a is a fixed alias from this code, never input.
     */
    public static function notMerged(string $a): string
    {
        return "({$a}.merged_into IS NULL OR NOT EXISTS (SELECT 1 FROM devices mt WHERE mt.id = {$a}.merged_into AND mt.client_id = {$a}.client_id AND mt.removed_at IS NULL))";
    }

    /**
     * Current (not removed) devices of a client, with counts. No limit for findings (every device counts);
     * the client page passes a limit.
     *
     * @return list<array<string,mixed>>
     */
    public function devicesForClient(int $clientId, ?int $limit = null): array
    {
        $stmt = $this->db->prepare(
            "SELECT d.*, (SELECT COUNT(*) FROM device_patches p WHERE p.device_id = d.id) AS patch_count,
                    (SELECT COUNT(DISTINCT sv.cve_id) FROM software_vulns sv JOIN device_software s ON s.id = sv.software_id WHERE s.device_id = d.id) AS vuln_count,
                    (SELECT COUNT(*) FROM device_software s WHERE s.device_id = d.id) AS software_count,
                    (SELECT COUNT(*) FROM findings f WHERE f.device_id IN (SELECT m.id FROM devices m WHERE m.id = d.id OR (m.merged_into = d.id AND m.client_id = d.client_id AND m.removed_at IS NULL))
                        AND f.status = 'open' AND f.severity = 'fail') AS open_fail,
                    (SELECT COUNT(*) FROM findings f WHERE f.device_id IN (SELECT m.id FROM devices m WHERE m.id = d.id OR (m.merged_into = d.id AND m.client_id = d.client_id AND m.removed_at IS NULL))
                        AND f.status = 'open' AND f.severity = 'warn') AS open_warn,
                    (SELECT COUNT(*) FROM devices m WHERE m.merged_into = d.id AND m.client_id = d.client_id AND m.removed_at IS NULL) AS merged_count
             FROM devices d WHERE d.client_id = :c AND d.removed_at IS NULL AND " . self::notMerged('d') . " ORDER BY d.name, d.id" . ($limit !== null ? ' LIMIT ' . max(1, $limit) : '')
        );
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Match the agent's devices to the inventory source's (1.38): an agent device whose IP address belongs to exactly
     * one active inventory device of the client, and whose name matches it (or that has no name), is the same machine
     * and is merged into it ('auto'). A match that no longer holds is undone. Devices an admin merged ('manual') or
     * split ('split') are left as they are. Nothing is deleted: lists show one row, the device page combines both.
     * Returns how many changed.
     */
    public function refreshMerges(int $clientId): int
    {
        $short = static fn (string $n): string => strtolower(explode('.', trim($n))[0]);
        // A merge into a device the source no longer reports is released (else the agent's device would vanish too).
        // So is one whose target was deleted, moved to another client (its source re-linked elsewhere) or is no longer an
        // inventory device: manual merges too, as the device they named is no longer this client's.
        $released = $this->db->prepare("UPDATE devices a LEFT JOIN devices t ON t.id = a.merged_into SET a.merged_into = NULL, a.merge_state = NULL
                                        WHERE a.client_id = :c AND a.merged_into IS NOT NULL
                                          AND (t.id IS NULL OR t.removed_at IS NOT NULL OR t.client_id <> a.client_id OR t.source = 'agent' OR t.merged_into IS NOT NULL)");
        $released->execute(['c' => $clientId]);
        $others = $this->db->prepare("SELECT id, name, dns_name, ip_addresses FROM devices WHERE client_id = :c AND source <> 'agent' AND removed_at IS NULL AND merged_into IS NULL");
        $others->execute(['c' => $clientId]);
        $byIp = [];
        $names = [];
        foreach ($others->fetchAll() as $o) {
            $names[(int) $o['id']] = array_filter([$short((string) $o['name']), $short((string) $o['dns_name'])]);
            foreach (explode(',', (string) $o['ip_addresses']) as $ip) {
                if (($ip = trim($ip)) !== '') {
                    $byIp[$ip][(int) $o['id']] = true;
                }
            }
        }
        $agents = $this->db->prepare("SELECT id, name, dns_name, ip_addresses, merged_into, merge_state FROM devices WHERE client_id = :c AND source = 'agent' AND removed_at IS NULL");
        $agents->execute(['c' => $clientId]);
        $set = $this->db->prepare('UPDATE devices SET merged_into = :t, merge_state = :s WHERE id = :id');
        $changed = 0;
        foreach ($agents->fetchAll() as $a) {
            if (in_array($a['merge_state'], ['manual', 'split'], true)) {
                continue;
            }
            $candidates = [];
            foreach (explode(',', (string) $a['ip_addresses']) as $ip) {
                $candidates += $byIp[trim($ip)] ?? [];
            }
            // The agent stores the address as the name when a device has no host name: that is no name (1.39).
            $ownName = (string) $a['name'];
            if ($ownName !== '' && in_array($ownName, array_map('trim', explode(',', (string) $a['ip_addresses'])), true)) {
                $ownName = '';
            }
            $own = array_filter([$short($ownName), $short((string) $a['dns_name'])]);
            $target = null;
            if (count($candidates) === 1) {
                $id = (int) array_key_first($candidates);
                // A different name on the same address is not proof (a reused address): only a matching or missing name.
                if ($own === [] || array_intersect($own, $names[$id] ?? []) !== []) {
                    $target = $id;
                }
            }
            if ($target !== ($a['merged_into'] !== null ? (int) $a['merged_into'] : null)) {
                $set->execute(['t' => $target, 's' => $target !== null ? 'auto' : null, 'id' => (int) $a['id']]);
                $changed++;
            }
        }
        return $changed + $released->rowCount();
    }

    /** An admin's merge (into an inventory device of the same client) or split (1.38). Returns whether it applied. */
    public function setMerge(int $clientId, int $agentDeviceId, ?int $targetId): bool
    {
        if ($targetId !== null) {
            $t = $this->db->prepare("SELECT COUNT(*) FROM devices WHERE id = :t AND client_id = :c AND source <> 'agent' AND removed_at IS NULL AND merged_into IS NULL");
            $t->execute(['t' => $targetId, 'c' => $clientId]);
            if ((int) $t->fetchColumn() !== 1) {
                return false;
            }
        }
        $stmt = $this->db->prepare("UPDATE devices SET merged_into = :t, merge_state = :s WHERE id = :id AND client_id = :c AND source = 'agent'");
        $stmt->execute(['t' => $targetId, 's' => $targetId !== null ? 'manual' : 'split', 'id' => $agentDeviceId, 'c' => $clientId]);
        return $stmt->rowCount() === 1;
    }

    /**
     * The agent devices of the same client merged into a device (1.38; client-checked since 1.39).
     *
     * @return list<array<string,mixed>>
     */
    public function mergedInto(int $clientId, int $deviceId): array
    {
        $stmt = $this->db->prepare('SELECT id, name, dns_name, ip_addresses, merge_state, site_id, checks FROM devices
                                    WHERE merged_into = :d AND client_id = :c AND removed_at IS NULL ORDER BY id');
        $stmt->execute(['d' => $deviceId, 'c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * One device of a client (or null), with its software (matched first) and missing patches.
     *
     * @return array<string,mixed>|null
     */
    public function device(int $clientId, int $deviceId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM devices WHERE id = :id AND client_id = :c');
        $stmt->execute(['id' => $deviceId, 'c' => $clientId]);
        $d = $stmt->fetch();
        if ($d === false) {
            return null;
        }
        $sw = $this->db->prepare("SELECT s.*, (SELECT GROUP_CONCAT(sv.cve_id ORDER BY sv.cve_id SEPARATOR ',') FROM software_vulns sv WHERE sv.software_id = s.id) AS cves
                                  FROM device_software s WHERE s.device_id = :d ORDER BY s.cpe = '', s.name LIMIT 2000");
        $sw->execute(['d' => $deviceId]);
        $d['software'] = $sw->fetchAll();
        $p = $this->db->prepare('SELECT * FROM device_patches WHERE device_id = :d ORDER BY status = \'failed\' DESC, detected_at, name');
        $p->execute(['d' => $deviceId]);
        $d['patches'] = $p->fetchAll();
        return $d;
    }

    /**
     * Patches of a client's current devices, grouped by device ID.
     *
     * @return array<int, list<array<string,mixed>>>
     */
    public function patchesByDevice(int $clientId): array
    {
        $stmt = $this->db->prepare('SELECT p.* FROM device_patches p JOIN devices d ON d.id = p.device_id WHERE d.client_id = :c AND d.removed_at IS NULL');
        $stmt->execute(['c' => $clientId]);
        $out = [];
        foreach ($stmt->fetchAll() as $p) {
            $out[(int) $p['device_id']][] = $p;
        }
        return $out;
    }

    /**
     * Vulnerabilities in installed software of a client's current devices (one row per device, product and CVE).
     *
     * @return list<array<string,mixed>>
     */
    public function softwareVulns(int $clientId): array
    {
        $stmt = $this->db->prepare(
            'SELECT d.id AS device_id, d.source, d.source_id, d.name AS device_name, s.product, s.version, sv.cve_id, sv.confidence,
                    c.cvss_score, c.cvss_severity, c.summary, (k.cve_id IS NOT NULL) AS in_kev
             FROM software_vulns sv JOIN device_software s ON s.id = sv.software_id JOIN devices d ON d.id = s.device_id
             JOIN cves c ON c.cve_id = sv.cve_id LEFT JOIN kev_catalog k ON k.cve_id = sv.cve_id
             WHERE d.client_id = :c AND d.removed_at IS NULL'
        );
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Devices of a client with installed software still waiting for vulnerability data. Their software
     * vulnerability findings must not resolve yet: missing data is not evidence of a fix.
     *
     * @return array<int,true> device IDs
     */
    public function devicesAwaitingData(int $clientId): array
    {
        $stmt = $this->db->prepare("SELECT DISTINCT s.device_id FROM device_software s JOIN devices d ON d.id = s.device_id WHERE d.client_id = :c AND d.removed_at IS NULL AND s.cpe <> '' AND s.match_pending = 1");
        $stmt->execute(['c' => $clientId]);
        return array_fill_keys(array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN)), true);
    }

    /** Mark every installed copy of one CPE as still waiting for vulnerability data (for one client or all). */
    public function markPending(?int $clientId, string $cpe): void
    {
        $scope = $clientId !== null ? ' AND d.client_id = ' . (int) $clientId : '';
        $this->db->prepare("UPDATE device_software s JOIN devices d ON d.id = s.device_id SET s.match_pending = 1 WHERE s.cpe = :cpe{$scope}")->execute(['cpe' => $cpe]);
    }

    /**
     * Certificate summaries of internal services on a client's current devices (agent full scans).
     *
     * @return list<array{device_id:int, source:string, source_id:string, device_name:string, port:int, tls:array<string,mixed>}>
     */
    public function internalTls(int $clientId): array
    {
        $stmt = $this->db->prepare('SELECT d.id AS device_id, d.source, d.source_id, d.name AS device_name, p.port, p.tls FROM device_ports p JOIN devices d ON d.id = p.device_id
                                    WHERE d.client_id = :c AND d.removed_at IS NULL AND p.tls IS NOT NULL');
        $stmt->execute(['c' => $clientId]);
        $out = [];
        foreach ($stmt->fetchAll() as $r) {
            $tls = json_decode((string) $r['tls'], true);
            if (is_array($tls)) {
                $out[] = ['device_id' => (int) $r['device_id'], 'source' => (string) $r['source'], 'source_id' => (string) $r['source_id'], 'device_name' => (string) $r['device_name'], 'port' => (int) $r['port'], 'tls' => $tls];
            }
        }
        return $out;
    }

    /**
     * Current agent devices of a client with their open ports (for the protocol rules).
     *
     * @return list<array<string,mixed>> devices rows with 'ports' (device_ports rows).
     */
    public function agentDevicesWithPorts(int $clientId): array
    {
        $stmt = $this->db->prepare("SELECT id, source, source_id, name, ip_addresses, checks FROM devices WHERE client_id = :c AND source = 'agent' AND removed_at IS NULL");
        $stmt->execute(['c' => $clientId]);
        $devices = [];
        foreach ($stmt->fetchAll() as $d) {
            $d['ports'] = [];
            $devices[(int) $d['id']] = $d;
        }
        if ($devices !== []) {
            foreach ($this->db->query('SELECT device_id, port, service, web, checks FROM device_ports WHERE device_id IN (' . implode(',', array_keys($devices)) . ')')->fetchAll() as $p) {
                $devices[(int) $p['device_id']]['ports'][] = $p;
            }
        }
        return array_values($devices);
    }

    /**
     * Open ports of one device (agent full scans).
     *
     * @return list<array<string,mixed>>
     */
    public function ports(int $deviceId): array
    {
        $stmt = $this->db->prepare('SELECT * FROM device_ports WHERE device_id = :d ORDER BY port');
        $stmt->execute(['d' => $deviceId]);
        return $stmt->fetchAll();
    }

    /**
     * Distinct catalogue CPEs installed on current devices (for one client or all), for matching.
     *
     * @return list<string>
     */
    public function cpesToMatch(?int $clientId): array
    {
        $sql = "SELECT DISTINCT s.cpe FROM device_software s JOIN devices d ON d.id = s.device_id WHERE s.cpe <> '' AND d.removed_at IS NULL"
            . ($clientId !== null ? ' AND d.client_id = ' . (int) $clientId : '');
        return array_map('strval', $this->db->query($sql)->fetchAll(PDO::FETCH_COLUMN));
    }

    /**
     * Set the CVE matches of every installed copy of one CPE (for one client or all).
     *
     * @param array<string,string> $matches cve_id => confirmed|possible
     */
    public function setMatchesForCpe(?int $clientId, string $cpe, array $matches, string $query): void
    {
        $scope = $clientId !== null ? ' AND d.client_id = ' . (int) $clientId : '';
        $this->db->beginTransaction();
        try {
            $this->db->prepare("DELETE sv FROM software_vulns sv JOIN device_software s ON s.id = sv.software_id JOIN devices d ON d.id = s.device_id WHERE s.cpe = :cpe{$scope}")
                ->execute(['cpe' => $cpe]);
            $ins = $this->db->prepare("INSERT INTO software_vulns (software_id, cve_id, confidence, cpe, first_seen, last_seen)
                                       SELECT s.id, :v, :conf, :q, UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM device_software s JOIN devices d ON d.id = s.device_id
                                       WHERE s.cpe = :cpe AND d.removed_at IS NULL{$scope}");
            foreach ($matches as $cve => $conf) {
                $ins->execute(['v' => $cve, 'conf' => $conf === 'confirmed' ? 'confirmed' : 'possible', 'q' => $query, 'cpe' => $cpe]);
            }
            // Distribution builds (agent-reported services) may carry backported fixes: never "confirmed".
            $this->db->prepare("UPDATE software_vulns sv JOIN device_software s ON s.id = sv.software_id JOIN devices d ON d.id = s.device_id
                                SET sv.confidence = 'distro' WHERE s.cpe = :cpe AND s.distro = 1 AND sv.confidence = 'confirmed'{$scope}")->execute(['cpe' => $cpe]);
            $this->db->prepare("UPDATE device_software s JOIN devices d ON d.id = s.device_id SET s.match_pending = 0 WHERE s.cpe = :cpe{$scope}")->execute(['cpe' => $cpe]);
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * The client's link to an organisation in a source, or null.
     *
     * @return array<string,mixed>|null
     */
    public function link(int $clientId, string $source): ?array
    {
        $stmt = $this->db->prepare('SELECT l.*, u.username AS linked_by_username FROM source_links l LEFT JOIN users u ON u.id = l.linked_by WHERE l.client_id = :c AND l.source = :s');
        $stmt->execute(['c' => $clientId, 's' => $source]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Links due for a sync (not synced for $hours), of active clients.
     *
     * @return list<array<string,mixed>>
     */
    public function linksDue(string $source, int $hours, int $limit): array
    {
        $stmt = $this->db->prepare(
            'SELECT l.* FROM source_links l JOIN clients c ON c.id = l.client_id AND c.is_archived = 0 AND c.is_demo = 0
             WHERE l.source = :s AND (l.last_sync_at IS NULL OR l.last_sync_at < UTC_TIMESTAMP() - INTERVAL :h HOUR) ORDER BY l.last_sync_at IS NOT NULL, l.last_sync_at LIMIT :lim'
        );
        $stmt->bindValue('s', $source);
        $stmt->bindValue('h', $hours, PDO::PARAM_INT);
        $stmt->bindValue('lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Link a client to an organisation (replacing an earlier link of that client).
     *
     * @throws \DomainException When the organisation is already linked to another client.
     */
    public function setLink(int $clientId, string $source, string $orgId, string $orgName, int $userId): void
    {
        $other = $this->db->prepare('SELECT client_id FROM source_links WHERE source = :s AND org_id = :o AND client_id <> :c');
        $other->execute(['s' => $source, 'o' => $orgId, 'c' => $clientId]);
        if ($other->fetchColumn() !== false) {
            throw new \DomainException('This organisation is already linked to another client.');
        }
        $this->db->prepare('INSERT INTO source_links (client_id, source, org_id, org_name, linked_by, linked_at) VALUES (:c, :s, :o, :n, :u, UTC_TIMESTAMP())
                            ON DUPLICATE KEY UPDATE org_id = VALUES(org_id), org_name = VALUES(org_name), linked_by = VALUES(linked_by), linked_at = UTC_TIMESTAMP(),
                               last_sync_at = NULL, last_sync_status = \'\', last_sync_message = \'\'')
            ->execute(['c' => $clientId, 's' => $source, 'o' => self::clean($orgId, 64), 'n' => self::clean($orgName, 200), 'u' => $userId]);
    }

    /** Remove a client's link; its devices are marked removed (their findings resolve on the next refresh). */
    public function unlink(int $clientId, string $source): void
    {
        $this->db->prepare('DELETE FROM source_links WHERE client_id = :c AND source = :s')->execute(['c' => $clientId, 's' => $source]);
        $this->db->prepare('UPDATE devices SET removed_at = UTC_TIMESTAMP() WHERE client_id = :c AND source = :s AND removed_at IS NULL')->execute(['c' => $clientId, 's' => $source]);
        $this->refreshMerges($clientId); // the agent's devices merged into them show again at once (1.39)
    }

    /** Record the outcome of a sync on the link. */
    public function recordSync(int $clientId, string $source, string $status, string $message): void
    {
        $this->db->prepare('UPDATE source_links SET last_sync_at = UTC_TIMESTAMP(), last_sync_status = :st, last_sync_message = :m WHERE client_id = :c AND source = :s')
            ->execute(['st' => $status, 'm' => mb_substr($message, 0, 500), 'c' => $clientId, 's' => $source]);
    }

    /**
     * Text from a source: valid UTF-8 (bad bytes replaced), without control characters (C0, C1) or invisible
     * direction and zero-width characters that could disguise a name on screen, shortened. Non-text values give ''.
     */
    public static function clean(mixed $value, int $max): string
    {
        if (!is_scalar($value)) {
            return '';
        }
        $value = mb_scrub((string) $value, 'UTF-8');
        $value = (string) preg_replace('/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]+/u', ' ', $value);
        return trim(mb_substr(trim($value), 0, $max));
    }
}
