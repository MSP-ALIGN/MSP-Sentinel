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
    public const MAX_SOFTWARE = 2000;
    public const MAX_PATCHES = 500;

    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Save one client's snapshot from a source.
     *
     * @param array{devices:list<array<string,mixed>>, complete:bool} $snapshot
     * @return array{devices:int, removed:int, software:int, patches:int}
     */
    public function saveSnapshot(int $clientId, string $source, array $snapshot): array
    {
        $stats = ['devices' => 0, 'removed' => 0, 'software' => 0, 'patches' => 0];
        $devices = array_slice(array_values(array_filter((array) $snapshot['devices'], 'is_array')), 0, self::MAX_DEVICES);
        $complete = ($snapshot['complete'] ?? false) === true && count((array) $snapshot['devices']) <= self::MAX_DEVICES;
        $this->db->beginTransaction();
        try {
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
                $sid = self::clean((string) ($d['source_id'] ?? ''), 64);
                if ($sid === '' || isset($seen[$sid])) {
                    continue;
                }
                $lc = is_int($d['last_contact'] ?? null) && $d['last_contact'] > 0 && $d['last_contact'] < time() + 86400 ? gmdate('Y-m-d H:i:s', $d['last_contact']) : null;
                $ips = array_slice(array_values(array_filter(array_map('strval', (array) ($d['ip_addresses'] ?? [])), static fn (string $ip): bool => filter_var($ip, FILTER_VALIDATE_IP) !== false)), 0, 20);
                $upDevice->execute([
                    'c' => $clientId, 's' => $source, 'sid' => $sid, 'n' => self::clean((string) ($d['name'] ?? ''), 255), 'dns' => self::clean((string) ($d['dns_name'] ?? ''), 255),
                    'cls' => in_array($d['device_class'] ?? '', ['workstation', 'server'], true) ? $d['device_class'] : 'other',
                    'os' => self::clean((string) ($d['os_name'] ?? ''), 255), 'b' => self::clean((string) ($d['os_build'] ?? ''), 64), 'r' => self::clean((string) ($d['os_release'] ?? ''), 64),
                    'ip' => mb_substr(implode(',', $ips), 0, 500), 'lc' => $lc,
                    'avp' => self::clean((string) ($d['av_product'] ?? ''), 200), 'avs' => in_array($d['av_state'] ?? '', ['on', 'off', 'missing'], true) ? $d['av_state'] : '',
                    'avd' => in_array($d['av_definitions'] ?? '', ['current', 'outdated'], true) ? $d['av_definitions'] : '',
                    'enc' => in_array($d['encryption'] ?? '', ['on', 'off'], true) ? $d['encryption'] : '',
                ]);
                $find->execute(['s' => $source, 'sid' => $sid]);
                $deviceId = (int) $find->fetchColumn();
                $seen[$sid] = $deviceId;
                $stats['devices']++;
                $stats['software'] += $this->saveSoftware($deviceId, (array) ($d['software'] ?? []));
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
        $up = $this->db->prepare(
            'INSERT INTO device_software (device_id, name, publisher, version, product, cpe, first_seen, last_seen)
             VALUES (:d, :n, :p, :v, :pr, :cpe, UTC_TIMESTAMP(), UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE publisher = VALUES(publisher), product = VALUES(product), cpe = VALUES(cpe), last_seen = UTC_TIMESTAMP(), id = LAST_INSERT_ID(id)'
        );
        $keep = [];
        foreach (array_slice(array_values(array_filter($software, 'is_array')), 0, self::MAX_SOFTWARE) as $s) {
            $name = self::clean((string) ($s['name'] ?? ''), 255);
            if ($name === '') {
                continue;
            }
            $version = self::clean((string) ($s['version'] ?? ''), 100);
            $id = SoftwareCatalog::identify($name, $version);
            $up->execute(['d' => $deviceId, 'n' => $name, 'p' => self::clean((string) ($s['publisher'] ?? ''), 255), 'v' => $version,
                          'pr' => $id['product'] ?? '', 'cpe' => $id['cpe'] ?? '']);
            $keep[] = (int) $this->db->lastInsertId();
        }
        $this->db->prepare('DELETE FROM device_software WHERE device_id = ?' . ($keep === [] ? '' : ' AND id NOT IN (' . implode(',', $keep) . ')'))->execute([$deviceId]);
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
                detected_at = COALESCE(VALUES(detected_at), detected_at), last_seen = UTC_TIMESTAMP(), id = LAST_INSERT_ID(id)'
        );
        $keep = [];
        foreach (array_slice(array_values(array_filter($patches, 'is_array')), 0, self::MAX_PATCHES) as $p) {
            $pid = self::clean((string) ($p['patch_id'] ?? ''), 100);
            $status = in_array($p['status'] ?? '', ['pending', 'failed'], true) ? $p['status'] : null;
            if ($pid === '' || $status === null) {
                continue;
            }
            $det = is_int($p['detected_at'] ?? null) && $p['detected_at'] > 0 && $p['detected_at'] < time() + 86400 ? gmdate('Y-m-d H:i:s', $p['detected_at']) : null;
            $kb = preg_match('/^KB\d{6,8}$/i', (string) ($p['kb'] ?? '')) === 1 ? strtoupper((string) $p['kb']) : '';
            $up->execute(['d' => $deviceId, 'pid' => $pid, 'n' => self::clean((string) ($p['name'] ?? ''), 300), 'kb' => $kb,
                          'sev' => strtolower(self::clean((string) ($p['severity'] ?? ''), 20)), 'st' => $status, 'det' => $det]);
            $keep[] = (int) $this->db->lastInsertId();
        }
        $this->db->prepare('DELETE FROM device_patches WHERE device_id = ?' . ($keep === [] ? '' : ' AND id NOT IN (' . implode(',', $keep) . ')'))->execute([$deviceId]);
        return count($keep);
    }

    /**
     * Current (not removed) devices of a client, with counts.
     *
     * @return list<array<string,mixed>>
     */
    public function devicesForClient(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT d.*, (SELECT COUNT(*) FROM device_patches p WHERE p.device_id = d.id) AS patch_count,
                    (SELECT COUNT(DISTINCT sv.cve_id) FROM software_vulns sv JOIN device_software s ON s.id = sv.software_id WHERE s.device_id = d.id) AS vuln_count,
                    (SELECT COUNT(*) FROM device_software s WHERE s.device_id = d.id) AS software_count
             FROM devices d WHERE d.client_id = :c AND d.removed_at IS NULL ORDER BY d.name, d.id LIMIT 5000"
        );
        $stmt->execute(['c' => $clientId]);
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
            'SELECT l.* FROM source_links l JOIN clients c ON c.id = l.client_id AND c.is_archived = 0
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
    }

    /** Record the outcome of a sync on the link. */
    public function recordSync(int $clientId, string $source, string $status, string $message): void
    {
        $this->db->prepare('UPDATE source_links SET last_sync_at = UTC_TIMESTAMP(), last_sync_status = :st, last_sync_message = :m WHERE client_id = :c AND source = :s')
            ->execute(['st' => $status, 'm' => mb_substr($message, 0, 500), 'c' => $clientId, 's' => $source]);
    }

    /** Text from a source, without control characters, shortened. */
    public static function clean(string $value, int $max): string
    {
        $value = (string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value);
        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        }
        return trim(mb_substr(trim($value), 0, $max));
    }
}
