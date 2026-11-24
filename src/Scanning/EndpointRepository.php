<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use PDO;

/**
 * Database access for TLS endpoints and web pages.
 *
 * Security assumptions: values come from TlsChecker and HttpProbe, already
 * cleaned and length-limited. All queries use bound parameters.
 */
final class EndpointRepository
{
    /** TLS ports checked even when nmap couldn't name the service. */
    public const TLS_PORTS = [443, 465, 636, 993, 995, 4433, 4443, 5986, 8443, 9443, 10443];
    /** Web ports fetched for admin-page detection. */
    public const WEB_PORTS = [80, 443, 4433, 4443, 8000, 8080, 8081, 8443, 8888, 9000, 9443, 10000, 10443];

    /** Works on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /** True if an open service on this port is (probably) TLS. */
    public static function isTls(int $port, string $serviceName): bool
    {
        return in_array($port, self::TLS_PORTS, true) || preg_match('/https|ssl|tls/i', $serviceName) === 1;
    }

    /** True if this port should be fetched as a web page. */
    public static function isWeb(int $port, string $serviceName): bool
    {
        return in_array($port, self::WEB_PORTS, true) || preg_match('/^(http|https|ssl\/http|http-alt|http-proxy)/i', $serviceName) === 1;
    }

    /**
     * Hostnames stored on an asset (names that resolved to it in earlier scans).
     *
     * @return list<string>
     */
    public function assetHostnames(int $assetId): array
    {
        $stmt = $this->db->prepare('SELECT hostnames FROM assets WHERE id = :id');
        $stmt->execute(['id' => $assetId]);
        return array_values(array_filter(explode(',', (string) $stmt->fetchColumn())));
    }

    /** The asset ID of a client's address, or null. */
    public function assetId(int $clientId, string $ip): ?int
    {
        $stmt = $this->db->prepare('SELECT id FROM assets WHERE client_id = :c AND ip = :ip');
        $stmt->execute(['c' => $clientId, 'ip' => $ip]);
        $id = $stmt->fetchColumn();
        return $id === false ? null : (int) $id;
    }

    /**
     * Save a TLS check result (insert or update).
     *
     * @param array<string,mixed> $r Result from TlsChecker::check (+ probeProtocols fields).
     */
    public function saveTls(int $assetId, int $port, string $sni, array $r): void
    {
        $cols = ['subject_cn', 'sans', 'issuer', 'not_before', 'not_after', 'self_signed', 'chain_trusted', 'hostname_match',
                 'key_type', 'key_bits', 'signature_alg', 'protocol', 'accepts_tls10', 'accepts_tls11'];
        $values = ['a' => $assetId, 'p' => $port, 'sni' => $sni, 'err' => (string) ($r['error'] ?? '')];
        $sets = [];
        foreach ($cols as $c) {
            $values[$c] = $r[$c] ?? null;
            if ($c === 'accepts_tls10' || $c === 'accepts_tls11') {
                // Probes run once per endpoint: keep the previous answer when this check didn't probe.
                $sets[] = "{$c} = IFNULL(VALUES({$c}), {$c})";
            } elseif (!($r['ok'] ?? false)) {
                continue; // a failed check keeps the last known certificate details, and only records the error
            } else {
                $sets[] = "{$c} = VALUES({$c})";
            }
        }
        foreach (['subject_cn', 'sans', 'issuer', 'key_type', 'signature_alg', 'protocol'] as $c) {
            $values[$c] ??= '';
        }
        $sql = 'INSERT INTO tls_endpoints (asset_id, port, sni, ' . implode(', ', $cols) . ', last_error, first_seen, last_checked)
                VALUES (:a, :p, :sni, :' . implode(', :', $cols) . ', :err, UTC_TIMESTAMP(), UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE ' . implode(', ', array_merge($sets, ['last_error = VALUES(last_error)', 'last_checked = UTC_TIMESTAMP()']));
        $this->db->prepare($sql)->execute($values);
    }

    /**
     * Remove TLS rows for names no longer used on this endpoint (for example the
     * name-less row after a hostname was added to scope), so stale certificates
     * can't cause false alarms.
     *
     * @param list<string> $keepSnis The SNI values just checked ('' = no SNI).
     */
    public function pruneTls(int $assetId, int $port, array $keepSnis): void
    {
        $placeholders = implode(',', array_fill(0, count($keepSnis), '?'));
        $this->db->prepare("DELETE FROM tls_endpoints WHERE asset_id = ? AND port = ? AND sni NOT IN ({$placeholders})")
            ->execute(array_merge([$assetId, $port], $keepSnis));
    }

    /**
     * Save a web page check result (insert or update).
     *
     * @param array<string,mixed> $r Result from HttpProbe::fetch.
     */
    public function saveWeb(int $assetId, int $port, array $r): void
    {
        $this->db->prepare(
            'INSERT INTO web_pages (asset_id, port, scheme, host_header, status_code, title, server_header, redirect_to, category, matched, last_error, first_seen, last_checked)
             VALUES (:a, :p, :s, :h, :st, :t, :sv, :r, :c, :m, :e, UTC_TIMESTAMP(), UTC_TIMESTAMP())
             ON DUPLICATE KEY UPDATE scheme = VALUES(scheme), host_header = VALUES(host_header),
                status_code = IF(VALUES(status_code) IS NULL, status_code, VALUES(status_code)),
                title = IF(VALUES(status_code) IS NULL, title, VALUES(title)),
                server_header = IF(VALUES(status_code) IS NULL, server_header, VALUES(server_header)),
                redirect_to = IF(VALUES(status_code) IS NULL, redirect_to, VALUES(redirect_to)),
                category = IF(VALUES(status_code) IS NULL, category, VALUES(category)),
                matched = IF(VALUES(status_code) IS NULL, matched, VALUES(matched)),
                last_error = VALUES(last_error), last_checked = UTC_TIMESTAMP()'
        )->execute([
            'a' => $assetId, 'p' => $port, 's' => $r['scheme'], 'h' => (string) ($r['host_header'] ?? ''),
            'st' => $r['status_code'] ?? null, 't' => (string) ($r['title'] ?? ''), 'sv' => (string) ($r['server_header'] ?? ''),
            'r' => (string) ($r['redirect_to'] ?? ''), 'c' => $r['category'] ?? null, 'm' => (string) ($r['matched'] ?? ''),
            'e' => (string) ($r['last_error'] ?? ''),
        ]);
    }

    /**
     * TLS endpoints of a client whose service is currently open.
     *
     * @return list<array<string,mixed>>
     */
    public function tlsForClient(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT t.*, a.ip FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id
             JOIN services s ON s.asset_id = t.asset_id AND s.port = t.port AND s.protocol = 'tcp' AND s.is_open = 1
             WHERE a.client_id = :c ORDER BY t.not_after IS NULL, t.not_after, INET6_ATON(a.ip), t.port, t.sni"
        );
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Web pages of a client whose service is currently open.
     *
     * @return list<array<string,mixed>>
     */
    public function webForClient(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT w.*, a.ip FROM web_pages w JOIN assets a ON a.id = w.asset_id
             JOIN services s ON s.asset_id = w.asset_id AND s.port = w.port AND s.protocol = 'tcp' AND s.is_open = 1
             WHERE a.client_id = :c ORDER BY w.category IS NULL, INET6_ATON(a.ip), w.port"
        );
        $stmt->execute(['c' => $clientId]);
        return $stmt->fetchAll();
    }

    /**
     * Open TLS/web endpoints of a client, for the daily check job.
     *
     * @return list<array{ip:string,port:int,service:string,hostnames:list<string>}>
     */
    public function checkableEndpoints(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT a.ip, a.hostnames, s.port, s.service_name FROM services s JOIN assets a ON a.id = s.asset_id
             WHERE a.client_id = :c AND s.is_open = 1 AND s.protocol = 'tcp' ORDER BY INET6_ATON(a.ip), s.port"
        );
        $stmt->execute(['c' => $clientId]);
        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            $port = (int) $row['port'];
            if (self::isTls($port, (string) $row['service_name']) || self::isWeb($port, (string) $row['service_name'])) {
                $out[] = ['ip' => (string) $row['ip'], 'port' => $port, 'service' => (string) $row['service_name'],
                          'hostnames' => array_values(array_filter(explode(',', (string) $row['hostnames'])))];
            }
        }
        return $out;
    }

    /**
     * Number of TLS endpoints (open, non-archived clients) whose certificate is
     * expired or has $days whole days or fewer left: the same boundary as ExposureRules.
     */
    public function countExpiring(int $days): int
    {
        $stmt = $this->db->prepare(
            "SELECT COUNT(DISTINCT t.asset_id, t.port) FROM tls_endpoints t JOIN assets a ON a.id = t.asset_id JOIN clients c ON c.id = a.client_id AND c.is_archived = 0
             JOIN services s ON s.asset_id = t.asset_id AND s.port = t.port AND s.protocol = 'tcp' AND s.is_open = 1
             WHERE t.not_after IS NOT NULL AND t.not_after < UTC_TIMESTAMP() + INTERVAL (:d + 1) DAY"
        );
        $stmt->bindValue('d', $days, PDO::PARAM_INT);
        $stmt->execute();
        return (int) $stmt->fetchColumn();
    }
}
