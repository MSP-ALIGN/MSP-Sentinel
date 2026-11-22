<?php

declare(strict_types=1);

namespace Sentinel\Compliance;

use PDO;

/**
 * A client's compliance frameworks from MSP Align, with what Sentinel knows about each control. Read-only: nothing
 * is written to MSP Align; the vCIO keeps deciding each control's status there.
 *
 * How findings meet controls: MSP Align tags every control with crosswalk tags from a fixed vocabulary (its
 * db/frameworks/README.md), shared across frameworks. Sentinel maps each kind of finding to those tags once (TAGS
 * below), so the same mapping works for CIS, NIST CSF, HIPAA, CMMC, ISO 27001, PCI DSS, SOC 2, cyber insurance...
 *
 * Honest by design, per control:
 * - "issues": open Sentinel findings in an area the control is about (listed, worst first);
 * - "clear": Sentinel checked that area for this client and has no open problem there. That is not proof the control
 *   is met (Sentinel sees only part of it), and the page says so;
 * - "not_checked": the control is in an area Sentinel covers, but it hasn't checked it for this client yet (for
 *   example no devices from NinjaOne, or no scan yet);
 * Controls outside Sentinel's areas (policies, training, physical security...) are counted, not listed.
 *
 * MSP Align is read at most once an hour per client (cached in align_cache), or when someone asks to refresh.
 *
 * Untrusted input: everything from MSP Align (AlignClient casts it; views escape it).
 */
final class AlignCompliance
{
    /** Cached answers are reused for this long. */
    private const CACHE_SECONDS = 3600;

    /**
     * Crosswalk tags per kind of finding: by finding-key prefix, and where it matters by the finding's code.
     *
     * @var array<string, array<string, list<string>>>
     */
    private const TAGS = [
        'port' => ['*' => ['cfg_ports_services', 'net_firewall']],
        'tls' => ['*' => ['net_encrypt_transit']],
        'web' => ['firewall_admin' => ['net_firewall', 'cfg_ports_services'], 'device_admin' => ['net_firewall', 'cfg_ports_services'],
                  'vpn_portal' => ['net_remote_access', 'iam_mfa_remote'], 'remote_desktop_web' => ['net_remote_access', 'iam_mfa_remote'], '*' => ['cfg_ports_services']],
        'site' => ['login_over_http' => ['net_encrypt_transit'], 'no_https_redirect' => ['net_encrypt_transit'], 'missing_hsts' => ['net_encrypt_transit'],
                   'insecure_cookies' => ['net_encrypt_transit', 'cfg_baseline'], '*' => ['cfg_baseline']],
        'vuln' => ['*' => ['vuln_scan', 'vuln_remediation', 'vuln_patch_apps']],
        'webvuln' => ['*' => ['vuln_scan', 'vuln_remediation', 'vuln_patch_apps']],
        'email' => ['*' => ['email_auth']],
        'dev' => ['os_unsupported' => ['ep_lifecycle'], 'av_missing' => ['ep_malware', 'ep_edr'], 'av_off' => ['ep_malware', 'ep_edr'], 'av_outdated' => ['ep_malware'],
                  'encryption_off' => ['ep_encryption', 'data_encrypt_rest'], 'patches_missing' => ['vuln_patch_os', 'vuln_remediation'],
                  'patches_failed' => ['vuln_patch_os', 'vuln_remediation'], '*' => []],
        'devvuln' => ['*' => ['vuln_patch_apps', 'vuln_remediation']],
        'proto' => ['rdp_no_nla' => ['net_remote_access', 'cfg_baseline'], 'http_login' => ['net_encrypt_transit'], '*' => ['cfg_ports_services', 'cfg_baseline']],
        'dport' => ['*' => ['net_encrypt_transit']],
    ];

    /** Remote-access ports: an exposed one also concerns secure remote access. */
    private const REMOTE_PORTS = [22, 23, 3389, 5900, 5901, 5938];

    public function __construct(private readonly PDO $db, private readonly ?AlignClient $align)
    {
    }

    /** Every tag Sentinel can say something about. @return list<string> */
    public static function coveredTags(): array
    {
        $all = ['net_remote_access'];
        foreach (self::TAGS as $codes) {
            foreach ($codes as $tags) {
                array_push($all, ...$tags);
            }
        }
        return array_values(array_unique($all));
    }

    /**
     * Tags a finding concerns, from its key ("port:203.0.113.5:3389", "dev:ninjaone:12:av_off", ...).
     *
     * @return list<string>
     */
    public static function tagsFor(string $findingKey): array
    {
        $parts = explode(':', $findingKey);
        $kind = $parts[0];
        if (!isset(self::TAGS[$kind])) {
            return [];
        }
        $code = (string) end($parts);
        $tags = self::TAGS[$kind][$code] ?? self::TAGS[$kind]['*'] ?? [];
        if ($kind === 'web' && isset($parts[3])) {
            $tags = self::TAGS['web'][$parts[3]] ?? self::TAGS['web']['*'];
        }
        if ($kind === 'port' && in_array((int) $code, self::REMOTE_PORTS, true)) {
            $tags[] = 'net_remote_access';
        }
        return array_values(array_unique($tags));
    }

    /**
     * The Compliance page data for a linked client: frameworks from MSP Align (cached), each control's Sentinel view.
     *
     * @param array<string,mixed> $client
     * @return array{frameworks:list<array<string,mixed>>, fetched_at:string, error:string, checked:array<string,string>}
     */
    public function forClient(array $client, bool $refresh = false): array
    {
        $cid = (int) $client['id'];
        $alignId = (int) ($client['align_client_id'] ?? 0);
        $cached = $this->cached($cid);
        $error = '';
        $data = $cached['data'] ?? null;
        $stale = $cached === null || $refresh || strtotime($cached['fetched_at'] . ' UTC') < time() - self::CACHE_SECONDS;
        if ($stale && $this->align !== null && $alignId > 0) {
            try {
                $frameworks = [];
                foreach ($this->align->assessments($alignId) as $a) {
                    $frameworks[] = $a + ['controls' => $this->align->controls($alignId, $a['framework_id'])];
                }
                $data = ['frameworks' => $frameworks];
                $this->db->prepare('INSERT INTO align_cache (client_id, fetched_at, data) VALUES (:c, UTC_TIMESTAMP(), :d)
                                    ON DUPLICATE KEY UPDATE fetched_at = VALUES(fetched_at), data = VALUES(data)')
                    ->execute(['c' => $cid, 'd' => json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)]);
                $cached = $this->cached($cid);
            } catch (AlignException $ex) {
                $error = $ex->getMessage();
            }
        } elseif ($stale && $this->align === null) {
            $error = __('MSP Align is not connected (Administration, Integrations).');
        }
        $checked = $this->checkedAreas($cid);
        $findings = $this->openFindings($cid);
        $out = [];
        foreach ((array) ($data['frameworks'] ?? []) as $f) {
            $rows = [];
            $outside = 0;
            foreach ((array) ($f['controls'] ?? []) as $c) {
                $tags = array_values(array_intersect((array) ($c['tags'] ?? []), self::coveredTags()));
                if ($tags === []) {
                    $outside++;
                    continue;
                }
                $hits = array_values(array_filter($findings, static fn (array $x): bool => array_intersect($x['tags'], $tags) !== []));
                $areas = array_values(array_unique(array_map(static fn (string $t): string => $checked[$t], array_filter($tags, static fn (string $t): bool => isset($checked[$t])))));
                $rows[] = $c + [
                    'sentinel' => $hits !== [] ? 'issues' : ($areas !== [] ? 'clear' : 'not_checked'),
                    'findings' => array_slice($hits, 0, 10), 'finding_count' => count($hits), 'areas' => $areas,
                ];
            }
            $out[] = ['framework_id' => (int) ($f['framework_id'] ?? 0), 'framework' => (string) ($f['framework'] ?? ''), 'score' => (int) ($f['score'] ?? 0),
                      'url' => (string) ($f['url'] ?? ''), 'controls' => $rows, 'outside' => $outside,
                      'issues' => count(array_filter($rows, static fn ($r) => $r['sentinel'] === 'issues'))];
        }
        return ['frameworks' => $out, 'fetched_at' => (string) ($cached['fetched_at'] ?? ''), 'error' => $error, 'checked' => $checked];
    }

    /**
     * What Sentinel has actually checked for this client, by tag (with a short description of how).
     *
     * @return array<string,string>
     */
    public function checkedAreas(int $clientId): array
    {
        $q = fn (string $sql): int => (int) $this->db->query(str_replace(':c', (string) $clientId, $sql))->fetchColumn();
        $areas = [];
        if ($q("SELECT COUNT(*) FROM scan_jobs WHERE client_id = :c AND job_type = 'ports' AND status IN ('done','partial')") > 0) {
            foreach (['cfg_ports_services', 'net_firewall', 'net_remote_access', 'iam_mfa_remote', 'net_encrypt_transit', 'vuln_scan', 'vuln_remediation', 'cfg_baseline'] as $t) {
                $areas[$t] = __('external scan');
            }
            $areas['vuln_patch_apps'] = __('external scan');
        }
        if ($q('SELECT COUNT(*) FROM email_checks WHERE client_id = :c') > 0) {
            $areas['email_auth'] = __('email records (SPF, DMARC)');
        }
        if ($q("SELECT COUNT(*) FROM devices WHERE client_id = :c AND removed_at IS NULL AND source <> 'agent'") > 0) {
            foreach (['ep_lifecycle', 'ep_malware', 'ep_edr', 'ep_encryption', 'data_encrypt_rest', 'vuln_patch_os', 'vuln_patch_apps', 'vuln_remediation'] as $t) {
                $areas[$t] = __('device inventory (NinjaOne)');
            }
        }
        if ($q("SELECT COUNT(*) FROM devices WHERE client_id = :c AND removed_at IS NULL AND source = 'agent' AND last_full_seen IS NOT NULL") > 0) {
            foreach (['cfg_ports_services', 'cfg_baseline', 'net_remote_access', 'net_encrypt_transit'] as $t) {
                $areas[$t] = isset($areas[$t]) ? $areas[$t] . ', ' . __('internal scan') : __('internal scan');
            }
        }
        return $areas;
    }

    /** @return list<array{id:int, title:string, severity:string, target:string, tags:list<string>}> */
    private function openFindings(int $clientId): array
    {
        $stmt = $this->db->prepare("SELECT id, finding_key, title, severity, target FROM findings WHERE client_id = :c AND status = 'open' ORDER BY severity = 'fail' DESC, id");
        $stmt->execute(['c' => $clientId]);
        $out = [];
        foreach ($stmt->fetchAll() as $r) {
            $tags = self::tagsFor((string) $r['finding_key']);
            if ($tags !== []) {
                $out[] = ['id' => (int) $r['id'], 'title' => (string) $r['title'], 'severity' => (string) $r['severity'], 'target' => (string) $r['target'], 'tags' => $tags];
            }
        }
        return $out;
    }

    /** @return array{fetched_at:string, data:array<mixed>}|null */
    private function cached(int $clientId): ?array
    {
        $stmt = $this->db->prepare('SELECT fetched_at, data FROM align_cache WHERE client_id = :c');
        $stmt->execute(['c' => $clientId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $data = json_decode((string) $row['data'], true);
        return ['fetched_at' => (string) $row['fetched_at'], 'data' => is_array($data) ? $data : []];
    }
}
