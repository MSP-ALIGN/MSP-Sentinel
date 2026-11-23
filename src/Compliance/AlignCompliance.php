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
 * - "clear": Sentinel recently checked that area for this client (checkedAreas: only what a check genuinely assesses)
 *   and has no open problem there. That is not proof the control is met (Sentinel sees only part of it), and the page
 *   says so;
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
    /** After a failed read, MSP Align isn't asked again (on page views) for this long. */
    private const RETRY_SECONDS = 600;
    /** One read of a client's compliance may take at most this long in total. */
    private const BUDGET_SECONDS = 25;
    /** "Checked" only counts recent evidence. */
    private const RECENT_DAYS = 30;

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
                  'encryption_off' => ['ep_encryption', 'data_encrypt_rest'], 'encryption_off_server' => ['ep_encryption', 'data_encrypt_rest'], 'patches_missing' => ['vuln_patch_os', 'vuln_remediation'],
                  'patches_failed' => ['vuln_patch_os', 'vuln_remediation'], '*' => []],
        'devvuln' => ['*' => ['vuln_patch_apps', 'vuln_remediation']],
        'proto' => ['rdp_no_nla' => ['net_remote_access', 'cfg_baseline'], 'http_login' => ['net_encrypt_transit'], '*' => ['cfg_ports_services', 'cfg_baseline']],
        'dport' => ['*' => ['net_encrypt_transit']],
        // Active Directory checks and name poisoning (on-premises agent).
        'ad' => ['asrep' => ['iam_passwords', 'iam_accounts'], 'kerberoast_admin' => ['iam_privileged', 'iam_passwords'], 'kerberoast' => ['iam_passwords'],
                 'unconstrained' => ['iam_least_privilege', 'iam_privileged'], 'admin_never_expires' => ['iam_privileged', 'iam_passwords'],
                 'stale_admins' => ['iam_privileged', 'iam_access_review'], 'domain_admins' => ['iam_privileged', 'iam_least_privilege'], 'krbtgt_old' => ['iam_privileged'],
                 'laps_missing' => ['iam_privileged', 'iam_passwords'], 'ldap_signing' => ['cfg_baseline'], '*' => ['iam_accounts']],
        'names' => ['*' => ['cfg_baseline']],
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
        // A recent failed attempt: show what we have instead of waiting on MSP Align again (unless asked to).
        $recentAttempt = !$refresh && $cached !== null && $cached['attempted_at'] !== '' && strtotime($cached['attempted_at'] . ' UTC') > time() - self::RETRY_SECONDS;
        if ($stale && !$recentAttempt && $this->align !== null && $alignId > 0) {
            $this->db->prepare("INSERT INTO align_cache (client_id, fetched_at, data, attempted_at) VALUES (:c, '2000-01-01 00:00:00', '{}', UTC_TIMESTAMP())
                                ON DUPLICATE KEY UPDATE attempted_at = VALUES(attempted_at)")->execute(['c' => $cid]);
            try {
                $started = microtime(true);
                $frameworks = [];
                foreach ($this->align->assessments($alignId) as $a) {
                    if (microtime(true) - $started > self::BUDGET_SECONDS) {
                        throw new AlignException(__('Reading from MSP Align took too long; try Read again later.'));
                    }
                    $frameworks[] = $a + ['controls' => $this->align->controls($alignId, $a['framework_id'])];
                }
                $json = json_encode(['frameworks' => $frameworks], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
                if ($json === false || strlen($json) > 15000000) {
                    throw new AlignException(__('MSP Align returned more compliance data than Sentinel stores for one client.'));
                }
                $data = ['frameworks' => $frameworks];
                $this->db->prepare('UPDATE align_cache SET fetched_at = UTC_TIMESTAMP(), data = :d WHERE client_id = :c')->execute(['c' => $cid, 'd' => $json]);
                $cached = $this->cached($cid);
            } catch (AlignException $ex) {
                $error = $ex->getMessage();
            }
        } elseif ($stale && $this->align === null) {
            $error = __('MSP Align is not connected (Administration, Integrations).');
        } elseif ($stale && $recentAttempt) {
            $error = __('MSP Align could not be read a few minutes ago; Sentinel tries again in a while (or use Read again).');
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
        $fetched = (string) ($cached['fetched_at'] ?? '');
        return ['frameworks' => $out, 'fetched_at' => str_starts_with($fetched, '2000-') ? '' : $fetched, 'error' => $error, 'checked' => $checked];
    }

    /**
     * What Sentinel has actually checked for this client, by tag, with a short note of how and when. Only tags a
     * check genuinely assesses, and only recent evidence: an external scan sees the internet-facing side (open ports,
     * exposed admin pages, certificates), not MFA, internal patching or hardening, so those tags are never "checked"
     * by it; they can still show open problems from findings.
     *
     * @return array<string,string>
     */
    public function checkedAreas(int $clientId): array
    {
        $one = function (string $sql) use ($clientId): array {
            $stmt = $this->db->prepare($sql);
            $stmt->execute(['c' => $clientId, 'd' => self::RECENT_DAYS]);
            return $stmt->fetch() ?: [];
        };
        $areas = [];
        $add = static function (array $tags, string $label) use (&$areas): void {
            foreach ($tags as $t) {
                $areas[$t] = isset($areas[$t]) ? $areas[$t] . '; ' . $label : $label;
            }
        };
        $scan = $one("SELECT MAX(finished_at) AS at FROM scan_jobs WHERE client_id = :c AND job_type = 'ports' AND status = 'done' AND finished_at > UTC_TIMESTAMP() - INTERVAL :d DAY");
        if (($scan['at'] ?? null) !== null) {
            $add(['cfg_ports_services', 'net_firewall', 'net_encrypt_transit', 'vuln_scan'],
                __('external scan of internet-facing services, {d}', ['d' => substr((string) $scan['at'], 0, 10)]));
        }
        $mail = $one('SELECT MAX(checked_at) AS at FROM email_checks WHERE client_id = :c AND checked_at > UTC_TIMESTAMP() - INTERVAL :d DAY');
        if (($mail['at'] ?? null) !== null) {
            $add(['email_auth'], __('email records (SPF, DMARC), {d}', ['d' => substr((string) $mail['at'], 0, 10)]));
        }
        // Device inventory: only areas every current device reports on (an unknown value is not "fine").
        $dev = $one("SELECT COUNT(*) AS n, MAX(last_seen) AS at, SUM(os_name = '') AS no_os, SUM(av_state = '') AS no_av, SUM(encryption = '') AS no_enc
                     FROM devices WHERE client_id = :c AND removed_at IS NULL AND source <> 'agent' AND last_seen > UTC_TIMESTAMP() - INTERVAL :d DAY");
        if ((int) ($dev['n'] ?? 0) > 0) {
            $label = __('device inventory from NinjaOne ({n} devices), {d}', ['n' => (int) $dev['n'], 'd' => substr((string) $dev['at'], 0, 10)]);
            $add(['vuln_patch_os', 'vuln_patch_apps'], $label);
            if ((int) $dev['no_os'] === 0) {
                $add(['ep_lifecycle'], $label);
            }
            if ((int) $dev['no_av'] === 0) {
                $add(['ep_malware'], $label);
            }
            if ((int) $dev['no_enc'] === 0) {
                $add(['ep_encryption', 'data_encrypt_rest'], $label);
            }
        }
        $agent = $one("SELECT MAX(last_full_seen) AS at FROM devices WHERE client_id = :c AND removed_at IS NULL AND source = 'agent' AND last_full_seen > UTC_TIMESTAMP() - INTERVAL :d DAY");
        if (($agent['at'] ?? null) !== null) {
            $add(['cfg_ports_services', 'net_encrypt_transit'], __('internal scan, {d}', ['d' => substr((string) $agent['at'], 0, 10)]));
        }
        // A recent successful directory read assesses the privileged accounts (not the whole password policy or MFA).
        $dir = $one('SELECT MAX(checked_at) AS at FROM site_directory WHERE client_id = :c AND checked_at > UTC_TIMESTAMP() - INTERVAL :d DAY');
        if (($dir['at'] ?? null) !== null) {
            $add(['iam_privileged'], __('Active Directory read by the agent, {d}', ['d' => substr((string) $dir['at'], 0, 10)]));
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

    /** @return array{fetched_at:string, data:array<mixed>, attempted_at:string}|null */
    private function cached(int $clientId): ?array
    {
        $stmt = $this->db->prepare('SELECT fetched_at, data, attempted_at FROM align_cache WHERE client_id = :c');
        $stmt->execute(['c' => $clientId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        $data = json_decode((string) $row['data'], true);
        return ['fetched_at' => (string) $row['fetched_at'], 'data' => is_array($data) ? $data : [], 'attempted_at' => (string) ($row['attempted_at'] ?? '')];
    }
}
