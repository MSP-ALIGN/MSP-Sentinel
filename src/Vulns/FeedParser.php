<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

/**
 * Parses NVD CVE API 2.0 pages, the CISA KEV catalog and FIRST EPSS
 * responses into small validated arrays.
 *
 * Security assumptions: all input is untrusted JSON. Every field is
 * type-checked, IDs must look like CVE IDs, text is stripped of control
 * characters and length-limited, numbers are clamped to sensible ranges,
 * and anything malformed is skipped rather than guessed.
 */
final class FeedParser
{
    /**
     * One NVD API page.
     *
     * virtualMatchString also returns CVEs where the product is only the
     * platform something else runs on ("vulnerable": false). When
     * $productPrefix is given (e.g. "cpe:2.3:a:openbsd:openssh:"), only CVEs
     * with a configuration marking THAT product as vulnerable are kept.
     *
     * @param array<mixed> $page Decoded JSON.
     * @param string|null $productPrefix vendor:product prefix that must be marked vulnerable.
     * Each CVE also gets 'platforms' (1.49): the operating systems the product is only vulnerable on (e.g. Chrome
     * "running on" Android), or [] when it is vulnerable whatever it runs on. See platformsFor().
     *
     * @return array{total:int, cves:list<array{cve_id:string,summary:string,cvss_score:?float,cvss_severity:string,cvss_version:string,published:?string,last_modified:?string,platforms:list<string>}>}
     */
    public static function nvdPage(array $page, ?string $productPrefix = null): array
    {
        $out = [];
        foreach ((array) ($page['vulnerabilities'] ?? []) as $item) {
            $cve = is_array($item) ? ($item['cve'] ?? null) : null;
            if (!is_array($cve) || !is_string($cve['id'] ?? null) || !Cpe::isCveId($cve['id'])) {
                continue;
            }
            if (($cve['vulnStatus'] ?? '') === 'Rejected') {
                continue;
            }
            if ($productPrefix !== null && !self::marksVulnerable((array) ($cve['configurations'] ?? []), $productPrefix)) {
                continue;
            }
            $summary = '';
            foreach ((array) ($cve['descriptions'] ?? []) as $d) {
                if (is_array($d) && ($d['lang'] ?? '') === 'en' && is_string($d['value'] ?? null)) {
                    $summary = $d['value'];
                    break;
                }
            }
            [$score, $severity, $version] = self::cvss((array) ($cve['metrics'] ?? []));
            $out[] = [
                'cve_id' => $cve['id'],
                'summary' => self::clean($summary, 1000),
                'cvss_score' => $score,
                'cvss_severity' => $severity,
                'cvss_version' => $version,
                'published' => self::date($cve['published'] ?? null),
                'last_modified' => self::dateTime($cve['lastModified'] ?? null),
                'platforms' => $productPrefix !== null ? self::platformsFor((array) ($cve['configurations'] ?? []), $productPrefix) : [],
            ];
        }
        return ['total' => max(0, (int) ($page['totalResults'] ?? 0)), 'cves' => $out];
    }

    /**
     * True if any configuration node marks a CPE with this vendor:product prefix as vulnerable.
     *
     * @param array<mixed> $configurations
     */
    private static function marksVulnerable(array $configurations, string $productPrefix): bool
    {
        $prefix = strtolower($productPrefix);
        $stack = $configurations;
        $seen = 0;
        while ($stack !== [] && $seen++ < 10000) {
            $item = array_pop($stack);
            if (!is_array($item)) {
                continue;
            }
            foreach ((array) ($item['cpeMatch'] ?? []) as $m) {
                if (is_array($m) && ($m['vulnerable'] ?? false) === true && is_string($m['criteria'] ?? null)
                    && str_starts_with(strtolower($m['criteria']), $prefix)) {
                    return true;
                }
            }
            foreach (['nodes', 'children'] as $key) {
                foreach ((array) ($item[$key] ?? []) as $child) {
                    $stack[] = $child;
                }
            }
        }
        return false;
    }

    /**
     * The platforms (OS families) a product is only vulnerable on, from NVD's configurations (1.49). NVD writes
     * "Chrome on Android" as a configuration with operator AND: one node marks the product vulnerable, another lists
     * the OS it runs on (vulnerable: false). The product's own CPE can also name a platform in its target_sw field.
     * Returns [] as soon as ONE configuration marks the product vulnerable without such a limit (vulnerable
     * everywhere), else the families of every limit found (windows, macos, linux, android, ios, chromeos, or another
     * NVD OS product name). Untrusted JSON: only strings are read; anything odd counts as "no limit" (the old,
     * stricter behaviour), never as a reason to drop a CVE.
     *
     * @param array<mixed> $configurations
     * @return list<string>
     */
    public static function platformsFor(array $configurations, string $productPrefix): array
    {
        $prefix = strtolower($productPrefix);
        $limits = [];
        $found = false;
        foreach (array_slice($configurations, 0, 500) as $conf) {
            if (!is_array($conf)) {
                continue;
            }
            $nodes = array_values(array_filter((array) ($conf['nodes'] ?? []), 'is_array'));
            // A negated node ("NOT running on ...", 1.49.1) can't be read as a positive limit: no limit, as before.
            foreach ($nodes as $node) {
                if (($node['negate'] ?? false) === true) {
                    $hasProduct = false;
                    foreach ($nodes as $n2) {
                        foreach ((array) ($n2['cpeMatch'] ?? []) as $m) {
                            $hasProduct = $hasProduct || (is_array($m) && ($m['vulnerable'] ?? false) === true && is_string($m['criteria'] ?? null) && str_starts_with(strtolower($m['criteria']), $prefix));
                        }
                    }
                    if ($hasProduct) {
                        return [];
                    }
                }
            }
            $here = [];      // limits from this configuration
            $vulnHere = false;
            $targetLimited = true; // every vulnerable product match here names a platform in target_sw
            foreach ($nodes as $node) {
                foreach ((array) ($node['cpeMatch'] ?? []) as $m) {
                    if (!is_array($m) || !is_string($m['criteria'] ?? null)) {
                        continue;
                    }
                    $crit = strtolower($m['criteria']);
                    if (($m['vulnerable'] ?? false) === true && str_starts_with($crit, $prefix)) {
                        $vulnHere = true;
                        $target = self::cpeFields($crit)[10] ?? '*';
                        // Only an operating system counts as a limit (1.49.1): "node.js" or "wordpress" is the
                        // software it runs in, not an OS, so it limits nothing.
                        $family = ($target === '*' || $target === '-' || $target === '') ? '' : self::platformFamily('', $target);
                        if ($family === '') {
                            $targetLimited = false;
                        } else {
                            $here[$family] = true;
                        }
                    }
                }
            }
            if (!$vulnHere) {
                continue;
            }
            $found = true;
            if (strtoupper((string) ($conf['operator'] ?? '')) === 'AND' && count($nodes) > 1) {
                $os = [];
                foreach ($nodes as $node) {
                    foreach ((array) ($node['cpeMatch'] ?? []) as $m) {
                        if (is_array($m) && ($m['vulnerable'] ?? false) !== true && is_string($m['criteria'] ?? null)
                            && str_starts_with(strtolower($m['criteria']), 'cpe:2.3:o:')) {
                            $f = self::cpeFields(strtolower($m['criteria']));
                            $os[self::platformFamily($f[3] ?? '', $f[4] ?? '')] = true;
                        }
                    }
                }
                // An OS this code doesn't know as a family counts as "no limit" (never a reason to drop a CVE).
                if ($os !== [] && !isset($os[''])) {
                    $limits += $os;
                    continue;
                }
            }
            if (!$targetLimited) {
                return []; // vulnerable whatever it runs on
            }
            $limits += $here;
        }
        if (!$found) {
            return [];
        }
        $out = array_keys($limits);
        sort($out);
        return $out;
    }

    /**
     * An NVD OS product (vendor and product) or target_sw value as a platform family: windows, macos, linux, android,
     * ios or chromeos, or '' for anything else (1.49.1: only known operating systems limit a CVE; "node.js", a CMS or
     * another vendor's "ios" limit nothing).
     */
    public static function platformFamily(string $vendor, string $name): string
    {
        $v = strtolower(trim($vendor));
        $n = strtolower(trim($name));
        return match (true) {
            $n === '' => '',
            str_starts_with($n, 'windows') => 'windows',
            str_starts_with($n, 'mac_os') || in_array($n, ['macos', 'macosx', 'mac'], true) => 'macos',
            in_array($n, ['iphone_os', 'ipados'], true) || ($n === 'ios' && in_array($v, ['', 'apple'], true)) => 'ios',
            $n === 'android' => 'android',
            in_array($n, ['chrome_os', 'chromeos'], true) => 'chromeos',
            str_contains($n, 'linux') || in_array($n, ['ubuntu', 'debian', 'fedora', 'centos', 'rhel', 'suse'], true) => 'linux',
            default => '',
        };
    }

    /** The fields of a CPE 2.3 string, honouring backslash-escaped colons inside a field (1.49.1). @return list<string> */
    private static function cpeFields(string $cpe): array
    {
        return preg_split('/(?<!\\\\):/', $cpe) ?: [];
    }

    /**
     * The platform family of a device's operating system name (as an inventory source reports it), or '' when unknown.
     */
    public static function osFamily(string $osName): string
    {
        $n = strtolower($osName);
        return match (true) {
            $n === '' => '',
            str_contains($n, 'windows') => 'windows',
            str_contains($n, 'ipados') || (preg_match('/\\bios\\b/', $n) === 1 && preg_match('/cisco|ios[ -]?x[er]|\\bnx-os/', $n) !== 1) => 'ios',
            str_contains($n, 'macos') || str_contains($n, 'mac os') || preg_match('/\\bos x\\b/', $n) === 1 => 'macos',
            str_contains($n, 'android') => 'android',
            str_contains($n, 'chrome os') || str_contains($n, 'chromeos') => 'chromeos',
            preg_match('/linux|ubuntu|debian|centos|red hat|rhel|fedora|suse|rocky|alma/', $n) === 1 => 'linux',
            default => '',
        };
    }

    /**
     * Best available CVSS base score: v3.1, then v4.0, v3.0, v2. Primary (NVD) metrics are preferred.
     *
     * @param array<mixed> $metrics
     * @return array{0:?float,1:string,2:string}
     */
    private static function cvss(array $metrics): array
    {
        foreach (['cvssMetricV31' => '3.1', 'cvssMetricV40' => '4.0', 'cvssMetricV30' => '3.0', 'cvssMetricV2' => '2.0'] as $key => $version) {
            $list = $metrics[$key] ?? null;
            if (!is_array($list) || $list === []) {
                continue;
            }
            usort($list, static fn ($a, $b): int => (($b['type'] ?? '') === 'Primary') <=> (($a['type'] ?? '') === 'Primary'));
            $data = $list[0]['cvssData'] ?? null;
            if (!is_array($data) || !is_numeric($data['baseScore'] ?? null)) {
                continue;
            }
            $score = max(0.0, min(10.0, round((float) $data['baseScore'], 1)));
            $severity = strtoupper((string) ($data['baseSeverity'] ?? $list[0]['baseSeverity'] ?? ''));
            if (!in_array($severity, ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], true)) {
                $severity = self::severityFor($score);
            }
            return [$score, $severity, $version];
        }
        return [null, '', ''];
    }

    /** CVSS v3 severity bands for a score. */
    public static function severityFor(float $score): string
    {
        return match (true) {
            $score >= 9.0 => 'CRITICAL',
            $score >= 7.0 => 'HIGH',
            $score >= 4.0 => 'MEDIUM',
            $score > 0.0 => 'LOW',
            default => 'NONE',
        };
    }

    /**
     * The CISA KEV catalog.
     *
     * @param array<mixed> $feed
     * @return list<array{cve_id:string,vendor:string,product:string,name:string,date_added:?string,due_date:?string,ransomware:string,required_action:string}>
     */
    public static function kev(array $feed): array
    {
        $out = [];
        foreach ((array) ($feed['vulnerabilities'] ?? []) as $v) {
            if (!is_array($v) || !is_string($v['cveID'] ?? null) || !Cpe::isCveId($v['cveID'])) {
                continue;
            }
            $out[$v['cveID']] = [
                'cve_id' => $v['cveID'],
                'vendor' => self::clean((string) ($v['vendorProject'] ?? ''), 200),
                'product' => self::clean((string) ($v['product'] ?? ''), 200),
                'name' => self::clean((string) ($v['vulnerabilityName'] ?? ''), 300),
                'date_added' => self::date($v['dateAdded'] ?? null),
                'due_date' => self::date($v['dueDate'] ?? null),
                'ransomware' => self::clean((string) ($v['knownRansomwareCampaignUse'] ?? ''), 20),
                'required_action' => self::clean((string) ($v['requiredAction'] ?? ''), 500),
            ];
        }
        return array_values($out);
    }

    /**
     * A FIRST EPSS API response.
     *
     * @param array<mixed> $response
     * @return list<array{cve_id:string,score:float,percentile:float,score_date:?string}>
     */
    public static function epss(array $response): array
    {
        $out = [];
        foreach ((array) ($response['data'] ?? []) as $row) {
            if (!is_array($row) || !is_string($row['cve'] ?? null) || !Cpe::isCveId($row['cve'])
                || !is_numeric($row['epss'] ?? null) || !is_numeric($row['percentile'] ?? null)) {
                continue;
            }
            $out[] = [
                'cve_id' => $row['cve'],
                'score' => max(0.0, min(1.0, (float) $row['epss'])),
                'percentile' => max(0.0, min(1.0, (float) $row['percentile'])),
                'score_date' => self::date($row['date'] ?? null),
            ];
        }
        return $out;
    }

    /** Y-m-d from an ISO date or date-time string, or null. */
    private static function date(mixed $value): ?string
    {
        return is_string($value) && preg_match('/^(\d{4}-\d{2}-\d{2})/', $value, $m) && checkdate((int) substr($m[1], 5, 2), (int) substr($m[1], 8, 2), (int) substr($m[1], 0, 4)) ? $m[1] : null;
    }

    /** Y-m-d H:i:s from an ISO date-time string, or null. */
    private static function dateTime(mixed $value): ?string
    {
        $d = self::date($value);
        if ($d === null) {
            return null;
        }
        return is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}T(\d{2}:\d{2}:\d{2})/', $value, $m) ? $d . ' ' . $m[1] : $d . ' 00:00:00';
    }

    /** Remove control characters and invalid UTF-8, then cut to $max characters. */
    private static function clean(string $value, int $max): string
    {
        $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        return mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value)), 0, $max);
    }
}
