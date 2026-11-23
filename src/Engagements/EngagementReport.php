<?php

declare(strict_types=1);

namespace Sentinel\Engagements;

use DateTimeImmutable;
use DateTimeZone;

/**
 * The pen-test report and the retest letter of an engagement, as a frozen snapshot (stored with the rendered HTML,
 * like every report: it never changes after it is issued).
 *
 * The report: executive summary (counts, rating, the most serious findings), scope and authorisation (targets,
 * exclusions, window, who signed and the document's SHA-256, who created and approved it, a stop if there was one),
 * method (tests, intensity, what was never done), how findings chain together (attack paths), every finding with its
 * evidence and fix, the hosts tested, and limitations.
 * The retest letter (an engagement that retests an earlier one, with its own signed authorisation and window):
 * each Fail or Warning of the earlier engagement's report is fixed (its host was tested again and the finding is
 * gone), still open, or not retested (its host was not tested again).
 *
 * Untrusted: evidence from the tested hosts and names typed into forms; the template escapes everything.
 */
final class EngagementReport
{
    /**
     * @param array<string,mixed> $engagement EngagementRepository::find()
     * @param array<string,mixed> $client
     * @param list<array<string,mixed>> $results
     * @param array<string,mixed> $brand ReportBuilder::brand()
     * @param array<string,string> $siteNames
     * @param array<string,string> $testLabels
     * @param array<string,mixed>|null $original the earlier engagement's report snapshot (retest letters)
     * @return array<string,mixed>
     */
    public static function build(array $engagement, array $client, array $results, array $brand, array $siteNames, array $testLabels, string $generatedBy, ?array $original = null): array
    {
        $tz = new DateTimeZone((string) $client['timezone']);
        $local = static fn (?string $utc): string => $utc === null ? '' : (new DateTimeImmutable($utc, new DateTimeZone('UTC')))->setTimezone($tz)->format('Y-m-d H:i');
        $findings = EngagementFindings::analyse($results);
        $counts = EngagementFindings::counts($findings);
        $scope = ['external' => [], 'internal' => [], 'exclude' => []];
        foreach ($engagement['targets'] as $t) {
            $scope[$t['kind']][] = $t['kind'] === 'internal' ? ($siteNames[(int) $t['site_id']] ?? '?') . ': ' . $t['value'] : (string) $t['value'];
        }
        $hosts = [];
        foreach ($results as $r) {
            $hosts[] = ['ip' => (string) $r['ip'], 'origin' => (string) $r['origin'], 'hostnames' => (string) $r['hostnames'], 'complete' => (int) $r['complete'] === 1,
                'tested_at' => $local((string) $r['scanned_at']),
                'ports' => array_map(static fn (array $p): string => (int) ($p['port'] ?? 0) . '/' . (string) ($p['service'] ?? '')
                    . (trim((string) ($p['product'] ?? '') . ' ' . (string) ($p['version'] ?? '')) !== '' ? ' (' . trim((string) ($p['product'] ?? '') . ' ' . (string) ($p['version'] ?? '')) . ')' : ''),
                    (array) $r['ports_list'])];
        }
        $snapshot = [
            'kind' => $original === null ? 'pentest' : 'retest',
            'generated_at' => gmdate('Y-m-d H:i') . ' UTC', 'generated_by' => $generatedBy, 'brand' => $brand,
            'client' => ['name' => (string) $client['name'], 'timezone' => (string) $client['timezone']],
            'engagement' => [
                'id' => (int) $engagement['id'], 'name' => (string) $engagement['name'], 'window_start' => $local((string) $engagement['window_start']),
                'window_end' => $local((string) $engagement['window_end']), 'intensity' => (string) $engagement['intensity'],
                'tests' => array_map(static fn (string $t): string => $testLabels[$t] ?? $t, $engagement['tests_list']),
                'signer' => (string) $engagement['signer_name'], 'signer_role' => (string) $engagement['signer_role'], 'signed_on' => (string) $engagement['signed_on'],
                'document_sha256' => (string) $engagement['document_sha256'], 'created_by' => (string) ($engagement['created_by_name'] ?? ''),
                'approved_by' => (string) ($engagement['approved_by_name'] ?? ''), 'approved_at' => $local($engagement['approved_at']),
                'stopped' => $engagement['stopped_at'] !== null ? ['at' => $local((string) $engagement['stopped_at']), 'by' => (string) ($engagement['stopped_by_name'] ?? ''), 'reason' => (string) $engagement['stop_reason']] : null,
            ],
            'scope' => $scope,
            'counts' => $counts,
            'rating' => $counts['fail'] > 0 ? 'risk' : ($counts['warn'] > 0 ? 'attention' : 'good'),
            'findings' => $findings,
            'paths' => self::attackPaths($findings),
            'hosts' => $hosts,
        ];
        if ($original !== null) {
            $snapshot['retest'] = self::compare((array) ($original['findings'] ?? []), $findings, array_column($hosts, 'ip'))
                + ['original_engagement' => (string) ($original['engagement']['name'] ?? ''), 'original_date' => (string) ($original['generated_at'] ?? '')];
        }
        return $snapshot;
    }

    /**
     * Render a snapshot with views/reports/pentest.php (self-contained HTML; every value escaped there).
     *
     * @param array<string,mixed> $r
     */
    public static function render(array $r, string $templateDir): string
    {
        ob_start();
        try {
            (static function (array $r, string $file): void {
                require $file;
            })($r, $templateDir . '/pentest.php');
            return (string) ob_get_clean();
        } catch (\Throwable $ex) {
            ob_end_clean();
            throw $ex;
        }
    }

    /**
     * How the findings could be chained by an attacker (plain sentences from fixed rules; only combinations that are
     * really present are described).
     *
     * @param list<array<string,mixed>> $findings
     * @return list<string>
     */
    public static function attackPaths(array $findings): array
    {
        $has = static function (array $keys, ?string $origin = null) use ($findings): bool {
            foreach ($findings as $f) {
                if (in_array($f['key'], $keys, true) && ($origin === null || $f['origin'] === $origin) && $f['severity'] !== 'info') {
                    return true;
                }
            }
            return false;
        };
        $externalDoor = $has(['ftp_anon', 'snmp_public', 'snmp_private', 'telnet', 'smb_anon_read', 'smb_anon_write', 'nfs_exports'], 'external')
            || array_filter($findings, static fn (array $f): bool => $f['origin'] === 'external' && str_starts_with($f['key'], 'exposed_')) !== [];
        $internalSpread = $has(['smb_anon_write', 'smb1', 'nfs_exports'], 'internal');
        $paths = [];
        if ($externalDoor && $internalSpread) {
            $paths[] = __('From the internet an attacker can reach services that should not be reachable; once inside, shares or old protocols that need no password would let them read data, plant files and spread to other machines.');
        }
        if ($has(['smb_anon_write']) && $has(['smb1'])) {
            $paths[] = __('Shares anyone can write to, together with SMBv1, are how ransomware spreads from one infected computer to the rest of the network.');
        }
        if ($has(['smb_signing']) && $has(['smb_anon_read', 'smb_anon_write', 'smb1'])) {
            $paths[] = __('SMB without required signing lets an attacker on the network relay a user\'s sign-in to other servers; the open shares show where that access would lead.');
        }
        if ($has(['snmp_private'])) {
            $paths[] = __('A device answering the default SNMP write community can be reconfigured by anyone who can reach it, for example to redirect or capture traffic.');
        }
        if ($has(['telnet', 'ftp'])) {
            $paths[] = __('Telnet and FTP send passwords unencrypted: anyone on the same network path can capture them and reuse them elsewhere.');
        }
        return $paths;
    }

    /**
     * Compare an earlier report's Fails and Warnings with the retest's findings.
     *
     * @param list<array<string,mixed>> $before
     * @param list<array<string,mixed>> $after
     * @param list<string> $retestedHosts
     * @return array{items:list<array<string,string>>, fixed:int, open:int, not_retested:int}
     */
    public static function compare(array $before, array $after, array $retestedHosts): array
    {
        $now = [];
        foreach ($after as $f) {
            $now[$f['key'] . '|' . $f['target']] = true;
        }
        $items = [];
        $n = ['fixed' => 0, 'open' => 0, 'not_retested' => 0];
        foreach ($before as $f) {
            if (!in_array($f['severity'] ?? '', ['fail', 'warn'], true)) {
                continue;
            }
            $host = (string) preg_replace('/:\d+(\/udp)?$/', '', (string) $f['target']);
            $status = isset($now[$f['key'] . '|' . $f['target']]) ? 'open' : (in_array($host, $retestedHosts, true) ? 'fixed' : 'not_retested');
            $n[$status]++;
            $items[] = ['severity' => (string) $f['severity'], 'title' => (string) $f['title'], 'target' => (string) $f['target'], 'status' => $status];
        }
        return ['items' => $items, 'fixed' => $n['fixed'], 'open' => $n['open'], 'not_retested' => $n['not_retested']];
    }
}
