<?php

declare(strict_types=1);

namespace Sentinel\Reports;

/**
 * A made-up report snapshot for the branding preview (1.59): a fictional client with a few typical findings, so an
 * admin can see their branding on a full document without creating a real report. Nothing here comes from the
 * database except the brand, and nothing is stored.
 *
 * Security assumptions: the snapshot holds only fixed sample text plus the brand (admin input), and is rendered by the
 * same template as real reports, which escapes every value.
 */
final class ReportPreview
{
    /**
     * Made-up score history (1.62): six months falling from 78 to 52, the first months estimated.
     *
     * @return array{points:list<array{day:string, score:int, level:string, estimated:bool}>, from:array{day:string, score:int, level:string, estimated:bool}, days:int}
     */
    private static function scoreHistory(): array
    {
        $points = [];
        for ($d = 180; $d >= 0; $d -= 6) {
            $score = (int) round(52 + 26 * $d / 180 + ($d % 30 === 0 ? 3 : 0));
            $points[] = ['day' => gmdate('Y-m-d', time() - $d * 86400), 'score' => $score, 'level' => $score >= 50 ? 'risk' : 'attention', 'estimated' => $d > 100];
        }
        $points[count($points) - 1]['score'] = 52;
        return ['points' => $points, 'from' => ['day' => gmdate('Y-m-d', time() - 30 * 86400), 'score' => 60, 'level' => 'risk', 'estimated' => false], 'days' => 182];
    }

    /**
     * @param array<string,mixed> $brand ReportBuilder::brand()
     * @return array<string,mixed>
     */
    public static function snapshot(array $brand, string $kind, string $version): array
    {
        $kind = $kind === 'technical' ? 'technical' : 'executive';
        $today = gmdate('Y-m-d');
        $start = gmdate('Y-m-d', strtotime('first day of last month'));
        $end = gmdate('Y-m-d', strtotime('last day of last month'));
        $f = static fn (array $x): array => $x + ['finding_key' => $x['title'], 'cve_id' => null, 'in_kev' => 0, 'kev_due' => null, 'epss' => null,
            'detail' => '', 'evidence' => '', 'confidence' => '', 'first_seen' => $start . ' 09:00:00', 'last_seen' => $today . ' 06:00:00',
            'reappeared' => 0, 'status' => 'open', 'resolved_at' => null, 'triage_note' => '', 'triaged_at' => null, 'triaged_by_name' => null];
        $open = [
            $f(['finding_type' => 'port', 'severity' => 'fail', 'source' => 'external', 'title' => __('Remote Desktop open to the internet'), 'target' => '203.0.113.10:3389',
                'detail' => __('Remote Desktop (RDP) answers on port 3389.'), 'meaning' => __('Attackers try passwords against Remote Desktop all day. One weak password gives them the whole computer.'),
                'fix' => __('Close port 3389 on the firewall and use a VPN or a remote access gateway with multi-factor sign-in.')]),
            $f(['finding_type' => 'vuln', 'severity' => 'fail', 'source' => 'external', 'title' => __('Example VPN 9.1: 1 known CVE(s) (worst: CVE-2099-0101, 9.8 Critical)'), 'target' => '203.0.113.11:443',
                'cve_id' => 'CVE-2099-0101', 'in_kev' => 1, 'epss' => 0.94, 'confidence' => 'confirmed', 'evidence' => 'confirmed|Example VPN 9.1',
                'detail' => __('Confirmed for the installed version.'), 'meaning' => __('This VPN version has a flaw that criminals are known to use to break in.'),
                'fix' => __('Update the VPN appliance to the vendor\'s fixed version straight away.')]),
            $f(['finding_type' => 'inventory', 'severity' => 'warn', 'source' => 'ninjaone', 'title' => __('Disk encryption is off'), 'target' => 'EX-LAPTOP-07',
                'meaning' => __('If this laptop is lost or stolen, anyone can read the files on its disk.'), 'fix' => __('Turn on BitLocker and store the recovery key safely.')]),
            $f(['finding_type' => 'tls', 'severity' => 'warn', 'source' => 'external', 'title' => __('Certificate expires in 12 days'), 'target' => 'mail.client.example:443',
                'meaning' => __('When the certificate expires, staff and customers get security warnings and some services stop working.'), 'fix' => __('Renew the certificate before it expires.')]),
        ];
        $top = array_map(static function (array $g): array {
            unset($g['items']);
            return $g;
        }, ReportBuilder::byIssue($open));
        $fixed = [$f(['finding_type' => 'port', 'severity' => 'fail', 'source' => 'external', 'title' => __('Database port open to the internet'), 'target' => '203.0.113.12:3306',
            'meaning' => '', 'fix' => '', 'status' => 'resolved', 'resolved_at' => $end . ' 14:00:00'])];
        $trend = [];
        for ($m = 5; $m >= 0; $m--) {
            $trend[] = ['label' => gmdate('M Y', strtotime("first day of -{$m} month")), 'fail' => [6, 5, 5, 4, 3, 2][5 - $m], 'warn' => [9, 8, 6, 6, 4, 2][5 - $m]];
        }
        return [
            'kind' => $kind, 'version' => $version, 'generated_at' => $today . ' 08:00', 'generated_by' => __('Preview'),
            'period' => ['start' => $start, 'end' => $end],
            'client' => ['id' => 0, 'name' => __('Example Client Co.'), 'timezone' => 'UTC'],
            'brand' => $brand,
            'rating' => ['level' => 'risk', 'score' => 52, 'reason' => __('1 known-exploited weakness(es) can be reached from the internet and need fixing now.')],
            'counts' => ['fail' => 2, 'warn' => 2, 'new' => 3, 'fixed' => 1, 'accepted' => 0, 'false_positive' => 0, 'certs_expiring' => 1],
            'top' => $top, 'open_issue_count' => count($top), 'open' => $open, 'decided' => [], 'fixed' => $fixed,
            'scope' => ['203.0.113.0/28', 'client.example'],
            'coverage' => ['external' => true, 'internal' => true],
            'scans' => [['id' => 1, 'status' => 'done', 'started_at' => $today . ' 02:00:00', 'finished_at' => $today . ' 02:14:00']],
            'last_checked' => $today . ' 02:14:00',
            'trend' => $trend,
            'score_history' => self::scoreHistory(),
        ];
    }
}
