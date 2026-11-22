<?php

declare(strict_types=1);

namespace Sentinel\Reports;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use Sentinel\Core\Settings;
use Sentinel\Scope\AuthorisationRepository;
use Sentinel\Scope\ScopeService;

/**
 * Builds a report snapshot: everything a report shows, gathered at one moment,
 * so the stored report never changes afterwards.
 *
 * Findings, totals and the rating show the status at the moment the report
 * is created (stated in the document); "new" and "fixed" count what changed
 * within the chosen period.
 *
 * Security assumptions:
 * - Every query is filtered by the one client ID, so no data from another
 *   client can appear in the report (tests check this).
 * - All text is scan data or admin input (untrusted). The snapshot keeps it
 *   as plain strings; the renderer escapes it.
 * - The logo is read from a file Sentinel itself wrote (re-encoded PNG).
 */
final class ReportBuilder
{
    public const KINDS = ['executive', 'technical'];

    /** @param string $storageDir Where the branding logo lives (storage/branding). */
    public function __construct(
        private readonly PDO $db,
        private readonly Settings $settings,
        private readonly AuthorisationRepository $authorisations,
        private readonly string $storageDir,
        private readonly string $version,
    ) {
    }

    /**
     * Gather the snapshot.
     *
     * @param array<string,mixed> $client Client row.
     * @param string $kind 'executive' or 'technical'.
     * @param string $start Period start (Y-m-d, UTC).
     * @param string $end   Period end (Y-m-d, UTC, inclusive).
     * @return array<string,mixed>
     */
    public function build(array $client, string $kind, string $start, string $end, string $generatedBy): array
    {
        $cid = (int) $client['id'];
        $periodEnd = $end . ' 23:59:59';
        $all = $this->findings($cid);
        $open = array_values(array_filter($all, static fn (array $f): bool => $f['status'] === 'open'));
        $decided = array_values(array_filter($all, static fn (array $f): bool => in_array($f['status'], ['accepted', 'false_positive'], true)));
        $fixed = array_values(array_filter($all, static fn (array $f): bool => $f['status'] === 'resolved' && $f['resolved_at'] !== null
            && $f['resolved_at'] >= $start && $f['resolved_at'] <= $periodEnd));
        $new = array_filter($all, static fn (array $f): bool => $f['first_seen'] >= $start && $f['first_seen'] <= $periodEnd);
        $fails = array_values(array_filter($open, static fn (array $f): bool => $f['severity'] === 'fail'));
        $warns = array_values(array_filter($open, static fn (array $f): bool => $f['severity'] === 'warn'));
        $certs = array_filter($open, static fn (array $f): bool => $f['finding_type'] === 'tls' && (str_ends_with((string) $f['finding_key'], ':cert_expiring') || str_ends_with((string) $f['finding_key'], ':cert_expired')));

        [$level, $reason] = match (true) {
            $fails !== [] => ['risk', __('{n} serious problem(s) need fixing now.', ['n' => count($fails)])],
            $warns !== [] => ['attention', __('No serious problems, but {n} item(s) should be fixed soon.', ['n' => count($warns)])],
            default => ['good', __('No open problems were found in the checks we ran.')],
        };

        $scans = $this->db->prepare("SELECT id, status, started_at, finished_at FROM scan_jobs WHERE client_id = :c AND finished_at IS NOT NULL AND job_type <> 'verify' ORDER BY id DESC LIMIT 10");
        $scans->execute(['c' => $cid]);
        $scanRows = $scans->fetchAll();
        $today = ScopeService::today((string) $client['timezone']);
        $scope = array_map(static fn (array $e): string => (string) $e['value'], $this->authorisations->activeEntries($cid, $today));
        sort($scope);

        return [
            'kind' => $kind,
            'version' => $this->version,
            'generated_at' => gmdate('Y-m-d H:i'),
            'generated_by' => $generatedBy,
            'period' => ['start' => $start, 'end' => $end],
            'client' => ['id' => $cid, 'name' => (string) $client['name']],
            'brand' => $this->brand(),
            'rating' => ['level' => $level, 'reason' => $reason],
            'counts' => [
                'fail' => count($fails), 'warn' => count($warns), 'new' => count($new), 'fixed' => count($fixed),
                'accepted' => count(array_filter($decided, static fn (array $f): bool => $f['status'] === 'accepted')),
                'false_positive' => count(array_filter($decided, static fn (array $f): bool => $f['status'] === 'false_positive')),
                'certs_expiring' => count($certs),
            ],
            'top' => array_slice($open, 0, 5),
            'open' => $open,
            'decided' => $decided,
            'fixed' => $fixed,
            'scope' => $scope,
            'scans' => $scanRows,
            'last_checked' => $scanRows[0]['finished_at'] ?? null,
            'trend' => $this->trend($cid, count($fails), count($warns)),
        ];
    }

    /** A short title for lists and file names. */
    public static function title(string $kind, string $clientName, string $start, string $end): string
    {
        return ($kind === 'executive' ? __('Executive summary') : __('Technical findings')) . ' – ' . $clientName . ' – ' . $start . ' to ' . $end;
    }

    /**
     * The client's current findings with guidance and vulnerability data, most important first.
     *
     * @return list<array<string,mixed>>
     */
    private function findings(int $clientId): array
    {
        $stmt = $this->db->prepare(
            "SELECT f.id, f.finding_key, f.finding_type, f.severity, f.title, f.detail, f.target, f.evidence, f.cve_id, f.status,
                    f.triage_note, f.triaged_at, u.display_name AS triaged_by_name, f.reappeared, f.first_seen, f.last_seen, f.resolved_at,
                    (k.cve_id IS NOT NULL) AS in_kev, k.required_action AS kev_action, k.due_date AS kev_due, ep.score AS epss, ep.percentile AS epss_percentile
             FROM findings f
             LEFT JOIN users u ON u.id = f.triaged_by
             LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
             LEFT JOIN epss_scores ep ON ep.cve_id = f.cve_id
             WHERE f.client_id = :c
             ORDER BY f.severity = 'fail' DESC, (k.cve_id IS NOT NULL) DESC, f.finding_type = 'port' DESC, f.target, f.id"
        );
        $stmt->execute(['c' => $clientId]);
        $rows = [];
        foreach ($stmt->fetchAll() as $f) {
            $g = Guidance::for($f, $f);
            $f['meaning'] = $g['meaning'];
            $f['fix'] = $g['fix'];
            $f['asset'] = self::assetOf((string) $f['target']);
            $f['confidence'] = $f['finding_type'] === 'vuln' ? (string) strtok((string) $f['evidence'], '|') : '';
            $rows[] = $f;
        }
        return $rows;
    }

    /** The host part of a target ("203.0.113.5:443 (www)" or "https://203.0.113.5:443" -> "203.0.113.5"). */
    public static function assetOf(string $target): string
    {
        $t = (string) preg_replace('#^[a-z]+://#i', '', $target);
        if (preg_match('/^\[([0-9a-f:]+)\]/i', $t, $m)) {
            return $m[1];
        }
        if (substr_count($t, ':') > 1 && preg_match('/^([0-9a-f:]+):(\d+)/i', $t, $m)) {
            return $m[1];
        }
        return (string) strtok($t, ': ');
    }

    /**
     * Open Fail/Warning counts at the end of each of the last 12 months (where recorded), plus today.
     *
     * @return list<array{label:string, fail:int, warn:int}>
     */
    private function trend(int $clientId, int $failNow, int $warnNow): array
    {
        $stmt = $this->db->prepare(
            "SELECT s.day, s.fail_open, s.warn_open FROM finding_stats s
             JOIN (SELECT MAX(day) AS day FROM finding_stats WHERE client_id = :c1 AND day >= UTC_DATE() - INTERVAL 12 MONTH
                   GROUP BY DATE_FORMAT(day, '%Y-%m')) last ON last.day = s.day
             WHERE s.client_id = :c2 AND DATE_FORMAT(s.day, '%Y-%m') < DATE_FORMAT(UTC_DATE(), '%Y-%m') ORDER BY s.day"
        );
        $stmt->execute(['c1' => $clientId, 'c2' => $clientId]);
        $points = [];
        foreach ($stmt->fetchAll() as $r) {
            $points[] = ['label' => (new DateTimeImmutable((string) $r['day'], new DateTimeZone('UTC')))->format('M Y'), 'fail' => (int) $r['fail_open'], 'warn' => (int) $r['warn_open']];
        }
        $points[] = ['label' => gmdate('j M'), 'fail' => $failNow, 'warn' => $warnNow];
        return $points;
    }

    /**
     * Branding frozen into the report.
     *
     * @return array{name:string, color:string, footer:string, logo:string, powered_by:bool, paper:string}
     */
    private function brand(): array
    {
        $logo = '';
        $hash = $this->settings->get('brand_logo');
        if (preg_match('/^[a-f0-9]{64}$/', $hash)) {
            $file = $this->storageDir . '/logo-' . $hash . '.png';
            if (is_file($file) && hash_file('sha256', $file) === $hash) {
                $logo = 'data:image/png;base64,' . base64_encode((string) file_get_contents($file));
            }
        }
        return [
            'name' => $this->settings->get('brand_name') !== '' ? $this->settings->get('brand_name') : $this->settings->get('product_name'),
            'color' => preg_match('/^#[0-9a-f]{6}$/i', $this->settings->get('brand_color')) ? $this->settings->get('brand_color') : '#1f4e79',
            'footer' => $this->settings->get('brand_footer'),
            'logo' => $logo,
            'powered_by' => $this->settings->get('report_powered_by') === '1',
            'paper' => $this->settings->get('report_paper') === 'Letter' ? 'Letter' : 'A4',
        ];
    }
}
