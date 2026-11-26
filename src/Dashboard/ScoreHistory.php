<?php

declare(strict_types=1);

namespace Sentinel\Dashboard;

use PDO;
use Sentinel\Core\Settings;

/**
 * A client's risk score over time (1.62), from the daily finding_stats rows.
 *
 * Days recorded since 1.62 carry the exact score and level (StatsRecorder, the dashboard's rule). Earlier days only
 * have open Fail/Warning counts, so their score is estimated, and marked 'estimated' so charts and reports can show it
 * differently. The estimate is calibrated to the client: the counts are scored as if all were internet-facing (the
 * raw estimate), then scaled by how today's exact score compares with today's raw estimate. A client whose mix of
 * internal, external and known-exploited findings is like today's gets a fair estimate, and a client that changed
 * nothing shows no change (an uncalibrated estimate would show internal-heavy clients as much worse in the past).
 * Today's point is always the live score.
 *
 * Security assumptions: read-only. Client IDs are integers and are checked against the user's clients by the route
 * before they reach this class; the client list for movers() comes from DashboardData, which is already filtered.
 * Every value placed in SQL is an integer cast or a bound parameter.
 */
final class ScoreHistory
{
    /** How far back from a requested day a recorded day may be and still count as "the score then" (days). */
    public const MAX_GAP_DAYS = 31;

    /** Uses the given connection. */
    public function __construct(private readonly PDO $db, private readonly Settings $settings)
    {
    }

    /**
     * Score and level from counts alone (all treated as internet-facing, not known exploited), then scaled by $factor
     * (calibration()).
     *
     * @return array{score:int, level:string}
     */
    public static function estimate(int $fail, int $warn, float $factor = 1.0): array
    {
        $score = (int) round(max(0, min(100, DashboardData::score([0, max(0, $fail), max(0, $warn)]) * $factor)));
        return ['score' => $score, 'level' => DashboardData::level($score, 0, $fail)];
    }

    /**
     * The calibration factor for a client: today's exact score divided by today's raw estimate (1 when there is nothing
     * to compare: no open Fail or Warning today).
     */
    public static function calibration(int $failNow, int $warnNow, int $scoreNow): float
    {
        $raw = DashboardData::score([0, max(0, $failNow), max(0, $warnNow)]);
        return $raw > 0 ? max(0.0, min(4.0, $scoreNow / $raw)) : 1.0;
    }

    /**
     * One point per recorded day in the last $days days, oldest first, ending with today's score. $now is the client's
     * current state (fail, warn, score, level); by default the live dashboard row (none for an archived client: then
     * there is no today's point and estimates are not calibrated).
     *
     * @param array{fail:int, warn:int, score:int, level:string}|null $now
     * @return list<array{day:string, score:int, level:string, estimated:bool}>
     */
    public function series(int $clientId, int $days, ?array $now = null): array
    {
        $days = max(1, min(366, $days));
        $now ??= (new DashboardData($this->db, $this->settings, [$clientId]))->clients($clientId)[0] ?? null;
        $factor = $now === null ? 1.0 : self::calibration((int) $now['fail'], (int) $now['warn'], (int) $now['score']);
        $stmt = $this->db->prepare('SELECT day, fail_open, warn_open, score, level FROM finding_stats
                                    WHERE client_id = :c AND day >= UTC_DATE() - INTERVAL ' . $days . ' DAY AND day < UTC_DATE() ORDER BY day');
        $stmt->execute(['c' => $clientId]);
        $out = array_map(static fn (array $row): array => self::point($row, $factor), $stmt->fetchAll());
        if ($now !== null) {
            $out[] = ['day' => gmdate('Y-m-d'), 'score' => (int) $now['score'], 'level' => (string) $now['level'], 'estimated' => false];
        }
        return $out;
    }

    /**
     * The score on a day: the latest recorded day on or before it and at most MAX_GAP_DAYS earlier, or null.
     *
     * @param array{fail:int, warn:int, score:int}|null $now the client's current state, to calibrate an estimate
     * @return array{day:string, score:int, level:string, estimated:bool}|null
     */
    public function on(int $clientId, string $day, ?array $now = null): ?array
    {
        return $this->onMany([$clientId => $now], $day)[$clientId] ?? null;
    }

    /**
     * The clients whose score changed most in the last $days days: now (DashboardData::clients() rows) against the
     * score $days days ago (on()). Clients with no history then, or no change, are left out. One query for all clients.
     *
     * @param list<array{id:int, name:string, fail:int, warn:int, score:int, level:string}> $clients
     * @return list<array{id:int, name:string, from:int, to:int, delta:int, level:string, estimated:bool}>
     */
    public function movers(array $clients, int $days = 30, int $limit = 5): array
    {
        $byId = [];
        foreach ($clients as $c) {
            $byId[(int) $c['id']] = $c;
        }
        $then = $this->onMany($byId, gmdate('Y-m-d', time() - max(1, $days) * 86400));
        $out = [];
        foreach ($then as $id => $p) {
            $c = $byId[$id];
            if ($p['score'] === (int) $c['score']) {
                continue;
            }
            $out[] = ['id' => $id, 'name' => (string) $c['name'], 'from' => $p['score'], 'to' => (int) $c['score'],
                      'delta' => (int) $c['score'] - $p['score'], 'level' => (string) $c['level'], 'estimated' => $p['estimated']];
        }
        // Biggest change first (up or down); ties by name.
        usort($out, static fn (array $a, array $b): int => [abs($b['delta']), $a['name']] <=> [abs($a['delta']), $b['name']]);
        return array_slice($out, 0, max(1, $limit));
    }

    /**
     * The score on $day for several clients in one query: for each, the latest recorded day in
     * [$day - MAX_GAP_DAYS, $day].
     *
     * @param array<int, array{fail:int, warn:int, score:int}|null> $now client ID => current state (for calibration) or null
     * @return array<int, array{day:string, score:int, level:string, estimated:bool}>
     */
    private function onMany(array $now, string $day): array
    {
        $ids = array_values(array_filter(array_map('intval', array_keys($now)), static fn (int $id): bool => $id > 0));
        if ($ids === [] || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $day)) {
            return [];
        }
        $in = implode(',', $ids); // integers only
        $stmt = $this->db->prepare("SELECT s.client_id, s.day, s.fail_open, s.warn_open, s.score, s.level FROM finding_stats s
            JOIN (SELECT client_id, MAX(day) AS d FROM finding_stats WHERE client_id IN ({$in}) AND day <= :d1 AND day >= :d2 - INTERVAL " . self::MAX_GAP_DAYS . " DAY GROUP BY client_id) m
              ON m.client_id = s.client_id AND m.d = s.day");
        $stmt->execute(['d1' => $day, 'd2' => $day]);
        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            $n = $now[(int) $row['client_id']] ?? null;
            $factor = $n === null ? 1.0 : self::calibration((int) $n['fail'], (int) $n['warn'], (int) $n['score']);
            $out[(int) $row['client_id']] = self::point($row, $factor);
        }
        return $out;
    }

    /**
     * A stored row as a point: the exact score when recorded, else the calibrated estimate.
     *
     * @param array<string,mixed> $row
     * @return array{day:string, score:int, level:string, estimated:bool}
     */
    private static function point(array $row, float $factor): array
    {
        if ($row['score'] !== null && in_array($row['level'], ['risk', 'attention', 'good'], true)) {
            return ['day' => (string) $row['day'], 'score' => (int) $row['score'], 'level' => (string) $row['level'], 'estimated' => false];
        }
        return ['day' => (string) $row['day'], 'estimated' => true] + self::estimate((int) $row['fail_open'], (int) $row['warn_open'], $factor);
    }
}
