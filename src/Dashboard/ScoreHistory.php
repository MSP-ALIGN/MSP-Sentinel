<?php

declare(strict_types=1);

namespace Sentinel\Dashboard;

use PDO;
use Sentinel\Core\Settings;

/**
 * A client's risk score over time (1.62), from the daily finding_stats rows.
 *
 * Days recorded since 1.62 carry the exact score and level (StatsRecorder, the dashboard's rule). Earlier days only
 * have open Fail/Warning counts: their score is estimated from those counts as if every finding were reachable from
 * the internet and none known exploited, and is marked 'estimated' so charts and reports can show it differently.
 * Today's point is always the live score.
 *
 * Security assumptions: read-only. Client IDs are integers and are checked against the user's clients by the route
 * before they reach this class; the client list for movers() comes from DashboardData, which is already filtered.
 * Every value placed in SQL is an integer cast or a bound parameter.
 */
final class ScoreHistory
{
    /** Uses the given connection. */
    public function __construct(private readonly PDO $db, private readonly Settings $settings)
    {
    }

    /**
     * Score and level estimated from counts alone (all treated as internet-facing, not known exploited).
     *
     * @return array{score:int, level:string}
     */
    public static function estimate(int $fail, int $warn): array
    {
        $score = DashboardData::score([0, max(0, $fail), max(0, $warn)]);
        return ['score' => $score, 'level' => DashboardData::level($score, 0, $fail)];
    }

    /**
     * One point per recorded day in the last $days days, oldest first, ending with today's live score (when the client
     * is active).
     *
     * @return list<array{day:string, score:int, level:string, estimated:bool}>
     */
    public function series(int $clientId, int $days): array
    {
        $days = max(1, min(366, $days));
        $stmt = $this->db->prepare('SELECT day, fail_open, warn_open, score, level FROM finding_stats
                                    WHERE client_id = :c AND day >= UTC_DATE() - INTERVAL ' . $days . ' DAY AND day < UTC_DATE() ORDER BY day');
        $stmt->execute(['c' => $clientId]);
        $out = array_map([self::class, 'point'], $stmt->fetchAll());
        $live = (new DashboardData($this->db, $this->settings, [$clientId]))->clients($clientId);
        if ($live !== []) {
            $out[] = ['day' => gmdate('Y-m-d'), 'score' => $live[0]['score'], 'level' => $live[0]['level'], 'estimated' => false];
        }
        return $out;
    }

    /**
     * The score on a day: the latest recorded day on or before it, or null when nothing was recorded by then.
     *
     * @return array{day:string, score:int, level:string, estimated:bool}|null
     */
    public function on(int $clientId, string $day): ?array
    {
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $day)) {
            return null;
        }
        $stmt = $this->db->prepare('SELECT day, fail_open, warn_open, score, level FROM finding_stats WHERE client_id = :c AND day <= :d ORDER BY day DESC LIMIT 1');
        $stmt->execute(['c' => $clientId, 'd' => $day]);
        $row = $stmt->fetch();
        return $row === false ? null : self::point($row);
    }

    /**
     * The clients whose score changed most in the last $days days: now (DashboardData::clients() rows) against the
     * latest day recorded on or before $days days ago. Clients with no history that far back, or no change, are left out.
     *
     * @param list<array{id:int, name:string, score:int, level:string}> $clients
     * @return list<array{id:int, name:string, from:int, to:int, delta:int, level:string, estimated:bool}>
     */
    public function movers(array $clients, int $days = 30, int $limit = 5): array
    {
        $since = gmdate('Y-m-d', time() - max(1, $days) * 86400);
        $out = [];
        foreach ($clients as $c) {
            $then = $this->on((int) $c['id'], $since);
            if ($then === null || $then['score'] === (int) $c['score']) {
                continue;
            }
            $out[] = ['id' => (int) $c['id'], 'name' => (string) $c['name'], 'from' => $then['score'], 'to' => (int) $c['score'],
                      'delta' => (int) $c['score'] - $then['score'], 'level' => (string) $c['level'], 'estimated' => $then['estimated']];
        }
        // Biggest change first (up or down); ties by name.
        usort($out, static fn (array $a, array $b): int => [abs($b['delta']), $a['name']] <=> [abs($a['delta']), $b['name']]);
        return array_slice($out, 0, max(1, $limit));
    }

    /**
     * A stored row as a point: the exact score when recorded, else the estimate.
     *
     * @param array<string,mixed> $row
     * @return array{day:string, score:int, level:string, estimated:bool}
     */
    private static function point(array $row): array
    {
        if ($row['score'] !== null && in_array($row['level'], ['risk', 'attention', 'good'], true)) {
            return ['day' => (string) $row['day'], 'score' => (int) $row['score'], 'level' => (string) $row['level'], 'estimated' => false];
        }
        return ['day' => (string) $row['day'], 'estimated' => true] + self::estimate((int) $row['fail_open'], (int) $row['warn_open']);
    }
}
