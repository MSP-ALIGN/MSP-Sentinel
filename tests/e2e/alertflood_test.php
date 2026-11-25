<?php

declare(strict_types=1);

/**
 * End-to-end tests against alert floods (1.49): one run never sends more than a set number of immediate Fail alerts
 * across clients (for example a vulnerability data run touching many clients).
 * Made-up clients and documentation addresses only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

/** A client with $n open Fail findings from $source; returns [client ID, finding IDs]. */
$seed = static function (TestContext $ctx, string $name, int $n, string $source): array {
    $ctx->db->prepare("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, created_at, updated_at)
                       VALUES (:n, 'UTC', '22:00:00', '06:00:00', '', '', '', UTC_TIMESTAMP(), UTC_TIMESTAMP())")->execute(['n' => $name]);
    $cid = (int) $ctx->db->lastInsertId();
    $ids = [];
    for ($i = 1; $i <= $n; $i++) {
        $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at, due_at, source)
                           VALUES (:c, :k, 'port', 'fail', :t, 'Open.', :tg, 'x', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 14 DAY, :s)")
            ->execute(['c' => $cid, 'k' => "flood:{$source}:{$i}", 't' => "Flood test problem {$i}", 'tg' => "203.0.113.{$i}:23", 's' => $source]);
        $ids[] = (int) $ctx->db->lastInsertId();
    }
    return [$cid, $ids];
};
$changed = static fn (array $ids): array => ['opened_ids' => $ids, 'reopened_ids' => [], 'resolved_ids' => [], 'escalated_ids' => []];
$count = static fn (TestContext $ctx, string $like): int => (int) $ctx->db->query("SELECT COUNT(*) FROM notifications n JOIN users u ON u.id = n.user_id
    WHERE u.username = 'admin' AND n.title LIKE " . $ctx->db->quote($like))->fetchColumn();

/** Remove what these tests made, so later tests' notification counts and outboxes are not affected. */
$floodCleanup = static function (TestContext $ctx): void {
    $ctx->db->exec("DELETE n FROM notifications n WHERE n.title LIKE 'Fail: Flood test problem%'
                    OR n.title LIKE 'Many new Fail findings at once%' OR n.title LIKE '% more new Fail findings for Flood Run Example%'");
    $ctx->db->exec("DELETE FROM deliveries WHERE subject LIKE '%Flood%' OR subject LIKE '%Many new Fail findings at once%'");
    $ids = implode(',', array_map('intval', $ctx->db->query("SELECT id FROM clients WHERE name LIKE 'Flood Run Example%'")->fetchAll(PDO::FETCH_COLUMN)));
    if ($ids !== '') {
        $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id IN ({$ids})");
        $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP() WHERE client_id IN ({$ids})");
    }
};

return [
    'alert floods (1.49): one run sends at most 60 immediate Fail alerts across clients, then one notice' => function (TestContext $ctx) use ($seed, $changed, $count, $floodCleanup): void {
        $before = $count($ctx, 'Fail: Flood test problem%');
        $alerts = App::alerts(); // one run, like a feeds job
        for ($c = 1; $c <= 4; $c++) {
            [$cid, $ids] = $seed($ctx, 'Flood Run Example ' . $c, 20, 'scan');
            $alerts->findingsChanged($cid, $changed($ids), false);
        }
        Assert::same(60, $count($ctx, 'Fail: Flood test problem%') - $before, 'capped at 60 for the run');
        Assert::same(1, $count($ctx, 'Many new Fail findings at once%'), 'one notice that alerts were paused');
        Assert::true($count($ctx, '% more new Fail findings for Flood Run Example 4') === 1, 'the client whose alerts were held back is told how many');
        $floodCleanup($ctx);
    },
];
