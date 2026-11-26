<?php

declare(strict_types=1);

/**
 * End-to-end tests for the risk score history (1.62): exact daily scores, estimates for older days, the client
 * overview chart and its ranges, the dashboard's biggest changes, the executive summary and the API. Made-up data
 * only (no scans).
 */

use Sentinel\Core\App;
use Sentinel\Dashboard\ScoreHistory;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'score history: exact and estimated days, client chart and ranges, dashboard, executive summary, API' => function (TestContext $ctx): void {
        $ctx->db->exec("INSERT INTO clients (name, timezone, created_at, updated_at) VALUES ('Score History Example', 'UTC', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $cid = (int) $ctx->db->lastInsertId();
        $ctx->db->exec("INSERT INTO clients (name, timezone, created_at, updated_at) VALUES ('Score History Other Example', 'UTC', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $other = (int) $ctx->db->lastInsertId();
        $token = null;
        try {
            // 60 days ago: counts only (recorded before 1.62) -> estimated; 20 days ago: an exact score.
            $ctx->db->exec("INSERT INTO finding_stats (client_id, day, fail_open, warn_open, recorded_at) VALUES ({$cid}, UTC_DATE() - INTERVAL 60 DAY, 3, 2, UTC_TIMESTAMP())");
            $ctx->db->exec("INSERT INTO finding_stats (client_id, day, fail_open, warn_open, score, level, recorded_at) VALUES ({$cid}, UTC_DATE() - INTERVAL 20 DAY, 2, 0, 40, 'attention', UTC_TIMESTAMP())");
            // Now: one ordinary Fail on the internet -> 15, Needs attention.
            $ctx->db->exec("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, target, status, source, first_seen, last_seen)
                            VALUES ({$cid}, 'port:203.0.113.190:3389', 'port', 'fail', 'Score history test finding', '203.0.113.190:3389', 'open', 'external', UTC_TIMESTAMP(), UTC_TIMESTAMP())");

            $est = ScoreHistory::estimate(3, 2);
            Assert::same(['score' => 43, 'level' => 'attention'], $est, 'estimate: 3 Fail + 2 Warning, all internet-facing');
            $series = App::scoreHistory()->series($cid, 90);
            Assert::same([[43, true], [40, false], [15, false]], array_map(static fn (array $p): array => [$p['score'], $p['estimated']], $series), 'estimated, exact, live today');
            Assert::same(gmdate('Y-m-d'), $series[2]['day']);
            Assert::same(2, count(App::scoreHistory()->series($cid, 30)), 'the 30-day range leaves out the older day');
            $then = App::scoreHistory()->on($cid, gmdate('Y-m-d', time() - 30 * 86400));
            Assert::true($then !== null && $then['score'] === 43 && $then['estimated'], 'the score 30 days ago is the latest day on or before it');
            Assert::same(null, App::scoreHistory()->on($cid, gmdate('Y-m-d', time() - 400 * 86400)));
            Assert::same(null, App::scoreHistory()->on($cid, "2026-01-01' OR '1'='1"), 'a malformed day is refused');
            Assert::same(null, App::scoreHistory()->on($cid, gmdate('Y-m-d', time() - 25 * 86400)), 'a recorded day more than 31 days earlier is not "the score then"');

            // Calibration: a client with 5 internal Fails then and now. Uncalibrated, the old day would read 57 (as if all
            // were internet-facing) against an exact 28 today: a change that never happened.
            $ctx->db->exec("INSERT INTO clients (name, timezone, created_at, updated_at) VALUES ('Score History Internal Example', 'UTC', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
            $internal = (int) $ctx->db->lastInsertId();
            $ctx->db->exec("INSERT INTO finding_stats (client_id, day, fail_open, warn_open, recorded_at) VALUES ({$internal}, UTC_DATE() - INTERVAL 35 DAY, 5, 0, UTC_TIMESTAMP())");
            for ($i = 1; $i <= 5; $i++) {
                $ctx->db->exec("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, target, status, source, first_seen, last_seen)
                                VALUES ({$internal}, 'port:10.0.0.{$i}:445', 'port', 'fail', 'Internal test finding', '10.0.0.{$i}:445', 'open', 'agent', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
            }
            Assert::same(57, ScoreHistory::estimate(5, 0)['score'], 'raw estimate');
            Assert::same([[28, true], [28, false]], array_map(static fn (array $p): array => [$p['score'], $p['estimated']], App::scoreHistory()->series($internal, 90)), 'calibrated: no change');
            Assert::same([], array_values(array_filter(App::scoreHistory()->movers((new \Sentinel\Dashboard\DashboardData($ctx->db, App::settings()))->clients(), 30, 500), static fn (array $m): bool => $m['id'] === $internal)), 'not a mover');

            // Biggest changes: from the estimated 43 to 15.
            $mine = array_values(array_filter(App::scoreHistory()->movers((new \Sentinel\Dashboard\DashboardData($ctx->db, App::settings()))->clients(), 30, 500), static fn (array $m): bool => $m['id'] === $cid));
            Assert::same([43, 15, -28, true], [$mine[0]['from'], $mine[0]['to'], $mine[0]['delta'], $mine[0]['estimated']]);
            Assert::same([], array_values(array_filter(App::scoreHistory()->movers((new \Sentinel\Dashboard\DashboardData($ctx->db, App::settings()))->clients(), 30, 500), static fn (array $m): bool => $m['id'] === $other)), 'no history: not a mover');

            // The daily recorder now stores the exact score.
            (new \Sentinel\Reports\StatsRecorder($ctx->db))->recordToday(true);
            Assert::same(['15', 'attention'], array_map('strval', $ctx->db->query("SELECT score, level FROM finding_stats WHERE client_id = {$cid} AND day = UTC_DATE()")->fetch(PDO::FETCH_NUM)));

            // Client overview: chart, change line, estimate note, range buttons (also in the refresh fragment).
            $admin = $ctx->login('admin', 'Admin-Pass-0001!');
            $page = $admin->get('/clients/' . $cid)->body;
            foreach (['Risk score history', 'class="score-history"', '43 → 15: down 28 (better)', 'estimated from earlier Fail and Warning counts', 'overview?range=90'] as $want) {
                Assert::contains($want, $page);
            }
            Assert::contains('40 → 15: down 25 (better)', $admin->get('/clients/' . $cid . '?range=30')->body);
            Assert::contains('40 → 15: down 25 (better)', $admin->get('/clients/' . $cid . '/overview?range=30')->body, 'the refresh keeps the range');
            Assert::contains('43 → 15', $admin->get('/clients/' . $cid . '?range=7')->body, 'an unknown range falls back to 90 days');
            Assert::true((bool) preg_match('/<section class="hud hud-score".*?<\/section>/s', $page, $panel), 'the panel is there');
            Assert::notContains('style=', $panel[0], 'no inline styles in the new panel (strict CSP)');
            Assert::contains('Biggest changes, last 30 days', $admin->get('/')->body);
            // A user limited to another client never sees this client's change.
            $limited = $ctx->createUser('scorelimited', 'technician', 'Scorelimited-Pass-01!');
            $ctx->db->exec("UPDATE users SET all_clients = 0 WHERE id = {$limited}");
            $ctx->db->exec("INSERT INTO user_clients (user_id, client_id) VALUES ({$limited}, {$other})");
            $mine = $ctx->login('scorelimited', 'Scorelimited-Pass-01!');
            $dash = $mine->get('/')->body;
            Assert::contains('Biggest changes, last 30 days', $dash);
            Assert::notContains('Score History Example', $dash, 'only the user\'s clients');
            Assert::status(404, $mine->get('/clients/' . $cid . '/overview?range=30'));

            // Executive summary: change since the start of the period and the chart.
            $id = App::reportService()->generate(App::clients()->find($cid), 'executive', gmdate('Y-m-d', time() - 45 * 86400), gmdate('Y-m-d'), null, 'Test');
            $html = (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$id}")->fetchColumn();
            Assert::contains('Risk score over time', $html);
            Assert::contains('Risk score 43 at the start of the period and 15 now: down 28 (better).', $html);
            Assert::contains('(The starting score is estimated.)', $html);
            Assert::contains('class="score-history"', $html);
            $tech = App::reportService()->generate(App::clients()->find($cid), 'technical', gmdate('Y-m-d', time() - 45 * 86400), gmdate('Y-m-d'), null, 'Test');
            Assert::notContains('Risk score over time', (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$tech}")->fetchColumn(), 'executive summary only');

            // API: only the token's clients; days checked.
            [, $token] = App::apiTokens()->create('Score history token', false, [$cid], false, false, [], 30, (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn());
            $ctx->db->exec('DELETE FROM auth_throttle');
            $res = json_decode($ctx->api('GET', '/api/v1/clients/' . $cid . '/score-history', $token)->body, true);
            Assert::same([[43, 'needs_attention', true], [40, 'needs_attention', false], [15, 'needs_attention', false]],
                array_map(static fn (array $p): array => [$p['score'], $p['level'], $p['estimated']], $res['data']));
            Assert::same(90, $res['meta']['days']);
            Assert::same(2, count(json_decode($ctx->api('GET', '/api/v1/clients/' . $cid . '/score-history?days=30', $token)->body, true)['data']));
            foreach (['0', '367', 'abc', '1.5'] as $bad) {
                Assert::same(400, $ctx->api('GET', '/api/v1/clients/' . $cid . '/score-history?days=' . $bad, $token)->status, 'days=' . $bad);
            }
            Assert::same(404, $ctx->api('GET', '/api/v1/clients/' . $other . '/score-history', $token)->status, 'another client is not visible');
            Assert::true(isset(json_decode($ctx->api('GET', '/api/v1/openapi.json', $token)->body, true)['paths']['/clients/{id}/score-history']), 'documented');

            // Archived: history without a live point.
            $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$cid}");
            Assert::same(2, count(App::scoreHistory()->series($cid, 90)), 'no live point for an archived client (today is already recorded, so it is left out)');
        } finally {
            $ctx->db->exec("DELETE FROM reports WHERE client_id IN ({$cid}, {$other})");
            $ctx->db->exec("DELETE FROM findings WHERE client_id IN ({$cid}, {$other})");
            $ctx->db->exec("DELETE FROM finding_stats WHERE client_id IN ({$cid}, {$other})");
            $ctx->db->exec("DELETE FROM api_tokens WHERE name = 'Score history token'");
            $ctx->db->exec("DELETE uc FROM user_clients uc JOIN users u ON u.id = uc.user_id WHERE u.username = 'scorelimited'");
            $ctx->db->exec("UPDATE users SET is_active = 0 WHERE username = 'scorelimited'");
            $extra = (int) $ctx->db->query("SELECT COALESCE(MAX(id), 0) FROM clients WHERE name = 'Score History Internal Example'")->fetchColumn();
            foreach ([$cid, $other, $extra] as $x) {
                $ctx->db->exec("DELETE FROM findings WHERE client_id = {$x}");
                $ctx->db->exec("DELETE FROM finding_stats WHERE client_id = {$x}");
                $ctx->db->exec("DELETE FROM clients WHERE id = {$x}");
            }
        }
    },
];
