<?php

declare(strict_types=1);

/**
 * End-to-end tests for the dashboards: the command view and client consoles,
 * the risk score, the 60-second refresh fragments (signed-in only, marked
 * with X-Sentinel-Fragment, escaped), and the trend from recorded counts.
 * Runs late (file name) so earlier tests have created clients, scans and findings.
 */

use Sentinel\Dashboard\DashboardData;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'risk score and level follow the documented formula' => function (TestContext $ctx): void {
        Assert::same(0, DashboardData::score(0, 0, 0));
        Assert::same(2, DashboardData::score(0, 0, 1));
        Assert::same(10, DashboardData::score(0, 1, 0));
        Assert::same(20, DashboardData::score(1, 1, 0), 'a known-exploited Fail counts 20, not 20 + 10');
        Assert::same(52, DashboardData::score(1, 3, 6));
        Assert::same(100, DashboardData::score(9, 9, 50), 'capped at 100');
        Assert::same(['risk', 'attention', 'good'], [DashboardData::level(1, 0), DashboardData::level(0, 3), DashboardData::level(0, 0)]);
    },
    'command view and client console show the panels; refresh fragments are signed-in only' => function (TestContext $ctx): void {
        if ((int) $ctx->db->query('SELECT COUNT(*) FROM clients WHERE is_archived = 0')->fetchColumn() === 0) {
            $ctx->db->exec("INSERT INTO clients (name, timezone, created_at, updated_at) VALUES ('Dashboard Example', 'UTC', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        }
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $dash = $admin->get('/')->body;
        foreach (['Threat level', 'Client risk grid', 'Top exposures', 'Activity', 'Attack surface', 'Certificates, next 30 days', 'Worker', 'data-refresh-url="/dashboard/live"', 'class="gauge'] as $s) {
            Assert::contains($s, $dash);
        }
        $live = $admin->get('/dashboard/live');
        Assert::same(200, $live->status);
        Assert::same('1', $live->header('x-sentinel-fragment'));
        Assert::notContains('<html', $live->body, 'a fragment, not a page');
        Assert::contains('Client risk grid', $live->body);
        Assert::notContains('<script', $live->body, 'scan data in the panels is escaped');

        $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE is_archived = 0 ORDER BY id LIMIT 1")->fetchColumn();
        $page = $admin->get('/clients/' . $cid)->body;
        Assert::contains('data-refresh-url="/clients/' . $cid . '/overview"', $page);
        Assert::contains('RISK / 100', $page);
        $frag = $admin->get('/clients/' . $cid . '/overview');
        Assert::same('1', $frag->header('x-sentinel-fragment'));
        Assert::status(404, $admin->get('/clients/999999/overview'));

        $anon = $ctx->client();
        $res = $anon->get('/dashboard/live');
        Assert::true($res->status === 303 && $res->header('x-sentinel-fragment') === null, 'signed-out: redirected, never a fragment');
        Assert::same(null, $anon->get('/clients/' . $cid . '/overview')->header('x-sentinel-fragment'));

        // The trend uses recorded daily counts.
        $ctx->db->exec("INSERT IGNORE INTO finding_stats (client_id, day, fail_open, warn_open) VALUES ({$cid}, UTC_DATE() - INTERVAL 3 DAY, 7, 2), ({$cid}, UTC_DATE() - INTERVAL 2 DAY, 5, 4)");
        $page = $admin->get('/clients/' . $cid)->body;
        Assert::contains('class="trend"', $page);
        Assert::notContains('The trend builds up day by day', substr($page, 0, (int) strpos($page, 'id="findings"')));
    },
];
