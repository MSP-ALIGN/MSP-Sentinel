<?php

declare(strict_types=1);

/**
 * End-to-end tests for operations tools: the System page and bin/doctor.php
 * (health checks, no secrets in output), the worker heartbeat, the update
 * check (fake releases feed on 127.0.0.1), and data retention. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'System page and doctor: health checks, admins only, no secrets' => function (TestContext $ctx): void {
        $ctx->cli('bin/worker.php', ['--no-schedule']); // records the heartbeat
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $admin->get('/admin/system')->body;
        foreach (['PHP version', 'Database migrations', 'nmap', 'Scan worker (cron)', 'Storage folder'] as $label) {
            Assert::contains($label, $page);
        }
        Assert::true((bool) preg_match('/Scan worker \(cron\)<\/th><td>Last run 0 minute/', $page), 'heartbeat seen');
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'systech'")->fetchColumn() === 0) {
            $ctx->createUser('systech', 'technician', 'Systech-Pass-01!');
        }
        Assert::status(403, $ctx->login('systech', 'Systech-Pass-01!')->get('/admin/system'));

        [$code, $out] = $ctx->cli('bin/doctor.php', ['--json']);
        $json = json_decode($out, true);
        Assert::true(is_array($json) && count($json['checks']) >= 10, 'doctor JSON');
        $byKey = array_column($json['checks'], 'status', 'key');
        Assert::same('ok', $byKey['migrations']);
        Assert::same('ok', $byKey['worker']);
        Assert::same(in_array('fail', $byKey, true) ? 1 : 0, $code, 'exit code reflects failures');
        $cfg = require $ctx->configPath;
        Assert::notContains($cfg['app_key'], $out . $page, 'app key never shown');
        if ((string) ($cfg['db']['pass'] ?? '') !== '') {
            Assert::notContains((string) $cfg['db']['pass'], $out . $page, 'database password never shown');
        }
        [, $text] = $ctx->cli('bin/doctor.php');
        Assert::contains('[ OK ] Database migrations', $text);
    },
    'development builds are marked on every page; release installs are not' => function (TestContext $ctx): void {
        $file = dirname(__DIR__, 2) . '/BUILD';
        Assert::true(!file_exists($file), 'no BUILD file left in the working tree');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::notContains('Development build', $admin->get('/admin/system')->body, 'release or manual install: no badge');
        try {
            file_put_contents($file, "branch=develop\ncommit=0123456789abcdef0123456789abcdef01234567\n");
            $page = $admin->get('/admin/system')->body;
            Assert::contains('Development build', $page);
            Assert::contains('branch develop, commit 0123456789ab', $page);
            Assert::contains('Development build', $admin->get('/')->body, 'badge on every page');
            file_put_contents($file, "branch=main\ncommit=0123456789abcdef0123456789abcdef01234567\n");
            $page = $admin->get('/admin/system')->body;
            Assert::contains('branch main, commit 0123456789ab', $page);
            Assert::notContains('Development build', $page, 'main is production');
            file_put_contents($file, "branch=<script>x</script>\ncommit=nothex\n");
            $page = $admin->get('/admin/system')->body;
            Assert::true(!str_contains($page, '<script>x') && !str_contains($page, 'Development build'), 'a malformed BUILD file is ignored');
        } finally {
            @unlink($file);
        }
    },
    'update now: shows how far behind the branch is; admins request it with one click' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        $build = $root . '/BUILD';
        $request = $root . '/storage/update-request';
        $state = (require $ctx->configPath)['web_update']['state_dir'];
        Assert::true(!file_exists($build) && !file_exists($request), 'clean working tree');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        try {
            // Behind-by check (fake compare API: 3 commits ahead of any installed commit except c...c).
            file_put_contents($build, "branch=develop\ncommit=" . str_repeat('a', 40) . "\nrepo=MSP-ALIGN/MSP-Sentinel\n");
            $admin->submit('/admin/system', '/admin/system/updates', ['action' => 'check']);
            $page = $admin->get('/admin/system')->body;
            Assert::contains('the develop branch has 3 new commit(s) since this install (newest abcdef012345)', $page);
            Assert::notContains('javascript:alert', $page, 'nothing but a count and a commit ID is kept from the answer');
            file_put_contents($build, "branch=develop\ncommit=" . str_repeat('c', 40) . "\nrepo=MSP-ALIGN/MSP-Sentinel\n");
            Assert::notContains('new commit(s)', $admin->get('/admin/system')->body, 'an answer for another commit is never shown');
            $admin->submit('/admin/system', '/admin/system/updates', ['action' => 'check']);
            Assert::contains('Up to date with the develop branch', $admin->get('/admin/system')->body);

            // Not set up on this server (no runner): no button, and a request is refused.
            Assert::contains('Updating from the web interface is turned off on this server', $admin->get('/admin/system')->body);
            @mkdir($state, 0750, true);
            touch($state . '/enabled');
            $page = $admin->get('/admin/system')->body;
            Assert::contains('action="/admin/system/update"', $page);

            // Technicians can't ask at all.
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'updtech'")->fetchColumn() === 0) {
                $ctx->createUser('updtech', 'technician', 'Updtech-Pass-01!');
            }
            $tech = $ctx->login('updtech', 'Updtech-Pass-01!');
            Assert::status(403, $tech->post('/admin/system/update', ['_csrf' => $tech->get('/')->csrf()]));
            $admin->post('/admin/system/update', []); // no CSRF token
            Assert::true(!file_exists($request), 'nothing requested by a technician or without a CSRF token');

            // One click by an admin: an EMPTY request file appears (nothing from the request reaches the root runner).
            $admin->submit('/admin/system', '/admin/system/update', []);
            Assert::true(is_file($request) && filesize($request) === 0, 'empty request file created');
            Assert::contains('Update requested', $admin->get('/admin/system')->body);
            Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'system.update_requested'")->fetchColumn(), 'audited');
            Assert::contains('The update was requested', $admin->get('/admin/system')->body);
            $admin->submit('/admin/system', '/admin/system/update', []);
            Assert::contains('already waiting or running', $admin->get('/admin/system')->body);

            // The runner's progress is shown (status checked, log scrubbed and escaped).
            unlink($request);
            file_put_contents($state . '/status.json', json_encode(['state' => 'running', 'started' => gmdate('Y-m-d H:i:s'), 'finished' => '', 'exit' => 0]));
            file_put_contents($state . '/update.log', "==> Backing up first\n\e[32mok\e[0m <script>alert(1)</script>\n");
            $page = $admin->get('/admin/system')->body;
            Assert::contains('Running', $page);
            Assert::contains('==&gt; Backing up first', $page);
            Assert::true(!str_contains($page, '<script>alert(1)') && !str_contains($page, "\e["), 'log escaped and scrubbed');
            Assert::notContains('action="/admin/system/update"', $page, 'no second request while running');
            // Finished a moment ago: the page says when the next update can start, and a click is refused with that.
            file_put_contents($state . '/status.json', json_encode(['state' => 'done', 'started' => gmdate('Y-m-d H:i:s'), 'finished' => gmdate('Y-m-d H:i:s'), 'exit' => 0]));
            Assert::contains('One update every 15 minutes', $admin->get('/admin/system')->body);
            $admin->submit('/admin/system', '/admin/system/update', []);
            Assert::contains('You can start the next one in', $admin->get('/admin/system')->body);
            Assert::true(!file_exists($request), 'no request the runner would ignore');
            file_put_contents($state . '/status.json', json_encode(['state' => 'failed', 'started' => gmdate('Y-m-d H:i:s', time() - 3600), 'finished' => gmdate('Y-m-d H:i:s', time() - 3500), 'exit' => 1]));
            $page = $admin->get('/admin/system')->body;
            Assert::contains('stopped with an error', $page);
            Assert::contains('action="/admin/system/update"', $page, 'can try again after a failure');
            // A request nobody picks up (the helper on the server is stopped) is pointed out and can be removed.
            touch($request, time() - 600);
            $page = $admin->get('/admin/system')->body;
            Assert::contains('was not picked up', $page);
            $admin->submit('/admin/system', '/admin/system/update', ['action' => 'cancel']);
            Assert::true(!file_exists($request), 'waiting request removed');
            file_put_contents($state . '/status.json', '{"state":"<b>","started":"x"}');
            Assert::notContains('<b>', $admin->get('/admin/system')->body, 'a malformed status file is ignored');

        } finally {
            @unlink($build);
            @unlink($request);
            foreach (['enabled', 'status.json', 'update.log'] as $f) {
                @unlink($state . '/' . $f);
            }
        }
    },
    'update check: reads only a version number; can be turned off' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/system', '/admin/system/updates', ['action' => 'check']);
        $page = $admin->get('/admin/system')->body;
        Assert::contains('Version 9.9.9 is available', $page);
        Assert::notContains('javascript:alert', $page, 'no URL from the feed is used');
        Assert::same('9.9.9', App::settings()->fresh('update_latest_version'));
        $pre = new \Sentinel\System\UpdateChecker(App::settings(), str_replace('/latest', '/pre', (require $ctx->configPath)['updates']['url']), App::version(), true);
        Assert::same(null, $pre->check(true), 'pre-releases ignored');
        $https = new \Sentinel\System\UpdateChecker(App::settings(), (require $ctx->configPath)['updates']['url'], App::version(), false);
        Assert::same(null, $https->check(true), 'plain http refused outside the test suite');
        $admin->submit('/admin/system', '/admin/system/updates', ['update_check_enabled' => '0']);
        App::settings()->set('update_check_enabled', App::settings()->fresh('update_check_enabled'));
        Assert::same(null, App::updates()->newer(), 'off: no update notice');
        Assert::notContains('Version 9.9.9 is available', $admin->get('/admin/system')->body);
        $admin->submit('/admin/system', '/admin/system/updates', ['update_check_enabled' => '1']);
        App::settings()->set('update_latest_version', '');
    },
    'data retention removes only old data and never the audit log' => function (TestContext $ctx): void {
        $db = $ctx->db;
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/system', '/admin/system/retention', ['retention_scans' => '1', 'retention_findings' => 'x', 'retention_reports' => '1']);
        Assert::contains('Enter whole months', $admin->get('/admin/system')->body);
        $admin->submit('/admin/system', '/admin/system/retention', ['retention_scans' => '1', 'retention_findings' => '1', 'retention_reports' => '1']);
        App::settings()->set('retention_scans_months', '1');
        App::settings()->set('retention_findings_months', '1');
        App::settings()->set('retention_reports_months', '1');

        $db->exec("INSERT INTO clients (name, timezone, created_at, updated_at) VALUES ('Retention Example', 'UTC', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $cid = (int) $db->lastInsertId();
        foreach (['old' => 'UTC_TIMESTAMP() - INTERVAL 3 MONTH', 'new' => 'UTC_TIMESTAMP()'] as $tag => $when) {
            $db->exec("INSERT INTO scan_jobs (client_id, trigger_type, status, payload, created_at, finished_at) VALUES ({$cid}, 'manual', 'done', '{}', {$when}, {$when})");
            $job = (int) $db->lastInsertId();
            $db->exec("INSERT INTO scan_log (job_id, client_id, target, ports, result, started_at) VALUES ({$job}, {$cid}, '203.0.113.99', '80', 'done', {$when})");
            $db->exec("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, target, status, first_seen, last_seen, resolved_at)
                       VALUES ({$cid}, 'port:203.0.113.99:{$tag}', 'port', 'warn', 'Retention {$tag}', '203.0.113.99:21', 'resolved', {$when}, {$when}, {$when})");
            $f = (int) $db->lastInsertId();
            $db->exec("INSERT INTO finding_events (finding_id, event, created_at) VALUES ({$f}, 'opened', {$when})");
            $db->exec("INSERT INTO reports (client_id, kind, title, period_start, period_end, generated_at, html, snapshot, html_sha256)
                       VALUES ({$cid}, 'executive', 'Retention {$tag}', UTC_DATE(), UTC_DATE(), {$when}, '<p>x</p>', '{}', REPEAT('a', 64))");
        }
        $auditBefore = (int) $db->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
        $counts = App::retention()->run(true);
        Assert::true($counts['scans'] >= 1 && $counts['findings'] >= 1 && $counts['reports'] >= 1, 'old rows removed: ' . json_encode($counts));
        Assert::same(1, (int) $db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn(), 'recent scan kept');
        Assert::same(['Retention new'], $db->query("SELECT title FROM findings WHERE client_id = {$cid}")->fetchAll(PDO::FETCH_COLUMN));
        Assert::same(['Retention new'], $db->query("SELECT title FROM reports WHERE client_id = {$cid}")->fetchAll(PDO::FETCH_COLUMN));
        Assert::same($auditBefore + 1, (int) $db->query('SELECT COUNT(*) FROM audit_log')->fetchColumn(), 'audit log only grows (one retention entry)');
        Assert::same(null, App::retention()->run(), 'runs at most once a day');
        foreach (['scans', 'findings', 'reports'] as $k) {
            App::settings()->set('retention_' . $k . '_months', '0');
        }
    },
];
