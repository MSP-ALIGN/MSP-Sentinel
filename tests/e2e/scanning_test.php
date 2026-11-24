<?php

declare(strict_types=1);

/**
 * End-to-end tests: queueing scans, the worker (with the fake nmap, which never
 * sends packets), scope re-checks, windows, cancelling, kill switches, the
 * schedule and the scan log. Documentation addresses and *.example names only.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\HttpClient;
use Sentinel\Tests\TestContext;

/** A client whose scan window is open now (UTC) or closed now, with an active authorisation. */
$scanClient = static function (TestContext $ctx, HttpClient $admin, string $name, string $scope, bool $windowOpen = true, string $extra = '', string $excluded = ''): int {
    $now = (int) gmdate('G');
    [$from, $to] = $windowOpen ? [($now + 23) % 24, ($now + 1) % 24] : [($now + 2) % 24, ($now + 3) % 24];
    $res = $admin->submit('/clients/new', '/clients', ['name' => $name, 'itflow_client_id' => '', 'timezone' => 'UTC',
        'scan_window_start' => sprintf('%02d:00', $from), 'scan_window_end' => sprintf('%02d:00', $to), 'notes' => '',
        'ports_extra' => $extra, 'ports_excluded' => $excluded]);
    $id = (int) basename((string) $res->location());
    $admin->submit('/clients/' . $id . '/authorisations/new', '/clients/' . $id . '/authorisations', [
        'approved_by_name' => 'Sam Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
        'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
        'document_ref' => '', 'notes' => '', 'scope' => $scope, 'confirm' => '1',
    ]);
    return $id;
};
$job = static function (TestContext $ctx, int $clientId): array {
    return $ctx->db->query("SELECT * FROM scan_jobs WHERE client_id = {$clientId} ORDER BY id DESC LIMIT 1")->fetch() ?: [];
};
$nmapTargets = static function (TestContext $ctx): array {
    $out = [];
    foreach (is_file($ctx->nmapLog) ? file($ctx->nmapLog, FILE_IGNORE_NEW_LINES) : [] as $line) {
        $args = json_decode($line, true);
        $out[] = end($args);
    }
    return $out;
};

return [
    'technician queues a scan; the worker scans only in-scope addresses' => function (TestContext $ctx) use ($scanClient, $job, $nmapTargets): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        // Scope: two IPs plus discovery.example's names. www.discovery.example resolves (via an outside alias) to
        // 198.51.100.50, which is NOT in scope; vpn.discovery.example resolves to 203.0.113.30 (not in scope) and 2001:db8:10::30 (in scope).
        $id = $scanClient($ctx, $admin, 'Scan Example Ltd', "203.0.113.160\n203.0.113.161\nwww.discovery.example\nvpn.discovery.example\n2001:db8:10::30");
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'stech'")->fetchColumn() === 0) {
            $ctx->createUser('stech', 'technician', 'Stech-Pass-0001!');
            $ctx->createUser('sview', 'viewer', 'Sview-Pass-0001!');
        }
        $view = $ctx->login('sview', 'Sview-Pass-0001!');
        Assert::status(403, $view->submit('/clients/' . $id, '/clients/' . $id . '/scan', []), 'viewer cannot queue');
        Assert::notContains('Scan now', $ctx->clientPages($view, (int) $id));

        $tech = $ctx->login('stech', 'Stech-Pass-0001!');
        Assert::redirect('/clients/' . $id . '/scans', $tech->submit('/clients/' . $id, '/clients/' . $id . '/scan', []));
        Assert::same('queued', $job($ctx, $id)['status']);
        Assert::contains('A scan for this client is already queued', ($tech->submit('/clients/' . $id, '/clients/' . $id . '/scan', []) && true) ? $ctx->clientPages($tech, (int) $id) : '');

        @unlink($ctx->nmapLog);
        [$code, $out] = $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job($ctx, $id)['id']]);
        Assert::same(0, $code, $out);
        $j = $job($ctx, $id);
        Assert::same('done', $j['status'], $out);
        $targets = $nmapTargets($ctx);
        sort($targets);
        Assert::same(['2001:db8:10::30', '203.0.113.160', '203.0.113.161'], $targets, 'nmap only ever saw in-scope addresses');

        $log = $ctx->db->query("SELECT target, result, detail FROM scan_log WHERE client_id = {$id} AND result <> 'checked' ORDER BY target")->fetchAll();
        $byTarget = array_column($log, null, 'target');
        Assert::same('skipped_out_of_scope', $byTarget['198.51.100.50']['result'], 'outside alias address skipped');
        Assert::contains('www.discovery.example', $byTarget['198.51.100.50']['detail']);
        Assert::same('skipped_out_of_scope', $byTarget['203.0.113.30']['result']);
        Assert::same('scanned', $byTarget['203.0.113.160']['result']);

        $page = $ctx->clientPages($admin, (int) $id);
        Assert::contains('OpenSSH 8.9p1', $page);
        Assert::contains('High risk: Remote Desktop', $page, 'RDP flagged');
        Assert::notContains('<script>alert(1)</script>', $page, 'banner text escaped');
        Assert::notContains('31337', $page, 'ports that were not asked for are not stored');
        Assert::notContains('192.0.2.250', $page, 'other hosts in nmap output ignored');
        Assert::contains('Example v6 httpd', $page);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.ip = '192.0.2.250'")->fetchColumn());
    },
    'a later scan closes ports that are no longer open' => function (TestContext $ctx) use ($job): void {
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Scan Example Ltd'")->fetchColumn();
        $asset = (int) $ctx->db->query("SELECT id FROM assets WHERE client_id = {$id} AND ip = '203.0.113.161'")->fetchColumn();
        $ctx->db->exec("INSERT INTO services (asset_id, port, protocol, is_open, first_seen, last_seen) VALUES ({$asset}, 8080, 'tcp', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job($ctx, $id)['id']]);
        Assert::same('done', $job($ctx, $id)['status']);
        Assert::same(0, (int) $ctx->db->query("SELECT is_open FROM services WHERE asset_id = {$asset} AND port = 8080")->fetchColumn(), 'closed');
        Assert::same(1, (int) $ctx->db->query("SELECT is_open FROM services WHERE asset_id = {$asset} AND port = 80")->fetchColumn(), 'still open');
    },
    'a host that times out does not close its known open ports' => function (TestContext $ctx) use ($scanClient, $job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $scanClient($ctx, $admin, 'Tarpit Example', '203.0.113.166');
        $ctx->db->exec("INSERT INTO assets (client_id, ip, first_seen, last_seen) VALUES ({$id}, '203.0.113.166', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $asset = (int) $ctx->db->lastInsertId();
        $ctx->db->exec("INSERT INTO services (asset_id, port, protocol, is_open, first_seen, last_seen) VALUES ({$asset}, 3389, 'tcp', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job($ctx, $id)['id']]);
        Assert::same(1, (int) $ctx->db->query("SELECT is_open FROM services WHERE asset_id = {$asset} AND port = 3389")->fetchColumn(), 'RDP still recorded as open');
        Assert::contains('(incomplete)', (string) $ctx->db->query("SELECT detail FROM scan_log WHERE client_id = {$id}")->fetchColumn());
    },
    'a large IPv6 scope fits in a job' => function (TestContext $ctx): void {
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Tarpit Example'")->fetchColumn();
        $ips = [];
        for ($i = 0; $i < 2048; $i++) {
            $ips[] = sprintf('2001:db8:%x:%x:%x:%x:%x:%x', $i, $i, $i, $i, $i, $i);
        }
        $jobId = \Sentinel\Core\App::scans()->queue($id, 'manual', null, false, null, ['ips' => $ips, 'hostnames' => [], 'ports' => [22]]);
        Assert::same(2048, count(\Sentinel\Core\App::scans()->find($jobId)['payload']['ips']), 'payload stored in full');
        \Sentinel\Core\App::scans()->cancel($jobId);
    },
    'when the window closes mid-job, the rest is queued for the next window' => function (TestContext $ctx) use ($scanClient, $job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $scanClient($ctx, $admin, 'Window Closes Example', "203.0.113.170\n203.0.113.172\n203.0.113.173");
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $first = (int) $job($ctx, $id)['id'];
        $proc = proc_open([PHP_BINARY, $ctx->root . '/bin/worker.php', '--no-schedule', '--job=' . $first], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $ctx->root,
            ['SENTINEL_CONFIG' => $ctx->configPath, 'PATH' => (string) getenv('PATH'), 'SENTINEL_ALLOW_ROOT' => '1']);
        for ($i = 0; $i < 50 && ($ctx->db->query("SELECT status FROM scan_jobs WHERE id = {$first}")->fetchColumn()) !== 'running'; $i++) {
            usleep(100000);
        }
        usleep(500000);
        $h = ((int) gmdate('G') + 2) % 24;
        $ctx->db->exec(sprintf("UPDATE clients SET scan_window_start = '%02d:00:00', scan_window_end = '%02d:00:00' WHERE id = %d", $h, ($h + 1) % 24, $id));
        stream_get_contents($pipes[1]);
        proc_close($proc);
        Assert::same('partial', $ctx->db->query("SELECT status FROM scan_jobs WHERE id = {$first}")->fetchColumn());
        $follow = $job($ctx, $id);
        Assert::true((int) $follow['id'] !== $first && $follow['status'] === 'queued', 'follow-up job queued');
        $ips = json_decode((string) $follow['payload'], true)['ips'];
        sort($ips);
        Assert::same(['203.0.113.170', '203.0.113.172', '203.0.113.173'], $ips, 'unfinished and unscanned addresses carried over');
        \Sentinel\Core\App::scans()->cancel((int) $follow['id']);
    },
    'an address leaving scope mid-scan is skipped; the job carries on' => function (TestContext $ctx) use ($scanClient, $job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $scanClient($ctx, $admin, 'Scope Change Example', "203.0.113.170\n203.0.113.174");
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $jobId = (int) $job($ctx, $id)['id'];
        $proc = proc_open([PHP_BINARY, $ctx->root . '/bin/worker.php', '--no-schedule', '--job=' . $jobId], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $ctx->root,
            ['SENTINEL_CONFIG' => $ctx->configPath, 'PATH' => (string) getenv('PATH'), 'SENTINEL_ALLOW_ROOT' => '1']);
        for ($i = 0; $i < 50 && ($ctx->db->query("SELECT status FROM scan_jobs WHERE id = {$jobId}")->fetchColumn()) !== 'running'; $i++) {
            usleep(100000);
        }
        usleep(500000);
        // The admin replaces the authorisation with one that no longer includes 203.0.113.170.
        $ctx->db->exec("DELETE FROM scope_entries WHERE client_id = {$id} AND value = '203.0.113.170'");
        stream_get_contents($pipes[1]);
        proc_close($proc);
        $results = $ctx->db->query("SELECT target, result FROM scan_log WHERE job_id = {$jobId}")->fetchAll(PDO::FETCH_KEY_PAIR);
        Assert::same(['203.0.113.170' => 'stopped', '203.0.113.174' => 'scanned'], $results, 'only that host stopped');
        Assert::same('done', $ctx->db->query("SELECT status FROM scan_jobs WHERE id = {$jobId}")->fetchColumn());
    },
    'outside the window: jobs wait; only admins may override, with a reason' => function (TestContext $ctx) use ($scanClient, $job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $scanClient($ctx, $admin, 'Night Window Example', '203.0.113.161', false);
        $tech = $ctx->login('stech', 'Stech-Pass-0001!');
        $page = $tech->get('/clients/' . $id);
        $all = $ctx->clientPages($tech, (int) $id);
        Assert::notContains('Run outside the window', $all, 'technicians have no override');
        Assert::status(403, $tech->post('/clients/' . $id . '/scan', ['_csrf' => $page->csrf(), 'outside_window' => '1', 'reason' => 'urgent']), 'technician override refused');
        $tech->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job($ctx, $id)['id']]);
        Assert::same('queued', $job($ctx, $id)['status'], 'waits for the window');
        $admin->submit('/clients/' . $id, '/scans/' . $job($ctx, $id)['id'] . '/cancel', []);
        Assert::same('cancelled', $job($ctx, $id)['status']);

        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', ['outside_window' => '1', 'reason' => '']);
        Assert::contains('Give a reason', $ctx->clientSection($admin, (int) $id, 'scans'));
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', ['outside_window' => '1', 'reason' => 'Client asked for a re-check after a firewall change']);
        [$code, $out] = $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job($ctx, $id)['id']]);
        Assert::same('done', $job($ctx, $id)['status'], $out);
        $audit = (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'scan.queued' ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::contains('firewall change', $audit, 'override reason audited');
    },
    'nmap errors and bad output are logged; the job is partial' => function (TestContext $ctx) use ($scanClient, $job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $scanClient($ctx, $admin, 'Broken Hosts Example', "203.0.113.162\n203.0.113.163\n203.0.113.164");
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job($ctx, $id)['id']]);
        Assert::same('partial', $job($ctx, $id)['status']);
        $results = $ctx->db->query("SELECT target, result FROM scan_log WHERE client_id = {$id} ORDER BY target")->fetchAll(PDO::FETCH_KEY_PAIR);
        Assert::same(['203.0.113.162' => 'error', '203.0.113.163' => 'error', '203.0.113.164' => 'scanned'], $results);
    },
    'cancelling a running scan stops nmap within seconds' => function (TestContext $ctx) use ($scanClient, $job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $scanClient($ctx, $admin, 'Slow Host Example', "203.0.113.170\n203.0.113.171");
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $proc = proc_open([PHP_BINARY, $ctx->root . '/bin/worker.php', '--no-schedule', '--job=' . $job($ctx, $id)['id']], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $ctx->root,
            ['SENTINEL_CONFIG' => $ctx->configPath, 'PATH' => (string) getenv('PATH'), 'SENTINEL_ALLOW_ROOT' => '1']);
        for ($i = 0; $i < 50 && ($job($ctx, $id)['status'] ?? '') !== 'running'; $i++) {
            usleep(100000);
        }
        usleep(500000);
        $start = microtime(true);
        $admin->submit('/clients/' . $id, '/scans/' . $job($ctx, $id)['id'] . '/cancel', []);
        stream_get_contents($pipes[1]);
        proc_close($proc);
        Assert::true(microtime(true) - $start < 8, 'worker stopped quickly (the fake host would take 30 s)');
        Assert::same('cancelled', $job($ctx, $id)['status']);
        $results = $ctx->db->query("SELECT target, result FROM scan_log WHERE client_id = {$id}")->fetchAll(PDO::FETCH_KEY_PAIR);
        Assert::same(['203.0.113.170' => 'stopped'], $results, 'second host never touched');
    },
    'pausing all scanning stops a running scan' => function (TestContext $ctx) use ($job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Slow Host Example'")->fetchColumn();
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $proc = proc_open([PHP_BINARY, $ctx->root . '/bin/worker.php', '--no-schedule', '--job=' . $job($ctx, $id)['id']], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $ctx->root,
            ['SENTINEL_CONFIG' => $ctx->configPath, 'PATH' => (string) getenv('PATH'), 'SENTINEL_ALLOW_ROOT' => '1']);
        for ($i = 0; $i < 50 && ($job($ctx, $id)['status'] ?? '') !== 'running'; $i++) {
            usleep(100000);
        }
        usleep(500000);
        $admin->submit('/', '/scanning/pause', []);
        stream_get_contents($pipes[1]);
        proc_close($proc);
        Assert::same('partial', $job($ctx, $id)['status']);
        Assert::contains('paused', (string) $job($ctx, $id)['summary']);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        Assert::contains('Scanning is paused', $ctx->clientSection($admin, (int) $id, 'scans'), 'nothing can be queued while paused');
        $admin->submit('/', '/scanning/resume', []);
    },
    'weekly schedule queues eligible clients once; orphaned jobs are recovered' => function (TestContext $ctx): void {
        $ctx->db->exec("DELETE FROM scan_log WHERE job_id IN (SELECT id FROM scan_jobs WHERE status = 'queued')");
        $ctx->db->exec("UPDATE scan_jobs SET status = 'cancelled' WHERE status IN ('queued','running')");
        $ctx->db->exec("UPDATE clients SET scan_window_start = '00:00:00', scan_window_end = '00:01:00'"); // windows closed: jobs only get queued
        $ctx->cli('bin/worker.php');
        $scheduled = (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE trigger_type = 'scheduled' AND status = 'queued'")->fetchColumn();
        Assert::true($scheduled >= 3, 'clients with active scope get a weekly job');
        $noScope = (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs j JOIN clients c ON c.id = j.client_id WHERE c.name = 'No Auth Example'")->fetchColumn();
        Assert::same(0, $noScope, 'clients without scope are skipped');
        $ctx->cli('bin/worker.php');
        Assert::same($scheduled, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE trigger_type = 'scheduled'")->fetchColumn(), 'not queued twice');

        // Jobs cancelled by a pause don't count: the weekly scan is queued again.
        $ctx->db->exec("UPDATE scan_jobs SET status = 'cancelled' WHERE trigger_type = 'scheduled'");
        $ctx->cli('bin/worker.php');
        Assert::same($scheduled, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE trigger_type = 'scheduled' AND status = 'queued'")->fetchColumn(), 'requeued after cancellation');

        $ctx->db->exec("UPDATE scan_jobs SET status = 'running' WHERE trigger_type = 'scheduled' AND status = 'queued' ORDER BY id LIMIT 1");
        $ctx->cli('bin/worker.php');
        Assert::contains('worker stopped unexpectedly', (string) $ctx->db->query("SELECT summary FROM scan_jobs WHERE status = 'failed' ORDER BY id DESC LIMIT 1")->fetchColumn());
        $ctx->db->exec("UPDATE scan_jobs SET status = 'cancelled' WHERE status = 'queued'");
    },
    'per-client port settings: validated, extras scanned, exclusions never scanned' => function (TestContext $ctx) use ($scanClient, $job): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $bad = $admin->submit('/clients/new', '/clients', ['name' => 'Bad Ports Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '22:00', 'scan_window_end' => '06:00', 'notes' => '', 'ports_extra' => '80;id', 'ports_excluded' => '70000']);
        Assert::status(422, $bad);
        Assert::contains('is not a port or range', $bad->body);
        Assert::contains('between 1 and 65535', $bad->body);
        $id = $scanClient($ctx, $admin, 'Custom Ports Example', '203.0.113.165', true, '8090, 9000-9002', '23,3389');
        @unlink($ctx->nmapLog);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/scan', []);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job($ctx, $id)['id']]);
        $args = json_decode(trim((string) file_get_contents($ctx->nmapLog)), true);
        $p = $args[array_search('-p', $args, true) + 1];
        Assert::contains('8090', $p);
        Assert::contains('9000-9002', $p);
        Assert::true(!preg_match('/(^|,)23(,|-|$)/', $p) && !str_contains($p, '3389'), 'excluded ports not scanned: ' . $p);
    },
    'the worker refuses to run as root unless explicitly allowed' => function (TestContext $ctx): void {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            return; // only meaningful when the tests run as root
        }
        $proc = proc_open([PHP_BINARY, $ctx->root . '/bin/worker.php'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $ctx->root,
            ['SENTINEL_CONFIG' => $ctx->configPath, 'PATH' => (string) getenv('PATH')]);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        Assert::same(1, proc_close($proc));
        Assert::contains('Refusing to run the scan worker as root', $out);
    },
];
