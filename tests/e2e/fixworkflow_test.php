<?php

declare(strict_types=1);

/**
 * End-to-end tests for the fix workflow: due dates by severity and KEV, the
 * admin policy and per-finding dates, assignment (who may assign whom) with
 * its alerts, owner and due filters, daily reminders, and "verify fix"
 * rechecks that touch only the finding's own target, in scope, at most every
 * 10 minutes. Mock hosts and DNS only; made-up data.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$setup = static function (TestContext $ctx): int {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Fixflow Example'")->fetchColumn();
    if ($cid > 0) {
        return $cid;
    }
    foreach ([['fixtech', 'technician'], ['fixview', 'viewer'], ['fixadmin', 'admin']] as [$u, $role]) {
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = '{$u}'")->fetchColumn() === 0) {
            $ctx->createUser($u, $role, 'Fixflow-Pass-0001!');
        }
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $now = (int) gmdate('G');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Fixflow Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
        'scan_window_start' => sprintf('%02d:00', ($now + 23) % 24), 'scan_window_end' => sprintf('%02d:00', ($now + 1) % 24), 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
        'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '',
        'scope' => "203.0.113.190\n203.0.113.192\nmail-weak.example", 'confirm' => '1']);
    $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
    $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
    $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
    return $cid;
};
$fid = static fn (TestContext $ctx, int $cid, string $key): int => (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$cid} AND finding_key = " . $ctx->db->quote($key))->fetchColumn();
$daysDue = static fn (TestContext $ctx, int $id): int => (int) $ctx->db->query("SELECT TIMESTAMPDIFF(DAY, opened_at, due_at) FROM findings WHERE id = {$id}")->fetchColumn();
// Email addresses and email settings only while a test needs them, so other test files see their own setup.
$withEmail = static function (TestContext $ctx, callable $fn): void {
    $ctx->db->exec("UPDATE users SET email = CONCAT(username, '@msp.example') WHERE username IN ('fixadmin', 'fixtech')");
    $old = [App::settings()->fresh('email_enabled'), App::settings()->fresh('team_addresses')];
    App::settings()->set('email_enabled', '1');
    App::settings()->set('team_addresses', 'team@msp.example');
    try {
        $fn();
    } finally {
        $ctx->db->exec("UPDATE users SET email = '' WHERE username IN ('fixadmin', 'fixtech')");
        App::settings()->set('email_enabled', $old[0]);
        App::settings()->set('team_addresses', $old[1]);
    }
};
$userId = static fn (TestContext $ctx, string $u): int => (int) $ctx->db->query("SELECT id FROM users WHERE username = " . $ctx->db->quote($u))->fetchColumn();

return [
    'due dates follow severity, KEV and the admin policy' => function (TestContext $ctx) use ($setup, $fid, $daysDue): void {
        $cid = $setup($ctx);
        $rdp = $fid($ctx, $cid, 'port:203.0.113.192:3389');
        $hsts = $fid($ctx, $cid, 'site:203.0.113.190:443:missing_hsts');
        $wp = $fid($ctx, $cid, 'webvuln:203.0.113.190:80:WordPress:CVE-2099-0202');
        Assert::true($rdp > 0 && $hsts > 0 && $wp > 0, 'findings exist');
        Assert::same(14, $daysDue($ctx, $rdp), 'Fail: 14 days');
        Assert::same(30, $daysDue($ctx, $hsts), 'Warning: 30 days');
        $ctx->db->exec("INSERT IGNORE INTO kev_catalog (cve_id, vendor, product, name) VALUES ('CVE-2099-0202', 'Example', 'WordPress', 'Made-up test entry')");
        App::fixWorkflow()->recomputeDue($cid);
        Assert::same(7, $daysDue($ctx, $wp), 'known exploited: 7 days');

        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('Due dates (fix workflow)', $admin->get('/admin/settings')->body);
        $admin->submit('/admin/settings', '/admin/settings/due-dates', ['due_days_kev' => '0', 'due_days_fail' => '14', 'due_days_warn' => '30']);
        Assert::same('7', App::settings()->fresh('due_days_kev'), 'invalid value rejected');
        Assert::redirect('/admin/settings#due-dates', $admin->submit('/admin/settings', '/admin/settings/due-dates', ['due_days_kev' => '3', 'due_days_fail' => '10', 'due_days_warn' => '60']));
        Assert::same([3, 10, 60], [$daysDue($ctx, $wp), $daysDue($ctx, $rdp), $daysDue($ctx, $hsts)], 'policy change applies at once');
        Assert::contains('settings.due_policy_updated', (string) $ctx->db->query("SELECT GROUP_CONCAT(action) FROM audit_log")->fetchColumn());
        $tech = $ctx->login('fixtech', 'Fixflow-Pass-0001!');
        Assert::status(403, $tech->submit('/findings', '/admin/settings/due-dates', ['due_days_kev' => '1', 'due_days_fail' => '1', 'due_days_warn' => '1']), 'technicians cannot change the policy');
        $admin->submit('/admin/settings', '/admin/settings/due-dates', ['due_days_kev' => '7', 'due_days_fail' => '14', 'due_days_warn' => '30']);
    },
    'admins set and reset a finding\'s own due date; a reopened finding gets a new deadline' => function (TestContext $ctx) use ($setup, $fid, $daysDue): void {
        $cid = $setup($ctx);
        $id = $fid($ctx, $cid, 'port:203.0.113.192:3389');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $tech = $ctx->login('fixtech', 'Fixflow-Pass-0001!');
        $date = gmdate('Y-m-d', time() + 5 * 86400);
        Assert::status(403, $tech->submit('/findings/' . $id, '/findings/' . $id . '/due', ['due_date' => $date, 'due_note' => 'x']), 'admins only');
        Assert::status(422, $admin->submit('/findings/' . $id, '/findings/' . $id . '/due', ['due_date' => $date, 'due_note' => '']), 'reason required');
        Assert::status(422, $admin->submit('/findings/' . $id, '/findings/' . $id . '/due', ['due_date' => '2026-02-30', 'due_note' => 'x']), 'real dates only');
        $admin->submit('/findings/' . $id, '/findings/' . $id . '/due', ['due_date' => $date, 'due_note' => 'Change window agreed with the client']);
        Assert::same([$date . ' 23:59:59', 1], array_values($ctx->db->query("SELECT due_at, due_custom FROM findings WHERE id = {$id}")->fetch(PDO::FETCH_NUM)), 'own date');
        App::fixWorkflow()->recomputeDue($cid);
        Assert::same($date . ' 23:59:59', (string) $ctx->db->query("SELECT due_at FROM findings WHERE id = {$id}")->fetchColumn(), 'not overwritten by the policy');
        $admin->submit('/findings/' . $id, '/findings/' . $id . '/due', ['reset' => '1', 'due_date' => '', 'due_note' => 'Back to normal']);
        Assert::same(14, $daysDue($ctx, $id), 'policy again');
        // Accept, then reopen by hand: the original (overdue) deadline stays. Accepting and reopening is no way to reset it.
        $ctx->db->exec("UPDATE findings SET opened_at = UTC_TIMESTAMP() - INTERVAL 40 DAY WHERE id = {$id}");
        App::fixWorkflow()->recomputeDue($cid);
        $admin->submit('/findings/' . $id, '/findings/' . $id . '/triage', ['status' => 'accepted', 'note' => 'Client accepts for now']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id = {$id} AND status = 'open' AND due_at < UTC_TIMESTAMP()")->fetchColumn(), 'accepted risks are never overdue');
        $admin->submit('/findings/' . $id, '/findings/' . $id . '/triage', ['status' => 'open', 'note' => 'Client changed their mind']);
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id = {$id} AND status = 'open' AND due_at < UTC_TIMESTAMP()")->fetchColumn(), 'still overdue after accept and reopen');
        Assert::same('23:59:59', substr((string) $ctx->db->query("SELECT due_at FROM findings WHERE id = {$id}")->fetchColumn(), 11), 'due at the end of the day');
    },
    'assignment: technicians and admins assign to technicians and admins, with alerts and history' => function (TestContext $ctx) use ($setup, $fid, $userId, $withEmail): void {
        $cid = $setup($ctx);
        $withEmail($ctx, function () use ($ctx, $cid, $fid, $userId): void {
        $id = $fid($ctx, $cid, 'site:203.0.113.190:80:exposed_git');
        $tech = $ctx->login('fixtech', 'Fixflow-Pass-0001!');
        $viewer = $ctx->login('fixview', 'Fixflow-Pass-0001!');
        $adminId = $userId($ctx, 'fixadmin');
        Assert::status(403, $viewer->submit('/findings/' . $id, '/findings/' . $id . '/assign', ['assignee' => 'me']), 'viewers cannot assign');
        Assert::status(422, $tech->submit('/findings/' . $id, '/findings/' . $id . '/assign', ['assignee' => (string) $userId($ctx, 'fixview')]), 'viewers cannot own findings');
        Assert::status(422, $tech->submit('/findings/' . $id, '/findings/' . $id . '/assign', ['assignee' => '999999']), 'unknown user');
        $before = (int) $ctx->db->query("SELECT COUNT(*) FROM deliveries WHERE recipient = 'fixadmin@msp.example'")->fetchColumn();
        Assert::redirect('/findings/' . $id, $tech->submit('/findings/' . $id, '/findings/' . $id . '/assign', ['assignee' => (string) $adminId]));
        Assert::same($adminId, (int) $ctx->db->query("SELECT assigned_to FROM findings WHERE id = {$id}")->fetchColumn());
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$adminId} AND kind = 'assigned' AND link = '/findings/{$id}'")->fetchColumn(), 'bell for the assignee');
        Assert::same($before + 1, (int) $ctx->db->query("SELECT COUNT(*) FROM deliveries WHERE recipient = 'fixadmin@msp.example'")->fetchColumn(), 'email for the assignee');
        Assert::contains('Assigned to fixadmin', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$id} AND event = 'assigned' ORDER BY id DESC LIMIT 1")->fetchColumn());
        Assert::contains('finding.assigned', (string) $ctx->db->query("SELECT GROUP_CONCAT(action) FROM audit_log")->fetchColumn());
        // Assigning to yourself sends nothing.
        $techId = $userId($ctx, 'fixtech');
        $tech->submit('/findings/' . $id, '/findings/' . $id . '/assign', ['assignee' => 'me']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$techId} AND kind = 'assigned'")->fetchColumn(), 'no alert for taking a finding');
        $page = $viewer->get('/findings/' . $id)->body;
        Assert::contains('fixtech', $page, 'viewers see the owner');
        Assert::notContains('/assign"', $page, 'but get no assign form');
        // Filters.
        Assert::contains('/findings/' . $id . '"', $tech->get('/findings?assignee=me')->body, 'my findings');
        Assert::notContains('/findings/' . $id . '"', $tech->get('/findings?assignee=none')->body, 'not unassigned any more');
        $tech->submit('/findings/' . $id, '/findings/' . $id . '/assign', ['assignee' => '']);
        Assert::same(null, $ctx->db->query("SELECT assigned_to FROM findings WHERE id = {$id}")->fetchColumn());
        $api = $ctx->db->query("SELECT due_at FROM findings WHERE id = {$id}")->fetchColumn();
        Assert::true($api !== null, 'open findings have a due date');
        });
    },
    'overdue filters and daily reminders' => function (TestContext $ctx) use ($setup, $fid, $userId, $withEmail): void {
        $cid = $setup($ctx);
        $withEmail($ctx, function () use ($ctx, $cid, $fid, $userId): void {
        $late = $fid($ctx, $cid, 'site:203.0.113.190:443:exposed_env');
        $soon = $fid($ctx, $cid, 'site:203.0.113.190:443:exposed_backup');
        $techId = $userId($ctx, 'fixtech');
        $ctx->db->exec("UPDATE findings SET opened_at = UTC_TIMESTAMP() - INTERVAL 20 DAY, assigned_to = {$techId} WHERE id = {$late}");
        $ctx->db->exec("UPDATE findings SET opened_at = UTC_TIMESTAMP() - INTERVAL 13 DAY, assigned_to = {$techId} WHERE id = {$soon}");
        App::fixWorkflow()->recomputeDue($cid);
        $tech = $ctx->login('fixtech', 'Fixflow-Pass-0001!');
        $overdue = $tech->get('/findings?due=overdue')->body;
        Assert::contains('/findings/' . $late . '"', $overdue);
        Assert::notContains('/findings/' . $soon . '"', $overdue);
        Assert::true(preg_match('/Overdue [56] day\(s\)/', $overdue) === 1, 'overdue badge');
        Assert::contains('/findings/' . $soon . '"', $tech->get('/findings?due=soon')->body);

        $wf = App::fixWorkflow();
        Assert::true(!$wf->claimDailyReminders(new DateTimeImmutable('2030-01-01 06:59:00', new DateTimeZone('UTC'))), 'not before 07:00 UTC');
        Assert::true($wf->claimDailyReminders(new DateTimeImmutable('2030-01-01 07:00:00', new DateTimeZone('UTC'))), 'once a day');
        Assert::true(!$wf->claimDailyReminders(new DateTimeImmutable('2030-01-01 18:00:00', new DateTimeZone('UTC'))), 'not twice');
        $r = App::alerts()->fixReminders($wf->dueItems());
        Assert::true($r['team'] && $r['assignees'] >= 1, 'reminders sent');
        $note = $ctx->db->query("SELECT title, body FROM notifications WHERE user_id = {$techId} AND kind = 'due' ORDER BY id DESC LIMIT 1")->fetch();
        Assert::contains('overdue', (string) $note['title']);
        Assert::contains('OVERDUE since', (string) $note['body']);
        Assert::contains('Due ' . gmdate('Y-m-d', time() + 86400), (string) $note['body'], 'due-soon reminder');
        $team = (string) $ctx->db->query("SELECT body FROM deliveries WHERE recipient = 'team@msp.example' AND subject LIKE '%overdue%' ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::contains('Fixflow Example: ', $team, 'team summary per client');
        Assert::contains('fixtech@msp.example', (string) $ctx->db->query("SELECT GROUP_CONCAT(recipient) FROM deliveries WHERE subject LIKE '%Your findings%'")->fetchColumn(), 'assignee email');
        });
    },
    'verify fix: rechecks one target, in scope, rate-limited, and resolves when fixed' => function (TestContext $ctx) use ($setup, $fid, $userId): void {
        $cid = $setup($ctx);
        $id = $fid($ctx, $cid, 'port:203.0.113.192:3389');
        $tech = $ctx->login('fixtech', 'Fixflow-Pass-0001!');
        $viewer = $ctx->login('fixview', 'Fixflow-Pass-0001!');
        Assert::status(403, $viewer->submit('/findings/' . $id, '/findings/' . $id . '/verify', []), 'viewers cannot verify');
        file_put_contents($ctx->nmapLog, '');
        Assert::redirect('/findings/' . $id, $tech->submit('/findings/' . $id, '/findings/' . $id . '/verify', []));
        $job = $ctx->db->query("SELECT id, job_type, outside_window, payload FROM scan_jobs WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetch();
        Assert::same(['verify', 0], [$job['job_type'], (int) $job['outside_window']], 'a technician\'s recheck waits for the scan window');
        Assert::same(null, App::scans()->openJob($cid), 'a verify job never blocks scans');
        // Second request within 10 minutes is refused.
        $tech->submit('/findings/' . $id, '/findings/' . $id . '/verify', []);
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify'")->fetchColumn(), 'one at a time');
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job['id']]);
        $calls = array_values(array_filter(explode("\n", (string) file_get_contents($ctx->nmapLog))));
        Assert::same(1, count($calls), 'one nmap call');
        $args = json_decode($calls[0], true);
        Assert::same(['3389', '203.0.113.192'], [$args[array_search('-p', $args, true) + 1], end($args)], 'only that address and port');
        Assert::contains('still seen', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$id} AND event = 'verified' ORDER BY id DESC LIMIT 1")->fetchColumn());
        Assert::same('open', (string) $ctx->db->query("SELECT status FROM findings WHERE id = {$id}")->fetchColumn());
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$userId($ctx, 'fixtech')} AND kind = 'verify' AND title LIKE 'Still present%'")->fetchColumn());

        // The client closes the port; the next recheck (after 10 minutes) resolves the finding.
        file_put_contents(dirname($ctx->nmapLog) . '/nmap-closed.json', json_encode(['203.0.113.192:3389']));
        $ctx->db->exec("UPDATE findings SET verify_requested_at = UTC_TIMESTAMP() - INTERVAL 11 MINUTE WHERE id = {$id}");
        $tech->submit('/findings/' . $id, '/findings/' . $id . '/verify', []);
        $job2 = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify'")->fetchColumn();
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job2]);
        @unlink(dirname($ctx->nmapLog) . '/nmap-closed.json');
        Assert::same('resolved', (string) $ctx->db->query("SELECT status FROM findings WHERE id = {$id}")->fetchColumn(), 'fixed');
        Assert::contains('no longer reachable from the internet', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$id} AND event = 'verified' ORDER BY id DESC LIMIT 1")->fetchColumn());
        $fpage = $tech->get('/findings/' . $id)->body;
        Assert::contains('Fixed', $fpage);
        Assert::contains('How to fix', $fpage, 'the finding page shows the guidance the report has');
        Assert::contains('Remote Desktop', $fpage);

        // An admin's recheck may run outside the scan window (as an admin's "scan now" can).
        $id2 = $fid($ctx, $cid, 'site:203.0.113.190:443:missing_hsts');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/findings/' . $id2, '/findings/' . $id2 . '/verify', []);
        Assert::same(1, (int) $ctx->db->query("SELECT outside_window FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify' ORDER BY id DESC LIMIT 1")->fetchColumn(), 'admin recheck outside the window');
        $ctx->db->exec("DELETE FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify' AND status = 'queued'");
        $ctx->db->exec("UPDATE findings SET verify_requested_at = NULL WHERE id = {$id2}");
    },
    'verify fix is honest: closed ports, aborted rechecks, already resolved, CSRF' => function (TestContext $ctx) use ($setup, $fid, $userId): void {
        $cid = $setup($ctx);
        $tech = $ctx->login('fixtech', 'Fixflow-Pass-0001!');
        $techId = $userId($ctx, 'fixtech');
        // A website finding on a port that stops answering is "no longer reachable", never "fixed".
        $csp = $fid($ctx, $cid, 'site:203.0.113.190:443:missing_csp');
        file_put_contents(dirname($ctx->nmapLog) . '/nmap-closed.json', json_encode(['203.0.113.190:443']));
        $tech->submit('/findings/' . $csp, '/findings/' . $csp . '/verify', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify'")->fetchColumn();
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
        @unlink(dirname($ctx->nmapLog) . '/nmap-closed.json');
        Assert::contains('nothing answers on this port', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$csp} AND event = 'verified' ORDER BY id DESC LIMIT 1")->fetchColumn());
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$techId} AND title LIKE 'No longer reachable%'")->fetchColumn());
        // A full scan brings the port (and the finding) back.
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'ports'")->fetchColumn()]);
        Assert::same('open', (string) $ctx->db->query("SELECT status FROM findings WHERE id = {$csp}")->fetchColumn(), 'back after the scan');

        // Queued, then the client is paused: the requester is told it could not finish.
        $hsts = $fid($ctx, $cid, 'site:203.0.113.190:443:missing_hsts');
        $tech->submit('/findings/' . $hsts, '/findings/' . $hsts . '/verify', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify'")->fetchColumn();
        $ctx->db->exec("UPDATE clients SET scanning_paused = 1 WHERE id = {$cid}");
        $ctx->cli('bin/worker.php', ['--no-schedule']);
        $ctx->db->exec("UPDATE clients SET scanning_paused = 0 WHERE id = {$cid}");
        Assert::same('cancelled', (string) $ctx->db->query("SELECT status FROM scan_jobs WHERE id = {$job}")->fetchColumn());
        Assert::contains('scanning was paused', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$hsts} AND event = 'verified' ORDER BY id DESC LIMIT 1")->fetchColumn());
        // Cancelled by a user from the scans list.
        $ctx->db->exec("UPDATE findings SET verify_requested_at = NULL WHERE id = {$hsts}");
        $tech->submit('/findings/' . $hsts, '/findings/' . $hsts . '/verify', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify'")->fetchColumn();
        $tech->submit('/clients/' . $cid, '/scans/' . $job . '/cancel', []);
        Assert::contains('cancelled by a user', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$hsts} AND event = 'verified' ORDER BY id DESC LIMIT 1")->fetchColumn());
        // Resolved by another check before the recheck ran: "already resolved", not "fixed".
        $ctx->db->exec("UPDATE findings SET verify_requested_at = NULL WHERE id = {$hsts}");
        $tech->submit('/findings/' . $hsts, '/findings/' . $hsts . '/verify', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify'")->fetchColumn();
        $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP() - INTERVAL 1 MINUTE WHERE id = {$hsts}");
        $ctx->db->exec("UPDATE scan_jobs SET started_at = UTC_TIMESTAMP() WHERE id = {$job}");
        $f = $ctx->db->query("SELECT finding_key, status, resolved_at FROM findings WHERE id = {$hsts}")->fetch();
        $o = \Sentinel\Findings\VerifyOutcome::decide($f, 'done', gmdate('Y-m-d H:i:s'), ['refresh_ok' => true]);
        Assert::same('already_resolved', $o['result']);
        $ctx->db->exec("UPDATE scan_jobs SET status = 'cancelled' WHERE id = {$job}");
        $ctx->db->exec("UPDATE findings SET status = 'open', resolved_at = NULL WHERE id = {$hsts}");
        // CSRF is required on the new routes.
        foreach (['assign', 'verify', 'due'] as $action) {
            Assert::status(400, $tech->post('/findings/' . $hsts . '/' . $action, ['assignee' => 'me']), 'CSRF on ' . $action);
        }
        Assert::status(400, $admin->post('/admin/settings/due-dates', ['due_days_kev' => '1', 'due_days_fail' => '1', 'due_days_warn' => '1']), 'CSRF on the policy');
    },
    'verify fix: email findings by DNS; refused when out of scope or paused' => function (TestContext $ctx) use ($setup, $fid): void {
        $cid = $setup($ctx);
        $id = $fid($ctx, $cid, 'email:mail-weak.example:spf_pass_all');
        Assert::true($id > 0, 'email finding exists');
        $tech = $ctx->login('fixtech', 'Fixflow-Pass-0001!');
        $tech->submit('/findings/' . $id, '/findings/' . $id . '/verify', []);
        $job = $ctx->db->query("SELECT id, payload FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify' ORDER BY id DESC LIMIT 1")->fetch();
        Assert::same('mail-weak.example', json_decode((string) $job['payload'], true)['email_domain'] ?? null);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job['id']]);
        Assert::contains('still seen', (string) $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$id} AND event = 'verified' ORDER BY id DESC LIMIT 1")->fetchColumn());
        Assert::same('dns', (string) $ctx->db->query("SELECT target FROM scan_log WHERE job_id = {$job['id']}")->fetchColumn(), 'logged in the scan log');

        // Paused client: refused, nothing queued.
        $hsts = $fid($ctx, $cid, 'site:203.0.113.190:443:missing_hsts');
        $ctx->db->exec("UPDATE clients SET scanning_paused = 1 WHERE id = {$cid}");
        $count = (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
        $tech->submit('/findings/' . $hsts, '/findings/' . $hsts . '/verify', []);
        Assert::same($count, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn(), 'paused: nothing queued');
        $ctx->db->exec("UPDATE clients SET scanning_paused = 0 WHERE id = {$cid}");
        // Out of scope: revoke the authorisation.
        $ctx->db->exec("UPDATE scan_authorisations SET valid_until = '2000-01-01' WHERE client_id = {$cid}");
        $tech->submit('/findings/' . $hsts, '/findings/' . $hsts . '/verify', []);
        Assert::same($count, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn(), 'out of scope: nothing queued');
        Assert::contains('no longer in an active authorisation', $tech->get('/findings/' . $hsts)->body);
        $ctx->db->exec("UPDATE scan_authorisations SET valid_until = '" . gmdate('Y-m-d', time() + 86400 * 200) . "' WHERE client_id = {$cid}");
    },
];
