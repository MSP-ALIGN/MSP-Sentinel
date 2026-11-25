<?php

declare(strict_types=1);

/**
 * End-to-end tests for pen-test engagements (1.27, part 1): created with the client's signed authorisation (a PDF),
 * only inside the authorised scope (external) and a site's internal authorisation (internal), approved by a
 * DIFFERENT admin with their password, stopped by the kill switch, cancelled before approval; the gate the scanners
 * use (isActive) and the target checks with exclusions. Roles enforced. Made-up data and documentation ranges only.
 */

use Sentinel\Core\App;
use Sentinel\Engagements\EngagementRepository as ER;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$engSetup = static function (TestContext $ctx): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Engagement Example'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Engagement Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
            'approved_by_name' => 'Robin Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
            'document_ref' => '', 'notes' => '', 'scope' => "203.0.113.0/28\nportal.engagement.example\n", 'confirm' => '1']);
        $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
        $admin->submit('/clients/' . $cid . '/sites/' . $site . '/internal-authorisations/new', '/clients/' . $cid . '/sites/' . $site . '/internal-authorisations', [
            'approved_by_name' => 'Sam Example', 'approved_by_role' => 'IT Manager', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-9001', 'notes' => '', 'ranges' => '10.97.0.0/24', 'confirm' => '1']);
        foreach (['engtech' => 'technician', 'engadmin2' => 'admin', 'engviewer' => 'viewer'] as $u => $role) {
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = '{$u}'")->fetchColumn() === 0) {
                $ctx->createUser($u, $role, ucfirst($u) . '-Pass-0001!');
            }
        }
    }
    $site = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$cid} AND is_default = 1")->fetchColumn();
    $pdf = dirname($ctx->configPath) . '/signed-authorisation.pdf';
    file_put_contents($pdf, "%PDF-1.4\n% made-up signed authorization for the test suite\n%%EOF\n");
    return [$cid, $site, $pdf];
};
/** The form fields of a valid engagement (window: an hour ago until tomorrow, in UTC as the client is). */
$fields = static fn (int $site, array $over = []): array => $over + [
    'name' => 'Annual test 2027', 'signer_name' => 'Robin Example', 'signer_role' => 'Owner', 'signed_on' => gmdate('Y-m-d'),
    'window_start' => gmdate('Y-m-d\TH:i', time() - 3600), 'window_end' => gmdate('Y-m-d\TH:i', time() + 86400), 'intensity' => 'normal',
    'tests[0]' => 'tcp_full', 'tests[1]' => 'nse_safe', 'tests[2]' => 'anon_access',
    'external' => "203.0.113.0/29\nportal.engagement.example", 'internal_' . $site => '10.97.0.0/25', 'exclusions' => "203.0.113.5\n10.97.0.9", 'notes' => '', 'confirm' => '1',
];
$lastId = static fn (TestContext $ctx, int $cid): int => (int) $ctx->db->query("SELECT MAX(id) FROM engagements WHERE client_id = {$cid}")->fetchColumn();

return [
    'engagements: only inside the authorized scope, with a signed PDF; roles enforced' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        $viewer = $ctx->login('engviewer', 'Engviewer-Pass-0001!');
        Assert::contains('Pen-test engagements', $ctx->clientSection($tech, $cid, 'engagements'));
        Assert::status(403, $viewer->get('/clients/' . $cid . '/engagements/new'), 'viewers cannot create');
        $form = '/clients/' . $cid . '/engagements/new';
        $action = '/clients/' . $cid . '/engagements';
        $before = $lastId($ctx, $cid);
        // Outside the scope (external and internal), not a PDF, no confirmation: refused, nothing saved.
        $res = $tech->upload($form, $action, $fields($site, ['external' => '203.0.113.64/28']), 'document', $pdf, 'application/pdf');
        Assert::status(422, $res);
        Assert::contains('not inside this client', $res->body);
        $res = $tech->upload($form, $action, $fields($site, ['internal_' . $site => '10.98.0.0/24']), 'document', $pdf, 'application/pdf');
        Assert::contains('inside the site', $res->body);
        $txt = dirname($ctx->configPath) . '/not-a-pdf.pdf';
        file_put_contents($txt, 'hello');
        Assert::contains('must be a PDF', $tech->upload($form, $action, $fields($site), 'document', $txt, 'application/pdf')->body);
        Assert::contains('Confirm that the client signed', $tech->upload($form, $action, $fields($site, ['confirm' => '']), 'document', $pdf, 'application/pdf')->body);
        Assert::contains('at most 14 days', $tech->upload($form, $action, $fields($site, ['window_end' => gmdate('Y-m-d\TH:i', time() + 86400 * 20)]), 'document', $pdf, 'application/pdf')->body);
        Assert::contains('need the normal pace', $tech->upload($form, $action, $fields($site, ['intensity' => 'gentle']), 'document', $pdf, 'application/pdf')->body, 'all ports never gentle');
        Assert::contains('not by name', $tech->upload($form, $action, $fields($site, ['exclusions' => 'portal.engagement.example']), 'document', $pdf, 'application/pdf')->body, 'exclusions by address');
        Assert::same($before, $lastId($ctx, $cid), 'nothing saved');
        // A valid one.
        $res = $tech->upload($form, $action, $fields($site), 'document', $pdf, 'application/pdf');
        Assert::status(303, $res);
        $id = $lastId($ctx, $cid);
        $e = App::engagements()->find($id);
        Assert::same(ER::STATE_AWAITING, ER::state($e, gmdate('Y-m-d H:i:s')));
        Assert::same(hash_file('sha256', $pdf), $e['document_sha256']);
        Assert::same(['tcp_full', 'nse_safe', 'anon_access'], $e['tests_list']);
        Assert::true(!(App::engagements()->isActive($id)), 'nothing runs before approval');
        $page = $tech->get('/engagements/' . $id)->body;
        Assert::contains('Awaiting approval', $page);
        Assert::contains('portal.engagement.example', $page);
        Assert::status(200, $viewer->get('/engagements/' . $id), 'everyone can view');
        // The document: a download, never inline; viewers can't fetch it.
        $doc = $tech->get('/engagements/' . $id . '/document');
        Assert::status(200, $doc);
        Assert::contains('attachment', (string) $doc->header('content-disposition'));
        Assert::contains('sandbox', (string) $doc->header('content-security-policy'));
        Assert::status(403, $viewer->get('/engagements/' . $id . '/document'));
        // Target checks the scanners use: inside, excluded, outside.
        Assert::true(ER::externalAllows($e['targets'], '203.0.113.3'), 'inside');
        Assert::true(!(ER::externalAllows($e['targets'], '203.0.113.5')), 'excluded');
        Assert::true(!(ER::externalAllows($e['targets'], '203.0.113.9')), 'outside the engagement (though inside the scope)');
        Assert::true(ER::externalAllows($e['targets'], 'portal.engagement.example'), 'a named host');
        Assert::true(ER::internalAllows($e['targets'], $site, '10.97.0.20'), 'internal inside');
        Assert::true(!(ER::internalAllows($e['targets'], $site, '10.97.0.9')), 'internal excluded');
        Assert::true(!(ER::internalAllows($e['targets'], $site, '10.97.0.200')), 'internal outside the engagement');
        Assert::true(!(ER::internalAllows($e['targets'], $site + 999, '10.97.0.20')), 'another site');
    },
    'engagements: a different admin approves with their password; stop is final; cancel before approval' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin2 = $ctx->login('engadmin2', 'Engadmin2-Pass-0001!');
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        // Created by an admin: that admin can't approve it.
        $admin->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Two-person rule']), 'document', $pdf, 'application/pdf');
        $id = $lastId($ctx, $cid);
        $admin->post('/engagements/' . $id . '/approve', ['_csrf' => $admin->get('/engagements/' . $id)->csrf(), 'password' => 'Admin-Pass-0001!']);
        Assert::same(null, App::engagements()->find($id)['approved_at'], 'never by its creator');
        Assert::status(403, $tech->post('/engagements/' . $id . '/approve', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'password' => 'Engtech-Pass-0001!']), 'technicians cannot approve');
        // The second admin is told and sees it waiting (1.34): a notification, the dashboard and the Engagements page.
        $admin2Id = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'engadmin2'")->fetchColumn();
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$admin2Id} AND kind = 'engagement' AND link = '/engagements/{$id}'")->fetchColumn(), 'other admins notified');
        Assert::contains('awaiting your approval', $admin2->get('/')->body, 'on the dashboard');
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        Assert::true(!in_array($id, array_map(static fn (array $a): int => (int) $a['id'], App::engagements()->awaitingApprovalBy($adminId)), true), 'not for its creator');
        $list = $admin2->get('/engagements');
        Assert::contains('Awaiting your approval', $list->body);
        Assert::contains('Two-person rule', $list->body);
        Assert::status(200, $tech->get('/engagements'), 'everyone can list engagements');
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'wrong']);
        Assert::same(null, App::engagements()->find($id)['approved_at'], 'the password is required');
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Engadmin2-Pass-0001!']);
        $e = App::engagements()->find($id);
        Assert::true($e['approved_at'] !== null, 'approved by the second admin');
        Assert::true(App::engagements()->isActive($id), 'active inside its window');
        Assert::contains('Active: testing is allowed now', $tech->get('/engagements/' . $id)->body);
        // The global kill switch also stops it.
        App::settings()->set('scanning_paused', '1');
        Assert::true(!(App::engagements()->isActive($id)), 'global pause');
        App::settings()->set('scanning_paused', '0');
        // Stop: a technician can, with a reason; final.
        $tech->post('/engagements/' . $id . '/stop', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'reason' => '']);
        Assert::true(App::engagements()->isActive($id), 'a reason is required');
        $tech->post('/engagements/' . $id . '/stop', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'reason' => 'Client asked to pause']);
        Assert::true(!(App::engagements()->isActive($id)), 'stopped');
        Assert::true(!(App::engagements()->approve($id, (int) $ctx->db->query("SELECT id FROM users WHERE username = 'engadmin2'")->fetchColumn())), 'never approved again');
        Assert::contains('Client asked to pause', $tech->get('/engagements/' . $id)->body);
        // A future window: approved but scheduled, not active yet.
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Next month',
            'window_start' => gmdate('Y-m-d\TH:i', time() + 86400 * 3), 'window_end' => gmdate('Y-m-d\TH:i', time() + 86400 * 5)]), 'document', $pdf, 'application/pdf');
        $later = $lastId($ctx, $cid);
        $admin->post('/engagements/' . $later . '/approve', ['_csrf' => $admin->get('/engagements/' . $later)->csrf(), 'password' => 'Admin-Pass-0001!']);
        Assert::same(ER::STATE_SCHEDULED, ER::state(App::engagements()->find($later), gmdate('Y-m-d H:i:s')));
        Assert::true(!(App::engagements()->isActive($later)), 'not before its window');
        // Cancel: only before approval.
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Withdrawn']), 'document', $pdf, 'application/pdf');
        $c = $lastId($ctx, $cid);
        $tech->post('/engagements/' . $c . '/cancel', ['_csrf' => $tech->get('/engagements/' . $c)->csrf()]);
        Assert::same(ER::STATE_CANCELLED, ER::state(App::engagements()->find($c), gmdate('Y-m-d H:i:s')));
        Assert::true(!(App::engagements()->cancel($later)), 'an approved one cannot be canceled, only stopped');
        $audit = implode("\n", $ctx->db->query("SELECT action FROM audit_log WHERE action LIKE 'engagement.%'")->fetchAll(PDO::FETCH_COLUMN));
        foreach (['engagement.created', 'engagement.approved', 'engagement.stopped', 'engagement.cancelled'] as $a) {
            Assert::contains($a, $audit);
        }
    },
    'engagements: external tests run only while active, scan deeper with the fixed scripts, honor exclusions and stop' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $admin2 = $ctx->login('engadmin2', 'Engadmin2-Pass-0001!');
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'External test',
            'external' => '203.0.113.0/29', 'internal_' . $site => '', 'exclusions' => '203.0.113.5']), 'document', $pdf, 'application/pdf');
        $id = $lastId($ctx, $cid);
        // Not approved yet: nothing can be started.
        $tech->post('/engagements/' . $id . '/run-external', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        Assert::same([], App::engagements()->externalJobs($id), 'not before approval');
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Engadmin2-Pass-0001!']);
        $tech->post('/engagements/' . $id . '/run-external', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        $jobs = App::engagements()->externalJobs($id);
        Assert::same(1, count($jobs), 'queued once');
        $tech->post('/engagements/' . $id . '/run-external', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        Assert::same(1, count(App::engagements()->externalJobs($id)), 'not twice while queued');
        @unlink($ctx->nmapLog);
        [$code, $out] = $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . (int) $jobs[0]['id']]);
        Assert::same(0, $code, 'worker: ' . $out);
        $calls = array_map(static fn (string $l): array => json_decode($l, true), file($ctx->nmapLog, FILE_IGNORE_NEW_LINES));
        $scanned = array_map(static fn (array $c): string => (string) end($c), $calls);
        sort($scanned);
        Assert::same(['203.0.113.0', '203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4', '203.0.113.6', '203.0.113.7'], $scanned, 'the /29 without the excluded address');
        $first = $calls[0];
        Assert::true(in_array('1-65535', $first, true) && in_array('-T3', $first, true) && in_array('--script', $first, true), 'all ports, normal timing, scripts: ' . implode(' ', $first));
        Assert::true(!in_array('-sU', $first, true) && !in_array('-A', $first, true) && !in_array('-O', $first, true), 'nothing outside the fixed set');
        $results = App::engagements()->results($id);
        $host = array_values(array_filter($results, static fn (array $r): bool => $r['ip'] === '203.0.113.3'))[0] ?? null;
        Assert::true($host !== null, 'results recorded');
        Assert::same([21, 22, 50080], array_column($host['ports_list'], 'port'), 'a high port found by the full scan');
        Assert::contains('Anonymous FTP login allowed', json_encode($host['ports_list']));
        Assert::contains('signing enabled but not required', json_encode($host['checks_list']));
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM assets WHERE client_id = {$cid} AND ip = '203.0.113.3'")->fetchColumn(), 'evidence only: day-to-day data untouched');
        $page = $tech->get('/engagements/' . $id)->body;
        Assert::contains('50080/http', $page);
        Assert::contains('Anonymous FTP login is allowed', $page, 'findings from the evidence');
        Assert::contains('SMB signing is not required', $page);
        // Stopped: a new run is refused, and a queued job is cancelled by the worker without scanning.
        $q = App::scans()->queue($cid, 'manual', null, true, 'test', ['engagement_id' => $id], 'engagement');
        $tech->post('/engagements/' . $id . '/stop', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'reason' => 'Test stop']);
        @unlink($ctx->nmapLog);
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $q]);
        Assert::same('cancelled', (string) $ctx->db->query('SELECT status FROM scan_jobs WHERE id = ' . $q)->fetchColumn());
        Assert::true(!is_file($ctx->nmapLog) || trim((string) file_get_contents($ctx->nmapLog)) === '', 'nothing scanned after the stop');
        $tech->post('/engagements/' . $id . '/run-external', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        Assert::same(2, count(App::engagements()->externalJobs($id)), 'no new run once stopped');
    },
    'engagements: internal tests through the agent: signed, excluded hosts untouched, evidence only, stopped by the kill switch' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $admin2 = $ctx->login('engadmin2', 'Engadmin2-Pass-0001!');
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        // An agent for the site (the real agent program, test mode: fake nmap, no packets).
        $dir = dirname($ctx->configPath) . '/agent-engagement';
        @mkdir($dir, 0700, true);
        if (!is_file($dir . '/agent.json')) {
            preg_match('/SNE(-[A-Z2-9]{5}){4}/', $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/sites/' . $site . '/enrol', [])->body, $m);
            [$code, $out] = $ctx->cli('bin/sentinel-agent.php', ['enrol', '--server', $ctx->baseUrl, '--code', $m[0] ?? 'missing', '--config', $dir . '/agent.json']);
            Assert::same(0, $code, 'enroll: ' . $out);
            $app = require $ctx->configPath;
            $c = json_decode((string) file_get_contents($dir . '/agent.json'), true);
            $c['nmap_path'] = $app['testing']['agent_nmap_path'];
            $c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections'], 'arp_file' => $dir . '/arp'];
            file_put_contents($dir . '/agent.json', json_encode($c));
            file_put_contents($dir . '/arp', "IP address       HW type     Flags       HW address            Mask     Device\n");
        }
        $run = static fn (): array => $ctx->cli('bin/sentinel-agent.php', ['run', '--once', '--config', $dir . '/agent.json']);
        $run(); // reports its version
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Internal test',
            'external' => '', 'internal_' . $site => '10.97.0.0/25', 'exclusions' => '10.97.0.9']), 'document', $pdf, 'application/pdf');
        $id = $lastId($ctx, $cid);
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Engadmin2-Pass-0001!']);
        $tech->post('/engagements/' . $id . '/run-internal', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        $jobs = App::agents()->engagementJobs($id);
        Assert::same(1, count($jobs), 'queued for the site agent');
        @unlink($ctx->nmapLog);
        [$code, $out] = $run();
        Assert::same(0, $code, 'agent: ' . $out);
        $calls = array_map(static fn (string $l): array => json_decode($l, true), file($ctx->nmapLog, FILE_IGNORE_NEW_LINES));
        $scanned = array_values(array_filter(array_map(static fn (array $c): string => in_array('-sn', $c, true) ? '' : (string) end($c), $calls)));
        Assert::same(['10.97.0.20'], $scanned, 'deep scan of the found host, not the excluded one: ' . $out);
        Assert::contains('10.97.0.9/32', (string) @file_get_contents(dirname($ctx->nmapLog) . '/nmap-excluded.log'), 'the excluded host is left out of the sweep too');
        Assert::true(in_array('1-65535', $calls[1] ?? [], true) && in_array('--script', $calls[1] ?? [], true), 'all ports and the fixed scripts');
        $results = App::engagements()->results($id);
        Assert::same(['10.97.0.20'], array_column($results, 'ip'), 'evidence for the tested host only');
        Assert::same('internal', $results[0]['origin']);
        Assert::contains("dialects:\n  NT LM 0.12", (string) ($results[0]['checks_list']['hostscripts'][0]['output'] ?? ''), 'script output kept line by line');
        Assert::same([445, 2049, 40000], array_column($results[0]['ports_list'], 'port'));
        Assert::same('done', (string) $ctx->db->query('SELECT status FROM agent_jobs WHERE id = ' . (int) $jobs[0]['id'])->fetchColumn());
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM devices WHERE client_id = {$cid} AND ip_addresses LIKE '%10.97.0.20%'")->fetchColumn(), 'engagement results stay out of the inventory');
        // The kill switch: a queued engagement job is never handed out once the engagement is stopped.
        $tech->post('/engagements/' . $id . '/run-internal', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        $second = App::agents()->engagementJobs($id);
        Assert::same(2, count($second));
        $tech->post('/engagements/' . $id . '/stop', ['_csrf' => $tech->get('/engagements/' . $id)->csrf(), 'reason' => 'Test stop']);
        @unlink($ctx->nmapLog);
        $run();
        Assert::true(!is_file($ctx->nmapLog) || trim((string) file_get_contents($ctx->nmapLog)) === '', 'nothing scanned after the stop');
        $agent = $ctx->db->query("SELECT * FROM agents WHERE site_id = {$site} AND status = 'active'")->fetch();
        Assert::true(in_array((int) $second[0]['id'], App::agents()->jobsToStop((int) $agent['id']), true), 'listed for the agent to stop');
    },
    'engagements: the penetration test report, then a retest letter marking each finding fixed or still open' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $admin2 = $ctx->login('engadmin2', 'Engadmin2-Pass-0001!');
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        $runAll = static function (int $id) use ($ctx, $tech): void {
            $tech->post('/engagements/' . $id . '/run-external', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
            $job = (int) (App::engagements()->externalJobs($id)[0]['id'] ?? 0);
            $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
        };
        $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Report test',
            'external' => '203.0.113.3', 'internal_' . $site => '', 'exclusions' => '']), 'document', $pdf, 'application/pdf');
        $id = $lastId($ctx, $cid);
        $tech->post('/engagements/' . $id . '/report', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        Assert::same([], App::reports()->forEngagement($id), 'no report before approval');
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Engadmin2-Pass-0001!']);
        $runAll($id);
        $res = $tech->post('/engagements/' . $id . '/report', ['_csrf' => $tech->get('/engagements/' . $id)->csrf()]);
        $reports = App::reports()->forEngagement($id);
        Assert::same('pentest', $reports[0]['kind'] ?? null, 'issued');
        $report = App::reports()->find((int) $reports[0]['id']);
        foreach (['Penetration test report', 'Scope and authorization', 'Anonymous FTP login is allowed', 'Robin Example', hash_file('sha256', $pdf), 'Never done: password guessing'] as $want) {
            Assert::contains($want, (string) $report['html'], $want);
        }
        Assert::contains('Penetration test report', $tech->get('/reports/' . (int) $reports[0]['id'])->body);
        $csv = $tech->get('/reports/' . (int) $reports[0]['id'] . '/csv');
        Assert::contains('Anonymous FTP login is allowed', $csv->body, 'CSV of the findings');
        // The client "fixes" anonymous FTP (the port is closed); a retest engagement checks it.
        file_put_contents(dirname($ctx->nmapLog) . '/nmap-closed.json', json_encode(['203.0.113.3:21']));
        try {
            $tech->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Retest',
                'external' => '203.0.113.3', 'internal_' . $site => '', 'exclusions' => '', 'retest_of' => (string) $id]), 'document', $pdf, 'application/pdf');
            $re = $lastId($ctx, $cid);
            Assert::same($id, (int) App::engagements()->find($re)['retest_of']);
            $admin2->post('/engagements/' . $re . '/approve', ['_csrf' => $admin2->get('/engagements/' . $re)->csrf(), 'password' => 'Engadmin2-Pass-0001!']);
            $runAll($re);
            $tech->post('/engagements/' . $re . '/report', ['_csrf' => $tech->get('/engagements/' . $re)->csrf()]);
            $letter = App::reports()->forEngagement($re)[0] ?? [];
            Assert::same('retest', $letter['kind'] ?? null);
            $snap = json_decode((string) App::reports()->find((int) $letter['id'])['snapshot'], true);
            $status = [];
            foreach ($snap['retest']['items'] as $it) {
                $status[$it['title']] = $it['status'];
            }
            Assert::same('fixed', $status['Anonymous FTP login is allowed'] ?? null, json_encode($status));
            Assert::same('open', $status['SMB signing is not required (relay attacks)'] ?? null, 'still open');
            Assert::contains('Retest letter', (string) App::reports()->find((int) $letter['id'])['html']);
        } finally {
            @unlink(dirname($ctx->nmapLog) . '/nmap-closed.json');
        }
    },
    'engagements: an account the creator made (or reset) cannot be the second approver' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Self approval attempt',
            'external' => '203.0.113.2', 'internal_' . $site => '', 'exclusions' => '']), 'document', $pdf, 'application/pdf');
        $id = $lastId($ctx, $cid);
        // The creator makes a second admin account (audited as theirs) and tries to approve through it.
        $admin->submit('/users/new', '/users', ['username' => 'shadow.admin', 'display_name' => 'Shadow', 'email' => '', 'role' => 'admin', 'password' => 'Shadow-Temp-Pass-01!', 'my_password' => 'Admin-Pass-0001!']);
        $ctx->db->exec("UPDATE users SET must_change_password = 0 WHERE username = 'shadow.admin'");
        $shadow = $ctx->login('shadow.admin', 'Shadow-Temp-Pass-01!');
        $shadow->post('/engagements/' . $id . '/approve', ['_csrf' => $shadow->get('/engagements/' . $id)->csrf(), 'password' => 'Shadow-Temp-Pass-01!']);
        Assert::same(null, $ctx->db->query("SELECT approved_at FROM engagements WHERE id = {$id}")->fetchColumn(), 'not approved by an account its creator made');
        Assert::contains('Another admin must approve it', $shadow->get('/engagements/' . $id)->body);
        // A long-standing second admin can.
        $admin2 = $ctx->login('engadmin2', 'Engadmin2-Pass-0001!');
        $admin2->post('/engagements/' . $id . '/approve', ['_csrf' => $admin2->get('/engagements/' . $id)->csrf(), 'password' => 'Engadmin2-Pass-0001!']);
        Assert::true($ctx->db->query("SELECT approved_at FROM engagements WHERE id = {$id}")->fetchColumn() !== null, 'approved by a real second admin');

        // The other direction: the account the admin made creates an engagement; the admin can't approve it.
        $shadow->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Reverse attempt',
            'external' => '203.0.113.2', 'internal_' . $site => '', 'exclusions' => '']), 'document', $pdf, 'application/pdf');
        $rev = $lastId($ctx, $cid);
        $admin->post('/engagements/' . $rev . '/approve', ['_csrf' => $admin->get('/engagements/' . $rev)->csrf(), 'password' => 'Admin-Pass-0001!']);
        Assert::same(null, $ctx->db->query("SELECT approved_at FROM engagements WHERE id = {$rev}")->fetchColumn(), 'not approved by the account that made its creator');
        // Through a chain: the shadow admin makes another admin, who tries to approve the first admin's engagement.
        $shadow->submit('/users/new', '/users', ['username' => 'shadow.two', 'display_name' => 'Shadow Two', 'email' => '', 'role' => 'admin', 'password' => 'Shadow-Temp-Pass-02!', 'my_password' => 'Shadow-Temp-Pass-01!']);
        $ctx->db->exec("UPDATE users SET must_change_password = 0 WHERE username = 'shadow.two'");
        $admin->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => 'Chain attempt',
            'external' => '203.0.113.2', 'internal_' . $site => '', 'exclusions' => '']), 'document', $pdf, 'application/pdf');
        $chain = $lastId($ctx, $cid);
        $two = $ctx->login('shadow.two', 'Shadow-Temp-Pass-02!');
        Assert::notContains('Chain attempt', $two->get('/engagements')->body === '' ? '' : implode(' ', array_column(App::engagements()->awaitingApprovalBy((int) $ctx->db->query("SELECT id FROM users WHERE username = 'shadow.two'")->fetchColumn()), 'name')), 'not offered for approval');
        $two->post('/engagements/' . $chain . '/approve', ['_csrf' => $two->get('/engagements/' . $chain)->csrf(), 'password' => 'Shadow-Temp-Pass-02!']);
        Assert::same(null, $ctx->db->query("SELECT approved_at FROM engagements WHERE id = {$chain}")->fetchColumn(), 'not approved through a chain of made accounts');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'engagement.approval_refused'")->fetchColumn() >= 3, 'refusals audited');
    },
    'engagements (1.47): two-person approval can be turned off by an Admin; only engagements created while off may be self-approved' => function (TestContext $ctx) use ($engSetup, $fields, $lastId): void {
        [$cid, $site, $pdf] = $engSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $tech = $ctx->login('engtech', 'Engtech-Pass-0001!');
        $s = App::settings();
        Assert::same('1', $s->fresh('engagement_two_person'), 'on by default');
        $make = static function (string $name, $who) use ($cid, $site, $pdf, $fields, $lastId, $ctx): int {
            $who->upload('/clients/' . $cid . '/engagements/new', '/clients/' . $cid . '/engagements', $fields($site, ['name' => $name]), 'document', $pdf, 'application/pdf');
            return $lastId($ctx, $cid);
        };
        $approve = static function ($who, int $id, string $pw): void {
            $who->post('/engagements/' . $id . '/approve', ['_csrf' => $who->get('/engagements/' . $id)->csrf(), 'password' => $pw]);
        };
        $approved = static fn (int $id): bool => App::engagements()->find($id)['approved_at'] !== null;
        $before = $make('Made under the two-person rule', $admin);
        // Who may change it: not a technician, not an Admin limited to some clients, not without the password.
        Assert::status(403, $tech->post('/admin/settings/engagements', ['_csrf' => $tech->get('/')->csrf(), 'my_password' => 'Engtech-Pass-0001!']));
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'englimited'")->fetchColumn() === 0) {
            $uid = $ctx->createUser('englimited', 'admin', 'Englimited-Pass-001!');
            $ctx->db->exec("UPDATE users SET all_clients = 0 WHERE id = {$uid}");
        }
        $lim = $ctx->login('englimited', 'Englimited-Pass-001!');
        Assert::status(403, $lim->post('/admin/settings/engagements', ['_csrf' => $lim->get('/')->csrf(), 'my_password' => 'Englimited-Pass-001!']));
        $admin->submit('/admin/settings', '/admin/settings/engagements', ['two_person' => '0', 'my_password' => 'not-my-password-1']);
        Assert::same('1', $s->fresh('engagement_two_person'), 'needs the right password');
        $ctx->clearThrottle();
        // A request without the field never turns it off.
        $admin->submit('/admin/settings', '/admin/settings/engagements', ['my_password' => 'Admin-Pass-0001!']);
        Assert::same('1', $s->fresh('engagement_two_person'), 'no field: nothing changed');
        // A role with Manage settings and every client, but not every permission, can't change it.
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Settings keeper', 'my_password' => 'Admin-Pass-0001!', 'permissions[0]' => 'settings.manage']);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'engsettings'")->fetchColumn() === 0) {
            $ctx->createUser('engsettings', 'Settings keeper', 'Engsettings-Pass-01!');
        }
        $keeper = $ctx->login('engsettings', 'Engsettings-Pass-01!');
        Assert::status(403, $keeper->post('/admin/settings/engagements', ['_csrf' => $keeper->get('/admin/settings')->csrf(), 'two_person' => '0', 'my_password' => 'Engsettings-Pass-01!']));
        Assert::contains('Only an Admin who holds every permission', $keeper->get('/admin/settings')->body, 'shown read-only');
        // An approver limited to some clients is told too.
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Client approver', 'my_password' => 'Admin-Pass-0001!', 'permissions[0]' => 'engagements.approve']);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'engclientapp'")->fetchColumn() === 0) {
            $cu = $ctx->createUser('engclientapp', 'Client approver', 'Engclientapp-Pass-1!');
            $ctx->db->exec("UPDATE users SET all_clients = 0 WHERE id = {$cu}");
            $ctx->db->exec("INSERT INTO user_clients (user_id, client_id) VALUES ({$cu}, {$cid})");
        }
        Assert::contains('Pen-test engagements', $admin->get('/admin/settings')->body);
        $admin->submit('/admin/settings', '/admin/settings/engagements', ['two_person' => '0', 'my_password' => 'Admin-Pass-0001!']); // box unticked: the hidden 0
        Assert::same('0', $s->fresh('engagement_two_person'), 'turned off');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'settings.engagement_approval' AND username = 'admin'")->fetchColumn() >= 1, 'audited');
        $a2 = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'engadmin2'")->fetchColumn();
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$a2} AND title LIKE 'Pen-test engagements no longer need%'")->fetchColumn() === 1, 'approvers told');
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications n JOIN users u ON u.id = n.user_id WHERE u.username = 'engclientapp' AND n.title LIKE 'Pen-test engagements no longer need%'")->fetchColumn(), 'a client-limited approver too');
        // An engagement made while it was on still needs a second person.
        $approve($admin, $before, 'Admin-Pass-0001!');
        Assert::true(!$approved($before), 'made under the two-person rule: still not by its creator');
        // Made while off: its creator (who may approve) approves it, and it says so everywhere.
        $mine = $make('Single-person approval', $admin);
        Assert::same(1, (int) App::engagements()->find($mine)['single_approval']);
        Assert::contains('you may approve your own engagement', $admin->get('/engagements/' . $mine)->body);
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        Assert::true(in_array($mine, array_map(static fn (array $a): int => (int) $a['id'], App::engagements()->awaitingApprovalBy($adminId, null, false)), true), 'listed for its creator');
        Assert::true(!in_array($before, array_map(static fn (array $a): int => (int) $a['id'], App::engagements()->awaitingApprovalBy($adminId, null, false)), true), 'not their two-person one');
        Assert::contains('Single-person approval', $admin->get('/engagements')->body, 'on the Engagements page');
        Assert::contains('awaiting approval: nothing runs until it is approved', $admin->get('/')->body, 'dashboard wording while off');
        // The rule is read again when approving: turned back on meanwhile, the creator's approval fails.
        $s->set('engagement_two_person', '1');
        Assert::true(!App::engagements()->approve($mine, $adminId, true), 'turned back on: refused even if the request thought it was off');
        $s->set('engagement_two_person', '0');
        $approve($admin, $mine, 'wrong-password-1');
        Assert::true(!$approved($mine), 'still needs the password');
        $ctx->clearThrottle();
        $approve($admin, $mine, 'Admin-Pass-0001!');
        Assert::true($approved($mine), 'approved by its creator');
        Assert::contains('Single-person approval', $admin->get('/engagements/' . $mine)->body);
        Assert::contains('"by_creator":true', (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'engagement.approved' AND target_id = {$mine}")->fetchColumn());
        $e = App::engagements()->find($mine);
        $html = \Sentinel\Engagements\EngagementReport::render(\Sentinel\Engagements\EngagementReport::build($e, App::clients()->find($cid), [],
            (new \Sentinel\Reports\ReportBuilder(App::db(), App::settings(), App::authorisations(), SENTINEL_ROOT . '/storage/branding', App::version()))->brand(), [], [], 'admin'), SENTINEL_ROOT . '/views/reports');
        Assert::contains('(single-person approval)', $html, 'the report says so');
        // A technician still can't approve, even their own.
        $techs = $make('Made by a technician', $tech);
        Assert::status(403, $tech->post('/engagements/' . $techs . '/approve', ['_csrf' => $tech->get('/engagements/' . $techs)->csrf(), 'password' => 'Engtech-Pass-0001!']));
        // Back on: an engagement made while off needs a second person again.
        $later = $make('Made while off, approved after', $admin);
        $admin->submit('/admin/settings', '/admin/settings/engagements', ['two_person' => '1', 'my_password' => 'Admin-Pass-0001!']);
        Assert::same('1', $s->fresh('engagement_two_person'));
        $approve($admin, $later, 'Admin-Pass-0001!');
        Assert::true(!$approved($later), 'back on: not by its creator');
        $admin2 = $ctx->login('engadmin2', 'Engadmin2-Pass-0001!');
        $approve($admin2, $later, 'Engadmin2-Pass-0001!');
        Assert::true($approved($later), 'a second person still can');
        // Tidy up for later tests.
        foreach ([$before, $techs] as $id) {
            $ctx->db->exec("UPDATE engagements SET cancelled_at = UTC_TIMESTAMP() WHERE id = {$id}");
        }
        foreach ([$mine, $later] as $id) {
            $ctx->db->exec("UPDATE engagements SET stopped_at = UTC_TIMESTAMP(), stop_reason = 'test' WHERE id = {$id}");
        }
    },
];
