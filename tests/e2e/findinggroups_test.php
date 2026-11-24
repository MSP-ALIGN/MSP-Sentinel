<?php

declare(strict_types=1);

/**
 * End-to-end tests for grouped findings (1.31): the same issue on several targets of one client is one row in the
 * findings list (expand it to see each target), with actions for the whole group (assign, accept risk / false
 * positive / reopen, due date for admins, verify fix), each checked and audited per finding; reports list each issue
 * once with all its targets. Made-up data and documentation ranges only.
 */

use Sentinel\Core\App;
use Sentinel\Findings\FindingRepository;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$grpSetup = static function (TestContext $ctx): array {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Group Example'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Group Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $add = static function (string $key, string $type, string $sev, string $title, string $target, ?string $cve = null) use ($ctx, $cid): void {
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, cve_id, status, first_seen, last_seen, opened_at, due_at)
                               VALUES (:c, :k, :t, :s, :ti, 'Made-up detail.', :tg, 'made-up evidence', :cve, 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 14 DAY)")
                ->execute(['c' => $cid, 'k' => $key, 't' => $type, 's' => $sev, 'ti' => $title, 'tg' => $target, 'cve' => $cve]);
        };
        $add('vuln:203.0.113.95:22:CVE-2099-0901', 'vuln', 'fail', 'CVE-2099-0901 in Example SSH 1.0 (9.1 Critical)', '203.0.113.95:22', 'CVE-2099-0901');
        $add('vuln:203.0.113.96:22:CVE-2099-0901', 'vuln', 'fail', 'CVE-2099-0901 in Example SSH 1.0 (9.1 Critical)', '203.0.113.96:22', 'CVE-2099-0901');
        $add('site:203.0.113.95:443:missing_hsts', 'web', 'warn', 'HSTS missing <b>bold</b>', 'https://203.0.113.95:443');
        $add('site:203.0.113.96:443:missing_hsts', 'web', 'warn', 'HSTS missing <b>bold</b>', 'https://203.0.113.96:443');
        $add('port:203.0.113.95:3389', 'port', 'fail', 'Remote Desktop open to the internet', '203.0.113.95:3389');
        foreach (['grptech' => 'technician', 'grpview' => 'viewer'] as $u => $role) {
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = '{$u}'")->fetchColumn() === 0) {
                $ctx->createUser($u, $role, ucfirst($u) . '-Pass-0001!');
            }
        }
    }
    $ids = static fn (string $like): array => array_map('strval', $ctx->db->query("SELECT id FROM findings WHERE client_id = {$cid} AND finding_key LIKE " . $ctx->db->quote($like) . ' ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
    return [$cid, $ids('vuln:%'), $ids('site:%'), $ids('port:%')];
};
$bulk = static function ($client, array $ids, array $fields): \Sentinel\Tests\HttpResult {
    $csrf = $client->get('/findings')->csrf();
    $post = ['_csrf' => $csrf, 'return' => '/findings?view=flat'] + $fields;
    foreach ($ids as $i => $id) {
        $post['ids[' . $i . ']'] = $id;
    }
    return $client->post('/findings/bulk', $post);
};

return [
    'findings list: the same issue on several targets is one row; one row per target on request' => function (TestContext $ctx) use ($grpSetup): void {
        [$cid, $vuln, $site, $port] = $grpSetup($ctx);
        $view = $ctx->login('grpview', 'Grpview-Pass-0001!');
        $page = $view->get('/findings?client=' . $cid)->body;
        Assert::same(1, substr_count($page, 'CVE-2099-0901 in Example SSH'), 'one row for the CVE on two servers');
        Assert::contains('on 2 targets', $page);
        Assert::contains('203.0.113.96:22', $page, 'each target listed inside the group');
        Assert::contains('HSTS missing &lt;b&gt;bold&lt;/b&gt;', $page, 'escaped');
        Assert::notContains('<b>bold</b>', $page);
        Assert::contains('Remote Desktop open to the internet', $page, 'a single finding stays a plain row');
        Assert::notContains('/findings/bulk', $page, 'viewers get no group actions');
        $flat = $view->get('/findings?view=flat&client=' . $cid)->body;
        Assert::same(2, substr_count($flat, 'CVE-2099-0901 in Example SSH'), 'one row per target');
        $key = FindingRepository::groupKey(['client_id' => $cid, 'finding_type' => 'vuln', 'cve_id' => 'CVE-2099-0901', 'title' => '']);
        $one = $view->get('/findings?group=' . $key)->body;
        Assert::same(2, substr_count($one, 'CVE-2099-0901 in Example SSH'), 'show all of one group');
        Assert::notContains('Remote Desktop open', $one);
        Assert::status(200, $view->get('/findings?group=not-a-key'));
    },
    'group actions: assign, accept risk, due date (admins), verify; each checked and audited per finding' => function (TestContext $ctx) use ($grpSetup, $bulk): void {
        [$cid, $vuln, $site, $port] = $grpSetup($ctx);
        $tech = $ctx->login('grptech', 'Grptech-Pass-0001!');
        $view = $ctx->login('grpview', 'Grpview-Pass-0001!');
        Assert::contains('Assign all', $tech->get('/findings?client=' . $cid)->body);
        // Viewers can't; CSRF is required.
        Assert::status(403, $bulk($view, $vuln, ['action' => 'assign', 'assignee' => 'me']));
        $noCsrf = $tech->post('/findings/bulk', ['action' => 'assign', 'assignee' => 'me', 'ids[0]' => $vuln[0]]);
        Assert::true(in_array($noCsrf->status, [400, 403, 419], true), 'CSRF checked');
        // Assign both to me.
        $res = $bulk($tech, $vuln, ['action' => 'assign', 'assignee' => 'me', 'note' => 'Patch window Friday']);
        Assert::redirect('/findings?view=flat', $res);
        $techId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'grptech'")->fetchColumn();
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id IN (" . implode(',', $vuln) . ") AND assigned_to = {$techId}")->fetchColumn());
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'finding.assigned' AND target_id IN (" . implode(',', $vuln) . ") AND details LIKE '%\"bulk\":true%'")->fetchColumn(), 'audited per finding');
        // Accept risk needs a note; then both are accepted with their own history.
        $bulk($tech, $site, ['action' => 'triage', 'status' => 'accepted', 'note' => '']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id IN (" . implode(',', $site) . ") AND status = 'accepted'")->fetchColumn(), 'no note: nothing changed');
        $bulk($tech, $site, ['action' => 'triage', 'status' => 'accepted', 'note' => 'Internal test sites only']);
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id IN (" . implode(',', $site) . ") AND status = 'accepted'")->fetchColumn());
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM finding_events WHERE finding_id IN (" . implode(',', $site) . ") AND note = 'Internal test sites only'")->fetchColumn());
        // Due dates: admins only.
        Assert::status(403, $bulk($tech, $vuln, ['action' => 'due', 'due_date' => gmdate('Y-m-d', time() + 86400 * 5), 'note' => 'x']));
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $due = gmdate('Y-m-d', time() + 86400 * 5);
        $bulk($admin, $vuln, ['action' => 'due', 'due_date' => $due, 'note' => 'Agreed with the client']);
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id IN (" . implode(',', $vuln) . ") AND DATE(due_at) = '{$due}'")->fetchColumn());
        $bulk($admin, $vuln, ['action' => 'due', 'reset' => '1', 'note' => 'Back to the policy']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id IN (" . implode(',', $vuln) . ") AND due_custom = 1")->fetchColumn(), 'reset to the policy');
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE id IN (" . implode(',', $vuln) . ") AND due_at IS NOT NULL")->fetchColumn(), 'policy dates recomputed');
        $bulk($admin, $vuln, ['action' => 'due', 'due_date' => $due, 'note' => 'Agreed with the client']);
        // Verify fix: each finding's own checks apply (no authorisation for these addresses: nothing queued, and why).
        $res = $bulk($tech, $vuln, ['action' => 'verify']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify'")->fetchColumn(), 'nothing outside the authorisation');
        Assert::contains('no longer in an active authorisation', $tech->get('/findings?view=flat')->body, 'the reason is shown');
        // Garbage IDs and too many are refused.
        $bulk($tech, ['abc', '-1'], ['action' => 'assign', 'assignee' => 'me']);
        Assert::contains('Choose findings and an action', $tech->get('/findings?view=flat')->body);
        // Only the findings list as a return address.
        $csrf = $tech->get('/findings')->csrf();
        Assert::redirect('/findings', $tech->post('/findings/bulk', ['_csrf' => $csrf, 'return' => 'https://evil.example/', 'action' => 'assign', 'assignee' => 'me', 'ids[0]' => $port[0]]));
    },
    'reports list each issue once with all its targets' => function (TestContext $ctx) use ($grpSetup): void {
        [$cid] = $grpSetup($ctx);
        $ctx->db->exec("UPDATE findings SET status = 'open' WHERE client_id = {$cid}");
        $id = App::reportService()->generate(App::clients()->find($cid), 'technical', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        $html = (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$id}")->fetchColumn();
        Assert::same(1, substr_count($html, 'CVE-2099-0901 in Example SSH 1.0 (9.1 Critical) · 2 targets'), 'one block for the CVE, with its target count');
        Assert::contains('203.0.113.95:22', $html);
        Assert::contains('203.0.113.96:22', $html);
        Assert::contains('2 issue(s), 3 finding(s)', $html, 'the Fail heading counts issues and findings');
        $exec = App::reportService()->generate(App::clients()->find($cid), 'executive', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        $eh = (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$exec}")->fetchColumn();
        Assert::same(1, substr_count($eh, 'CVE-2099-0901 in Example SSH'), 'the executive summary lists the issue once');
        Assert::contains('203.0.113.95:22, 203.0.113.96:22', $eh, 'with every target');
    },
    'picked findings: in the one-row-per-target view, technicians tick rows and apply one action to them' => function (TestContext $ctx) use ($grpSetup, $bulk): void {
        [$cid, $vuln, $site, $port] = $grpSetup($ctx);
        $tech = $ctx->login('grptech', 'Grptech-Pass-0001!');
        $flat = $tech->get('/findings?view=flat&client=' . $cid)->body;
        Assert::contains('id="sel-bulk"', $flat, 'the action panel');
        Assert::contains('name="ids[]" value="' . $site[0] . '" form="sel-bulk"', $flat, 'a box per row');
        Assert::contains('data-select-all="sel-bulk"', $flat);
        Assert::notContains('id="sel-bulk"', $tech->get('/findings?client=' . $cid)->body, 'not in the grouped view');
        Assert::notContains('id="sel-bulk"', $ctx->login('grpview', 'Grpview-Pass-0001!')->get('/findings?view=flat&client=' . $cid)->body, 'viewers get no boxes');
        // Two findings from different issues, picked by hand: one action for both.
        $res = $bulk($tech, [$site[1], $port[0]], ['action' => 'triage', 'status' => 'accepted', 'note' => 'Client accepts these two for now.']);
        Assert::redirect('/findings?view=flat', $res);
        Assert::same(2, (int) $ctx->db->query('SELECT COUNT(*) FROM findings WHERE status = \'accepted\' AND id IN (' . (int) $site[1] . ',' . (int) $port[0] . ')')->fetchColumn());
        $bulk($tech, [$site[1], $port[0]], ['action' => 'triage', 'status' => 'open', 'note' => 'Back to open for the next test.']);
        // The Clients list shows each client's risk and open findings, linking to them (1.37).
        $list = $tech->get('/clients')->body;
        Assert::contains('Open findings', $list);
        Assert::contains('/findings?client=' . $cid, $list);
        Assert::contains('3 Fail, 2 Warning', $list);
    },
];
