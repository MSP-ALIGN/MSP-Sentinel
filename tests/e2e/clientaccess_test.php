<?php

declare(strict_types=1);

/**
 * End-to-end tests for per-user client lists (1.41): a user limited to some clients sees nothing of the others (their
 * pages and records answer 404; lists, search, the dashboard, notifications and owners leave them out), can only give
 * clients they see, can't manage users who see more, and every route with an ID is covered by a client check. Made-up
 * clients and documentation addresses only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

/** Two clients with a finding and a report each, and a technician limited to the first. */
$setup = static function (TestContext $ctx): array {
    $mine = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Visible Example'")->fetchColumn();
    if ($mine === 0) {
        foreach (['Visible Example', 'Hidden Example'] as $name) {
            $ctx->db->prepare('INSERT INTO clients (name, timezone, created_at, updated_at) VALUES (:n, \'UTC\', UTC_TIMESTAMP(), UTC_TIMESTAMP())')->execute(['n' => $name]);
            $cid = (int) $ctx->db->lastInsertId();
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, target, status, first_seen, last_seen, opened_at)
                               VALUES (:c, :k, 'port', 'fail', :t, '198.51.100.9:3389', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 'k' => 'port:access:' . $cid, 't' => 'RDP open at ' . $name]);
            $ctx->db->prepare("INSERT INTO reports (client_id, kind, source, title, period_start, period_end, html, snapshot, html_sha256, generated_at)
                               VALUES (:c, 'executive', 'manual', :t, UTC_DATE(), UTC_DATE(), '<p>x</p>', '{}', :h, UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 't' => 'Report for ' . $name, 'h' => hash('sha256', 'x')]);
        }
        $mine = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Visible Example'")->fetchColumn();
        $uid = $ctx->createUser('limitedtech', 'technician', 'Limitedtech-Pass-0001!');
        App::users()->setClients($uid, [$mine]);
    }
    $hidden = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Hidden Example'")->fetchColumn();
    $f = static fn (int $c): int => (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$c} AND finding_key LIKE 'port:access:%'")->fetchColumn();
    $r = static fn (int $c): int => (int) $ctx->db->query("SELECT id FROM reports WHERE client_id = {$c} ORDER BY id LIMIT 1")->fetchColumn();
    return [$mine, $hidden, $f($mine), $f($hidden), $r($mine), $r($hidden)];
};

return [
    'client access: every route with an ID is checked against the user\'s clients (or is global by nature)' => function (TestContext $ctx): void {
        $router = require dirname(__DIR__, 2) . '/src/routes.php';
        $ref = new \ReflectionProperty($router, 'routes');
        $missing = [];
        foreach ($ref->getValue($router) as $route) {
            $source = (string) $route['regex'];
            if (!str_contains($source, '(?P<')) {
                continue; // no ID in the path
            }
            $o = $route['opts'];
            $global = preg_match('~^#\^/(users|admin)/~', $source) === 1; // users, roles, API tokens: Administration
            if (!($o['client_path'] ?? false) && ($o['client'] ?? null) === null && !$global) {
                $missing[] = $route['method'] . ' ' . $source;
            }
        }
        Assert::same([], $missing, 'routes with an ID but no client check');
    },

    'client access: a limited user sees only their clients, everywhere' => function (TestContext $ctx) use ($setup): void {
        [$mine, $hidden, $fMine, $fHidden, $rMine, $rHidden] = $setup($ctx);
        $u = $ctx->login('limitedtech', 'Limitedtech-Pass-0001!');
        $list = $u->get('/clients')->body;
        Assert::contains('Visible Example', $list);
        Assert::notContains('Hidden Example', $list);
        Assert::status(200, $u->get('/clients/' . $mine));
        foreach (['', '/findings', '/scans', '/devices', '/agents', '/reports', '/engagements'] as $section) {
            Assert::status(404, $u->get('/clients/' . $hidden . $section), 'hidden client page ' . $section);
        }
        Assert::status(404, $u->get('/findings/' . $fHidden), 'a hidden finding');
        Assert::status(404, $u->get('/reports/' . $rHidden), 'a hidden report');
        Assert::status(404, $u->get('/reports/' . $rHidden . '/download'), 'a hidden report download');
        Assert::status(200, $u->get('/findings/' . $fMine));
        $findings = $u->get('/findings?view=flat&status=all')->body;
        Assert::contains('RDP open at Visible Example', $findings);
        Assert::notContains('RDP open at Hidden Example', $findings);
        Assert::notContains('Hidden Example', $u->get('/reports')->body);
        Assert::notContains('Hidden Example', $u->get('/')->body, 'dashboard');
        Assert::notContains('Hidden Example', $u->get('/search?q=Example')->body, 'search');
        Assert::contains('Visible Example', $u->get('/search?q=Example')->body);
        // Actions on hidden records: 404 or skipped, nothing changed.
        $csrf = $u->get('/findings')->csrf();
        Assert::status(404, $u->post('/findings/' . $fHidden . '/triage', ['_csrf' => $csrf, 'status' => 'accepted', 'note' => 'Hidden']));
        $u->post('/findings/bulk', ['_csrf' => $csrf, 'action' => 'triage', 'status' => 'accepted', 'note' => 'Bulk hidden', 'ids[0]' => (string) $fHidden]);
        Assert::same('open', (string) $ctx->db->query("SELECT status FROM findings WHERE id = {$fHidden}")->fetchColumn(), 'bulk skips hidden findings');
        Assert::redirect('/reports', $u->post('/reports', ['_csrf' => $csrf, 'client_id' => (string) $hidden, 'kind' => 'executive']), 'report for a hidden client refused');
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$hidden}")->fetchColumn(), 'no report made');
        // Owners: only users who see the client.
        Assert::true(!in_array('limitedtech', array_column(App::fixWorkflow()->assignableUsers($hidden), 'username'), true), 'not an owner for the hidden client');
        Assert::true(in_array('limitedtech', array_column(App::fixWorkflow()->assignableUsers($mine), 'username'), true), 'an owner for theirs');
        Assert::contains('1 client(s)', $u->get('/profile')->body);
    },

    'client access: notifications and emails go only to users who see the client' => function (TestContext $ctx) use ($setup): void {
        [$mine, $hidden, $fMine, $fHidden] = $setup($ctx);
        $uid = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'limitedtech'")->fetchColumn();
        $count = static fn (): int => (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$uid}")->fetchColumn();
        $before = $count();
        $result = ['opened_ids' => [$fHidden], 'reopened_ids' => [], 'resolved_ids' => [], 'escalated_ids' => []];
        $ctx->db->exec("DELETE FROM finding_events WHERE event = 'alerted' AND finding_id IN ({$fHidden}, {$fMine})");
        App::alerts()->findingsChanged($hidden, $result, true);
        Assert::same($before, $count(), 'nothing about the hidden client');
        App::alerts()->findingsChanged($mine, ['opened_ids' => [$fMine]] + $result, true);
        Assert::true($count() > $before, 'told about their own client');
    },

    'client access: nobody gives clients they don\'t see; a limited Admin doesn\'t count as full control' => function (TestContext $ctx) use ($setup): void {
        [$mine, $hidden] = $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        // A user manager limited to the visible client.
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Client user manager', 'my_password' => 'Admin-Pass-0001!', 'permissions[0]' => 'users.manage', 'permissions[1]' => 'clients.manage']);
        $mgr = $ctx->createUser('clientmgr', 'Client user manager', 'Clientmgr-Pass-0001!');
        App::users()->setClients($mgr, [$mine]);
        $m = $ctx->login('clientmgr', 'Clientmgr-Pass-0001!');
        $viewer = (string) App::roles()->idForKey('viewer');
        $form = ['display_name' => 'Some One', 'email' => '', 'role_id' => $viewer, 'password' => 'Someone-Pass-0001!', 'my_password' => 'Clientmgr-Pass-0001!', 'clients_field' => '1'];
        $res = $m->submit('/users/new', '/users', ['username' => 'allclientsuser', 'all_clients' => '1'] + $form);
        Assert::status(422, $res, 'all clients refused');
        $res = $m->submit('/users/new', '/users', ['username' => 'hiddenuser', 'clients[0]' => (string) $hidden] + $form);
        Assert::status(422, $res);
        Assert::contains('only give clients you see', $res->body);
        Assert::redirect('/users', $m->submit('/users/new', '/users', ['username' => 'visibleuser', 'clients[0]' => (string) $mine] + $form));
        $vu = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'visibleuser'")->fetchColumn();
        Assert::same([$mine], App::users()->clientIds(App::users()->find($vu)));
        // A viewer who sees every client is beyond them: read-only.
        $wide = $ctx->createUser('wideviewer', 'viewer', 'Wideviewer-Pass-0001!');
        Assert::status(403, $m->post('/users/' . $wide, ['_csrf' => $m->get('/users')->csrf(), 'display_name' => 'Changed', 'email' => '', 'role_id' => $viewer, 'is_active' => '1']));
        // A client they add becomes one of theirs.
        $m->submit('/clients/new', '/clients', ['name' => 'Added By Manager Example', 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00',
            'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $new = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Added By Manager Example'")->fetchColumn();
        Assert::true($new > 0 && in_array($new, App::users()->clientIds(App::users()->find($mgr)), true), 'the new client is theirs');
        // Full control means every client: an Admin limited to some clients doesn't count.
        $holders = App::roles()->completeHoldersAfter();
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        Assert::same($holders - 1, App::roles()->completeHoldersAfter($adminId, null, null, false));
        $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$new}");
    },

    'client access (1.42): API tokens never reach more clients, or show more, than their creator' => function (TestContext $ctx) use ($setup): void {
        [$mine, $hidden, $fMine, $fHidden] = $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Client API keeper', 'my_password' => 'Admin-Pass-0001!', 'permissions[0]' => 'api.manage']);
        $keeper = $ctx->createUser('clientapi', 'Client API keeper', 'Clientapi-Pass-0001!');
        App::users()->setClients($keeper, [$mine]);
        $k = $ctx->login('clientapi', 'Clientapi-Pass-0001!');
        $count = static fn (): int => (int) $ctx->db->query('SELECT COUNT(*) FROM api_tokens')->fetchColumn();
        $before = $count();
        $form = ['my_password' => 'Clientapi-Pass-0001!', 'expires_days' => '30', 'ip_allowlist' => ''];
        $k->submit('/admin/api', '/admin/api/tokens', ['name' => 'All of them', 'all_clients' => '1'] + $form);
        $k->submit('/admin/api', '/admin/api/tokens', ['name' => 'The hidden one', 'clients[0]' => (string) $hidden] + $form);
        Assert::same($before, $count(), 'all clients and a hidden client are refused');
        $k->submit('/admin/api', '/admin/api/tokens', ['name' => 'Mine only', 'clients[0]' => (string) $mine] + $form);
        Assert::same($before + 1, $count(), 'their own client is fine');
        Assert::status(403, $k->post('/admin/api/events', ['_csrf' => $k->get('/admin/api')->csrf(), 'event_webhook_enabled' => '1', 'event_webhook_url' => 'https://hooks.example/x']), 'no event webhooks');
        Assert::notContains('id="events"', $k->get('/admin/api')->body);
        // A token for every client, made by someone who is now limited, reaches only the creator's clients.
        [, $secret] = App::apiTokens()->create('Old all-clients token', true, [], false, false, [], 30, $keeper);
        $ids = array_column(json_decode($ctx->api('GET', '/api/v1/clients', $secret)->body, true)['data'] ?? [], 'id');
        Assert::same([$mine], array_map('intval', $ids), 'only the creator\'s clients');
        Assert::status(404, $ctx->api('GET', '/api/v1/findings/' . $fHidden, $secret));
        Assert::status(200, $ctx->api('GET', '/api/v1/findings/' . $fMine, $secret));
        // Breached addresses: masked unless the creator may see them in full.
        $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, status, first_seen, last_seen, opened_at)
                           VALUES (:c, 'breach:pat@visible.example', 'breach', 'warn', 'p***@visible.example appeared in 1 data breach(es)', 'pat@visible.example: Example breach (2026-01)', 'p***@visible.example', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())")
            ->execute(['c' => $mine]);
        $bid = (int) $ctx->db->lastInsertId();
        $body = $ctx->api('GET', '/api/v1/findings/' . $bid, $secret)->body;
        Assert::notContains('pat@visible.example', $body, 'masked for a creator without "See breached addresses"');
        [, $adminSecret] = App::apiTokens()->create('Admin token', true, [], false, false, [], 30, (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn());
        Assert::contains('pat@visible.example', $ctx->api('GET', '/api/v1/findings/' . $bid, $adminSecret)->body, 'in full for an Admin\'s token');
    },
];
