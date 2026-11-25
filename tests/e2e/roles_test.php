<?php

declare(strict_types=1);

/**
 * End-to-end tests for roles and permissions (1.40): the built-in roles keep exactly the rights the old fixed roles had
 * (every route against the 1.39 table), custom roles grant exactly their permissions, nobody can give or take away more
 * than they hold, built-in and own roles can't be changed, someone always holds every permission, and a changed role
 * applies at once. Made-up users only.
 */

use Sentinel\Auth\Permissions;
use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

/** The permission list as form fields (permissions[0] => ..., ...). */
$permFields = static function (array $perms): array {
    $out = [];
    foreach (array_values($perms) as $i => $p) {
        $out['permissions[' . $i . ']'] = $p;
    }
    return $out;
};
$roleId = static fn (TestContext $ctx, string $name): int => (int) $ctx->db->query('SELECT id FROM roles WHERE name = ' . $ctx->db->quote($name))->fetchColumn();

return [
    'roles: the built-in roles keep exactly the rights the 1.39 roles had, on every route' => function (TestContext $ctx): void {
        $router = require dirname(__DIR__, 2) . '/src/routes.php';
        $old = json_decode((string) file_get_contents(dirname(__DIR__) . '/fixtures/routes-1.39-roles.json'), true);
        Assert::true(count($old) > 130, 'the 1.39 table is complete');
        $rank = ['viewer' => 1, 'technician' => 2, 'admin' => 3];
        foreach ($old as $key => $role) {
            [$method, $path] = explode(' ', $key, 2);
            $m = $router->match($method, (string) preg_replace('/\{[a-z]+\}/', '1', $path));
            if (in_array($role, ['public', 'pending'], true)) {
                Assert::same($role, $m['opts']['auth'], $key);
                continue;
            }
            $need = (array) $m['opts']['perm'];
            foreach ($rank as $builtin => $r) {
                $allowed = $need === [] || array_intersect($need, Permissions::builtin($builtin)) !== [];
                Assert::same($r >= $rank[$role], $allowed, "{$key} for {$builtin} (was {$role})");
            }
        }
        // Every action route names known permissions (the Router refuses unknown ones when the table loads).
        Assert::true(Permissions::isComplete(Permissions::builtin('admin')), 'Admin holds everything');
    },

    'roles: a custom role grants exactly its permissions; the Roles page shows who can do what' => function (TestContext $ctx) use ($permFields, $roleId): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $admin->get('/admin/roles');
        Assert::status(200, $page);
        Assert::contains('Who can do what', $page->body);
        Assert::contains('Set due dates', $page->body);
        // Lead technician: the Technician's rights plus due dates and approving engagements.
        $perms = array_merge(Permissions::builtin('technician'), ['findings.due', 'engagements.approve']);
        $res = $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Lead technician', 'description' => 'Senior technicians', 'my_password' => 'Admin-Pass-0001!'] + $permFields($perms));
        Assert::redirect('/admin/roles', $res);
        $lead = $roleId($ctx, 'Lead technician');
        Assert::true($lead > 0, 'saved');
        Assert::same(Permissions::clean($perms), App::roles()->find($lead)['permissions']);
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'role.created'")->fetchColumn() >= 1, 'audited');
        // A name already taken, an unknown permission (dropped), and no password: refused or cleaned.
        Assert::status(422, $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'lead TECHNICIAN', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['scans.run'])));
        Assert::status(422, $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'No password role'] + $permFields(['scans.run'])));

        $ctx->createUser('leadtech', 'Lead technician', 'Leadtech-Pass-0001!');
        $u = $ctx->login('leadtech', 'Leadtech-Pass-0001!');
        Assert::contains('Lead technician', $u->get('/profile')->body, 'the role shows on the profile');
        Assert::status(403, $u->get('/users'), 'no user management');
        Assert::status(403, $u->get('/admin/settings'), 'no settings');
        Assert::status(403, $u->get('/admin'), 'no Administration section at all');
        // Due dates: allowed (not 403) for this role, refused for a plain technician.
        $fid = (int) $ctx->db->query("SELECT id FROM findings WHERE status = 'open' ORDER BY id LIMIT 1")->fetchColumn();
        if ($fid > 0) {
            $r = $u->post('/findings/' . $fid . '/due', ['_csrf' => $u->get('/findings/' . $fid)->csrf(), 'due_date' => gmdate('Y-m-d', time() + 86400 * 10), 'due_note' => 'Agreed with the client']);
            Assert::true($r->status !== 403, 'the lead technician may set due dates');
            $ctx->createUser('plaintech', 'technician', 'Plaintech-Pass-0001!');
            $t = $ctx->login('plaintech', 'Plaintech-Pass-0001!');
            Assert::status(403, $t->post('/findings/' . $fid . '/due', ['_csrf' => $t->get('/findings/' . $fid)->csrf(), 'due_date' => gmdate('Y-m-d', time() + 86400 * 10), 'due_note' => 'x']));
        }
        // Alerts and lists follow the permission: the lead technician may approve engagements and own findings.
        Assert::true(in_array('leadtech', array_column(App::roles()->usersWith('engagements.approve'), 'username'), true), 'counts as an approver');
        Assert::true(in_array('leadtech', array_column(App::fixWorkflow()->assignableUsers(), 'username'), true), 'can own findings');
        Assert::true(!in_array('leadtech', array_column(App::roles()->usersWith('system.manage'), 'username'), true), 'gets no system alerts');
    },

    'roles: nobody gives or takes away more than they hold; built-in and own roles stay as they are' => function (TestContext $ctx) use ($permFields, $roleId): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        // A user manager who may only manage users and create reports.
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'User manager', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['users.manage', 'reports.create']));
        $mgrRole = $roleId($ctx, 'User manager');
        $ctx->createUser('usermgr', 'User manager', 'Usermgr-Pass-0001!');
        $m = $ctx->login('usermgr', 'Usermgr-Pass-0001!');
        $viewerId = (int) App::roles()->idForKey('viewer');
        $techId = (int) App::roles()->idForKey('technician');
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();

        // Roles: only permissions they hold.
        $res = $m->submit('/admin/roles/new', '/admin/roles', ['name' => 'Sneaky', 'my_password' => 'Usermgr-Pass-0001!'] + $permFields(['users.manage', 'findings.due']));
        Assert::status(422, $res);
        Assert::contains('only give permissions you hold', $res->body);
        Assert::redirect('/admin/roles', $m->submit('/admin/roles/new', '/admin/roles', ['name' => 'Report writer', 'my_password' => 'Usermgr-Pass-0001!'] + $permFields(['reports.create'])));
        // Users: only roles they could give; never someone more powerful.
        $res = $m->submit('/users/new', '/users', ['username' => 'newtech', 'display_name' => 'New Tech', 'email' => '', 'role_id' => (string) $techId,
            'password' => 'Newtech-Pass-0001!', 'my_password' => 'Usermgr-Pass-0001!']);
        Assert::status(422, $res);
        Assert::contains('only give a role whose permissions you hold', $res->body);
        Assert::redirect('/users', $m->submit('/users/new', '/users', ['username' => 'newviewer', 'display_name' => 'New Viewer', 'email' => '', 'role_id' => (string) $viewerId,
            'password' => 'Newviewer-Pass-0001!', 'my_password' => 'Usermgr-Pass-0001!']));
        Assert::contains('permissions you don', $m->get('/users/' . $adminId)->body, 'an admin is shown read-only');
        $csrf = $m->get('/users')->csrf();
        Assert::status(403, $m->post('/users/' . $adminId, ['_csrf' => $csrf, 'display_name' => 'Hijacked', 'email' => '', 'role_id' => (string) $viewerId, 'is_active' => '1', 'my_password' => 'Usermgr-Pass-0001!']));
        Assert::status(403, $m->post('/users/' . $adminId . '/password', ['_csrf' => $csrf, 'password' => 'Taken-Over-Pass-01!', 'my_password' => 'Usermgr-Pass-0001!']), 'no password reset of an admin');
        Assert::status(403, $m->post('/users/' . $adminId . '/2fa-reset', ['_csrf' => $csrf, 'password' => 'Taken-Over-Pass-01!', 'my_password' => 'Usermgr-Pass-0001!']), 'no 2FA reset of an admin');
        Assert::same('Alex Admin', (string) $ctx->db->query("SELECT display_name FROM users WHERE id = {$adminId}")->fetchColumn(), 'unchanged');
        // Their own role, built-in roles and roles above them: not changeable.
        Assert::status(403, $m->post('/admin/roles/' . $mgrRole, ['_csrf' => $csrf, 'name' => 'User manager', 'my_password' => 'Usermgr-Pass-0001!'] + $permFields(['users.manage', 'reports.create', 'scans.run'])));
        Assert::status(403, $m->post('/admin/roles/' . $techId, ['_csrf' => $csrf, 'name' => 'Technician', 'my_password' => 'Usermgr-Pass-0001!'] + $permFields(['reports.create'])));
        Assert::contains('Built-in roles can', $admin->get('/admin/roles/' . $techId)->body);
        Assert::status(403, $admin->post('/admin/roles/' . $techId, ['_csrf' => $admin->get('/admin/roles')->csrf(), 'name' => 'Technician', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['reports.create'])), 'not even an admin');
        $lead = $roleId($ctx, 'Lead technician');
        if ($lead > 0) {
            Assert::status(403, $m->post('/admin/roles/' . $lead . '/delete', ['_csrf' => $csrf]), 'a role above them');
        }
        // The Administration menu and overview show only what they may open (1.40.1: the overview cards too).
        $menu = $m->get('/admin')->body; // the Administration menu (1.51: no longer repeated in the user menu)
        Assert::contains('/admin/roles', $menu);
        Assert::notContains('href="/admin/settings"', $menu);
        $overview = $m->get('/admin')->body;
        Assert::contains('href="/users"', $overview);
        Assert::notContains('href="/admin/audit"', $overview, 'no audit card without audit.view');
    },

    'roles: changing a role signs its users out; roles in use are kept; someone always holds everything' => function (TestContext $ctx) use ($permFields, $roleId): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Scanner', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['scans.run']));
        $scanner = $roleId($ctx, 'Scanner');
        $ctx->createUser('scanuser', 'Scanner', 'Scanuser-Pass-0001!');
        $s = $ctx->login('scanuser', 'Scanuser-Pass-0001!');
        Assert::status(200, $s->get('/profile'));
        Assert::redirect('/admin/roles', $admin->submit('/admin/roles/' . $scanner, '/admin/roles/' . $scanner, ['name' => 'Scanner', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['scans.run', 'reports.create'])));
        Assert::redirect('/login', $s->get('/profile'), 'signed out at once');
        Assert::same(['scans.run', 'reports.create'], App::roles()->find($scanner)['permissions']);
        $added = json_decode((string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'role.updated' ORDER BY id DESC LIMIT 1")->fetchColumn(), true);
        Assert::same(['reports.create'], $added['added'] ?? null, 'the audit says what was added');
        // In use: kept. Unused: deleted.
        $csrf = $admin->get('/admin/roles')->csrf();
        $admin->post('/admin/roles/' . $scanner . '/delete', ['_csrf' => $csrf]);
        Assert::true(App::roles()->find($scanner) !== null, 'a role in use is kept');
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Unused role', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['scans.run']));
        $unused = $roleId($ctx, 'Unused role');
        $admin->post('/admin/roles/' . $unused . '/delete', ['_csrf' => $admin->get('/admin/roles')->csrf()]);
        Assert::same(null, App::roles()->find($unused), 'an unused role is deleted');
        // One active Admin always stays: the count the guard uses. Only the built-in Admin counts (1.40.1): a custom
        // role with every permission today would fall short when a later release adds one.
        $holders = App::roles()->completeHoldersAfter();
        Assert::true($holders >= 1, 'admins hold everything');
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        Assert::same($holders - 1, App::roles()->completeHoldersAfter($adminId, (int) App::roles()->idForKey('viewer'), true), 'demoting one admin');
        Assert::same($holders - 1, App::roles()->completeHoldersAfter($adminId, null, false), 'disabling one admin');
        App::roles()->create('Everything', '', Permissions::names(), $adminId);
        $ctx->createUser('fulluser', 'Everything', 'Fulluser-Pass-0001!');
        Assert::same($holders, App::roles()->completeHoldersAfter(), 'a custom role with every permission does not count');
        // The legacy column only ever under-grants for a custom role.
        Assert::same('viewer', (string) $ctx->db->query("SELECT role FROM users WHERE username = 'fulluser'")->fetchColumn());
    },

    'roles (1.40.1): API tokens never do more than their creator; release signers see only the release key' => function (TestContext $ctx) use ($permFields, $roleId): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'API keeper', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['api.manage']));
        $ctx->createUser('apikeeper', 'API keeper', 'Apikeeper-Pass-0001!');
        $k = $ctx->login('apikeeper', 'Apikeeper-Pass-0001!');
        $before = (int) $ctx->db->query('SELECT COUNT(*) FROM api_tokens')->fetchColumn();
        $k->submit('/admin/api', '/admin/api/tokens', ['my_password' => 'Apikeeper-Pass-0001!', 'name' => 'Too strong', 'all_clients' => '1', 'expires_days' => '30', 'can_triage' => '1']);
        Assert::same($before, (int) $ctx->db->query('SELECT COUNT(*) FROM api_tokens')->fetchColumn(), 'a triage token is refused');
        $k->submit('/admin/api', '/admin/api/tokens', ['my_password' => 'Apikeeper-Pass-0001!', 'name' => 'Read only', 'all_clients' => '1', 'expires_days' => '30']);
        Assert::same($before + 1, (int) $ctx->db->query('SELECT COUNT(*) FROM api_tokens')->fetchColumn(), 'a read token is fine');
        // A token made earlier with triage rights loses them when its creator can't triage (read access stays).
        $tok = App::apiTokens();
        [$tid, $secret] = $tok->create('Old triage token', true, [], true, true, [], 30, (int) $ctx->db->query("SELECT id FROM users WHERE username = 'apikeeper'")->fetchColumn());
        $auth = $tok->authenticate('Bearer ' . $secret, '192.0.2.50');
        Assert::true(!isset($auth['error']), 'still authenticates');
        Assert::same([0, 0], [(int) $auth['can_triage'], (int) $auth['can_scan']], 'its triage and scan rights lapsed');
        // A release signer sees the release key on the System page, not the update, backup or retention forms.
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Release signer', 'my_password' => 'Admin-Pass-0001!'] + $permFields(['release.manage']));
        $ctx->createUser('relsigner', 'Release signer', 'Relsigner-Pass-0001!');
        $r = $ctx->login('relsigner', 'Relsigner-Pass-0001!');
        $sys = $r->get('/admin/system');
        Assert::status(200, $sys);
        Assert::contains('Release key', $sys->body);
        Assert::notContains('/admin/system/retention', $sys->body);
        Assert::notContains('/admin/system/update"', $sys->body);
        Assert::notContains('/admin/system/backups', $sys->body);
    },
];
