<?php

declare(strict_types=1);

/**
 * End-to-end tests: roles, user management, profile, settings, audit log and escaping.
 * All users and passwords are made up.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'viewers and technicians cannot reach admin pages (GET or POST)' => function (TestContext $ctx): void {
        $ctx->createUser('vera', 'viewer', 'Viewer-Pass-0001!');
        $ctx->createUser('theo', 'technician', 'Techie-Pass-0001!');
        foreach (['vera' => 'Viewer-Pass-0001!', 'theo' => 'Techie-Pass-0001!'] as $user => $pass) {
            $c = $ctx->login($user, $pass);
            Assert::status(200, $c->get('/'), "{$user} dashboard");
            foreach (['/users', '/users/new', '/users/1', '/admin/audit', '/admin/settings'] as $path) {
                Assert::status(403, $c->get($path), "{$user} GET {$path}");
            }
            $token = $c->get('/')->csrf();
            Assert::status(403, $c->post('/users', ['_csrf' => $token, 'username' => 'sneaky', 'display_name' => 'S', 'role' => 'admin', 'password' => 'Sneaky-Pass-0001!']), "{$user} POST /users");
            Assert::status(403, $c->post('/admin/settings', ['_csrf' => $token, 'product_name' => 'Hacked', 'source_url' => 'https://evil.example']), "{$user} POST settings");
            Assert::notContains('href="/users"', $c->get('/')->body, "{$user} has no admin menu");
        }
        $count = (int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'sneaky'")->fetchColumn();
        Assert::same(0, $count, 'no user created by non-admins');
        $denied = (int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'access.denied'")->fetchColumn();
        Assert::true($denied > 0, 'denied access is audited');
    },
    'admin creates a user with validation, and the new user must change the password' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $bad = $admin->submit('/users/new', '/users', ['username' => 'x', 'display_name' => '', 'email' => 'not-an-email', 'role' => 'superuser', 'password' => 'short']);
        Assert::status(422, $bad);
        foreach (['Use 3 to 50 letters', 'Enter a name', 'valid email', 'Choose a role', 'at least 12'] as $msg) {
            Assert::contains($msg, $bad->body);
        }
        $dup = $admin->submit('/users/new', '/users', ['username' => 'ADMIN', 'display_name' => 'Dup', 'email' => '', 'role' => 'viewer', 'password' => 'Duplicate-Pass-01!']);
        Assert::contains('already taken', $dup->body, 'usernames are case-insensitive unique');

        $ok = $admin->submit('/users/new', '/users', ['username' => 'nina.new', 'display_name' => 'Nina New', 'email' => 'nina@msp.example', 'role' => 'technician', 'password' => 'Temp-Pass-0001!']);
        Assert::status(422, $ok, 'creating a user needs your own password');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'nina.new'")->fetchColumn());
        $ok = $admin->submit('/users/new', '/users', ['username' => 'nina.new', 'display_name' => 'Nina New', 'email' => 'nina@msp.example', 'role' => 'technician', 'password' => 'Temp-Pass-0001!', 'my_password' => 'Admin-Pass-0001!']);
        Assert::redirect('/users', $ok);
        Assert::contains('nina.new', $admin->get('/users')->body);

        // New user: enrol 2FA, then every page sends them to change the temporary password.
        $nina = $ctx->login('nina.new', 'Temp-Pass-0001!');
        Assert::redirect('/profile/password', $nina->get('/'));
        Assert::status(200, $nina->get('/help'), 'help is reachable during a forced password change');
        $res = $nina->submit('/profile/password', '/profile/password', ['current_password' => 'Temp-Pass-0001!', 'new_password' => 'Nina-Own-Pass-01!', 'confirm_password' => 'Nina-Own-Pass-01!']);
        Assert::redirect('/', $res);
        Assert::status(200, $nina->get('/'), 'dashboard after changing the password');
    },
    'password change checks the current password and signs out other sessions' => function (TestContext $ctx): void {
        $ctx->createUser('pat', 'viewer', 'Pat-First-Pass-01!');
        $first = $ctx->login('pat', 'Pat-First-Pass-01!');
        $ctx->allowFreshCode('pat');
        $second = $ctx->login('pat', 'Pat-First-Pass-01!');
        $wrong = $first->submit('/profile/password', '/profile/password', ['current_password' => 'nope-nope-nope', 'new_password' => 'Pat-Second-Pass-1!', 'confirm_password' => 'Pat-Second-Pass-1!']);
        Assert::status(422, $wrong);
        Assert::contains('current password is not correct', $wrong->body);
        $mismatch = $first->submit('/profile/password', '/profile/password', ['current_password' => 'Pat-First-Pass-01!', 'new_password' => 'Pat-Second-Pass-1!', 'confirm_password' => 'Pat-Other-Pass-1!']);
        Assert::contains('do not match', $mismatch->body);
        $ok = $first->submit('/profile/password', '/profile/password', ['current_password' => 'Pat-First-Pass-01!', 'new_password' => 'Pat-Second-Pass-1!', 'confirm_password' => 'Pat-Second-Pass-1!']);
        Assert::redirect('/', $ok);
        Assert::status(200, $first->get('/'), 'this session stays signed in');
        Assert::redirect('/login', $second->get('/'), 'other session is signed out');
        $old = $ctx->client()->submit('/login', '/login', ['username' => 'pat', 'password' => 'Pat-First-Pass-01!']);
        Assert::status(422, $old, 'old password no longer works');
    },
    'admin cannot change own role or disable self' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        $res = $admin->submit('/users/' . $id, '/users/' . $id, ['display_name' => 'Alex Admin', 'email' => 'admin@msp.example', 'role' => 'viewer', 'my_password' => 'Admin-Pass-0001!']);
        Assert::redirect('/users', $res);
        $row = $ctx->db->query("SELECT role, is_active FROM users WHERE id = {$id}")->fetch();
        Assert::same('admin', $row['role'], 'role unchanged');
        Assert::same(1, (int) $row['is_active'], 'still active');
        Assert::status(200, $admin->get('/users'), 'admin session still valid after editing self');
    },
    'role change and password reset by an admin take effect immediately' => function (TestContext $ctx): void {
        $id = $ctx->createUser('rita', 'technician', 'Rita-Pass-0001!!');
        $rita = $ctx->login('rita', 'Rita-Pass-0001!!');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $noPw = $admin->submit('/users/' . $id, '/users/' . $id, ['display_name' => 'Rita Example', 'email' => '', 'role' => 'viewer', 'is_active' => '1']);
        Assert::status(422, $noPw);
        Assert::contains('Enter your own password to confirm', $noPw->body, 'a role change needs the admin\'s own password');
        $admin->submit('/users/' . $id, '/users/' . $id, ['display_name' => 'Rita Example', 'email' => '', 'role' => 'viewer', 'is_active' => '1', 'my_password' => 'Admin-Pass-0001!']);
        Assert::same('viewer', $ctx->db->query("SELECT role FROM users WHERE id = {$id}")->fetchColumn());
        Assert::redirect('/login', $rita->get('/'), 'role change ends existing sessions');

        $ctx->allowFreshCode('rita');
        $rita = $ctx->login('rita', 'Rita-Pass-0001!!');
        $reset = $admin->submit('/users/' . $id, '/users/' . $id . '/password', ['password' => 'Rita-Temp-Pass-02!', 'my_password' => 'Admin-Pass-0001!']);
        Assert::redirect('/users/' . $id, $reset);
        Assert::redirect('/login', $rita->get('/'), 'password reset ends existing sessions');
        $ctx->allowFreshCode('rita');
        $rita = $ctx->login('rita', 'Rita-Temp-Pass-02!');
        Assert::redirect('/profile/password', $rita->get('/'), 'temporary password must be changed');
    },
    'admin 2FA reset forces re-enrolment' => function (TestContext $ctx): void {
        $id = $ctx->createUser('lou', 'viewer', 'Lou-Pass-00001!!');
        $ctx->login('lou', 'Lou-Pass-00001!!');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        // Without a new temporary password the reset is refused.
        $admin->submit('/users/' . $id, '/users/' . $id . '/2fa-reset', []);
        Assert::true($ctx->db->query("SELECT totp_enabled_at FROM users WHERE id = {$id}")->fetchColumn() !== null, 'reset refused without a password');
        Assert::redirect('/users/' . $id, $admin->submit('/users/' . $id, '/users/' . $id . '/2fa-reset', ['password' => 'Lou-Temp-Pass-02!', 'my_password' => 'Admin-Pass-0001!']));
        $old = $ctx->client()->submit('/login', '/login', ['username' => 'lou', 'password' => 'Lou-Pass-00001!!']);
        Assert::status(422, $old, 'old password no longer works, so nobody else can enroll in the user\'s place');
        $res = $ctx->client()->submit('/login', '/login', ['username' => 'lou', 'password' => 'Lou-Temp-Pass-02!']);
        Assert::redirect('/2fa/setup', $res, 'must enroll again');
        Assert::same(1, (int) $ctx->db->query("SELECT must_change_password FROM users WHERE id = {$id}")->fetchColumn(), 'temporary password must be changed');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = {$id}")->fetchColumn(), 'old recovery codes removed');
    },
    'fixing a name or email does not sign the user out' => function (TestContext $ctx): void {
        $id = $ctx->createUser('nora', 'viewer', 'Nora-Pass-0001!!');
        $nora = $ctx->login('nora', 'Nora-Pass-0001!!');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/users/' . $id, '/users/' . $id, ['display_name' => 'Nora Renamed', 'email' => 'nora@msp.example', 'role' => 'viewer', 'is_active' => '1']);
        Assert::same('Nora Renamed', $ctx->db->query("SELECT display_name FROM users WHERE id = {$id}")->fetchColumn());
        Assert::status(200, $nora->get('/'), 'session survives a cosmetic change');
    },
    'user-supplied text is escaped everywhere (no stored XSS)' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $payload = '<script>alert("x")</script><img src=x onerror=alert(1)>';
        $admin->submit('/users/new', '/users', ['username' => 'xss.test', 'display_name' => $payload, 'email' => '', 'role' => 'viewer', 'password' => 'Xss-Test-Pass-01!', 'my_password' => 'Admin-Pass-0001!']);
        $list = $admin->get('/users')->body;
        Assert::notContains('<script>alert("x")</script>', $list);
        Assert::notContains('<img src=x', $list);
        Assert::contains('&lt;script&gt;', $list);
        $audit = $admin->get('/admin/audit')->body;
        Assert::notContains('<script>alert', $audit);
        // A failed login with a hostile username is echoed back escaped.
        $login = $ctx->client()->submit('/login', '/login', ['username' => '"><script>alert(2)</script>', 'password' => 'whatever-123456']);
        Assert::notContains('<script>alert(2)</script>', $login->body);
    },
    'settings: white-label name applies, unsafe URLs are refused' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $bad = $admin->submit('/admin/settings', '/admin/settings', ['product_name' => 'Example Shield', 'source_url' => 'javascript:alert(1)']);
        Assert::status(422, $bad);
        Assert::contains('http:// or https://', $bad->body);
        $badName = $admin->submit('/admin/settings', '/admin/settings', ['product_name' => '<b>x</b>', 'source_url' => 'https://code.example/sentinel']);
        Assert::status(422, $badName);
        $ok = $admin->submit('/admin/settings', '/admin/settings', ['product_name' => 'Example Shield', 'source_url' => 'https://code.example/sentinel']);
        Assert::redirect('/admin/settings', $ok);
        $page = $admin->get('/');
        Assert::contains('<title>Dashboard · Example Shield</title>', $page->body);
        Assert::contains('href="https://code.example/sentinel"', $page->body, 'source link in footer (AGPL)');
        Assert::contains('Example Shield', $ctx->client()->get('/login')->body, 'login page uses the name too');
        // Put the defaults back for other tests and screenshots.
        $admin->submit('/admin/settings', '/admin/settings', ['product_name' => 'MSP Sentinel', 'source_url' => 'https://github.com/msp-align/msp-sentinel']);
    },
    'audit log records security events without secrets' => function (TestContext $ctx): void {
        $actions = $ctx->db->query('SELECT DISTINCT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN);
        foreach (['auth.login', 'auth.login_failed', 'auth.2fa_enrolled', 'auth.logout', 'user.created', 'user.updated', 'user.password_reset', 'user.2fa_reset', 'settings.updated', 'access.denied'] as $expected) {
            Assert::true(in_array($expected, $actions, true), "audit has {$expected}");
        }
        $all = implode("\n", $ctx->db->query('SELECT CONCAT_WS(" ", username, details) FROM audit_log')->fetchAll(PDO::FETCH_COLUMN));
        foreach (['Admin-Pass-0001!', 'Temp-Pass-0001!', 'Rita-Temp-Pass-02!', 'Pat-Second-Pass-1!'] as $secret) {
            Assert::notContains($secret, $all, 'no passwords in the audit log');
        }
    },
    'unknown pages, bad IDs and wrong methods give clean errors' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::status(404, $admin->get('/no-such-page'));
        Assert::status(404, $admin->get('/users/999999'));
        Assert::status(404, $admin->get('/users/abc'));
        Assert::redirect('/users/1', $admin->get('/users/1/password'), 'a form address opened as a page goes to the page holding the form');
        $res = $admin->get('/users/999999');
        Assert::contains('Page not found', $res->body);
        Assert::notContains('Stack trace', $res->body);
    },
];
