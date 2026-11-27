<?php

declare(strict_types=1);

/**
 * End-to-end tests for "Sign in with Microsoft" (1.43, 1.43.1) against the mock Entra ID (tests/mocks/entra_mock.php),
 * never Microsoft: only an Admin with every client sets it up (with their password); users link their own Microsoft
 * account from My profile while signed in, and only linked accounts sign in; Sentinel's code is skipped only with a
 * recent MFA; guests and every forged or tampered ID token and callback are refused; password sign-in can be turned off
 * per user (never for the last Admin); links can be removed, and a new tenant clears them. Made-up tenant, app and
 * accounts only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\HttpClient;
use Sentinel\Tests\HttpResult;
use Sentinel\Tests\TestContext;

const SSO_TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SSO_CLIENT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

/** The settings form fields. */
$ssoForm = static fn (string $tenant = SSO_TENANT): array => ['tenant_id' => $tenant, 'client_id' => SSO_CLIENT, 'client_secret' => 'mock-client-secret-value',
    'enabled' => '1', 'my_password' => 'Admin-Pass-0001!'];
/** Turn SSO on (as the admin, through the Integrations form) and make the made-up technician. */
$setup = static function (TestContext $ctx) use ($ssoForm): void {
    if (App::settings()->fresh('sso_entra_enabled') !== '1') {
        $ctx->login('admin', 'Admin-Pass-0001!')->submit('/admin/integrations', '/admin/integrations/sso', $ssoForm());
    }
    if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'ssouser'")->fetchColumn() === 0) {
        $uid = $ctx->createUser('ssouser', 'technician', 'Ssouser-Pass-0001!');
        $ctx->db->exec("UPDATE users SET email = 'user@msp.example' WHERE id = {$uid}");
    }
};
/** The mock's scenario: claims to set, tamper options. */
$scenario = static function (TestContext $ctx, array $claims = [], array $tamper = []): void {
    $dir = dirname($ctx->configPath) . '/entra';
    @mkdir($dir, 0700, true);
    file_put_contents($dir . '/scenario.json', json_encode(['claims' => (object) $claims, 'tamper' => $tamper]));
};
/** From a response that sends the browser to Microsoft (mock), through the mock's authorize, back to the callback. */
$follow = static function (HttpClient $c, HttpResult $start, ?string $state = null): HttpResult {
    $authorize = (string) $start->location();
    if (!str_starts_with($authorize, 'http://127.0.0.1')) {
        return $start;
    }
    $ch = curl_init($authorize);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false]);
    $raw = (string) curl_exec($ch);
    curl_close($ch);
    preg_match('/^Location: (.+)$/mi', $raw, $m);
    $q = [];
    parse_str((string) parse_url(trim($m[1] ?? ''), PHP_URL_QUERY), $q);
    return $c->get('/login/sso/callback?' . http_build_query(['code' => $q['code'] ?? '', 'state' => $state ?? ($q['state'] ?? '')]));
};
$signIn = static fn (HttpClient $c, ?string $state = null): HttpResult => $follow($c, $c->get('/login/sso'), $state);
/** A user links their Microsoft account from My profile (signed in with password and code). */
$link = static function (TestContext $ctx, string $username = 'ssouser', string $password = 'Ssouser-Pass-0001!') use ($follow): HttpResult {
    $ctx->clearThrottle();
    $u = $ctx->login($username, $password);
    return $follow($u, $u->post('/profile/sso-link', ['_csrf' => $u->get('/profile')->csrf(), 'my_password' => $password]));
};
$subject = static function (TestContext $ctx, string $username = 'ssouser'): ?string {
    $v = $ctx->db->query('SELECT sso_subject FROM users WHERE username = ' . $ctx->db->quote($username))->fetchColumn();
    return $v === null || $v === false ? null : (string) $v;
};
$lastFailure = static fn (TestContext $ctx): string => (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'auth.sso_failed' ORDER BY id DESC LIMIT 1")->fetchColumn();

return [
    'sso: only an Admin with every client sets it up, with their password; the request to Microsoft is well formed' => function (TestContext $ctx) use ($setup, $ssoForm): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/integrations', '/admin/integrations/sso', ['tenant_id' => 'not-a-guid'] + $ssoForm());
        Assert::same('0', App::settings()->fresh('sso_entra_enabled'), 'a bad tenant ID is refused');
        $admin->submit('/admin/integrations', '/admin/integrations/sso', ['my_password' => 'Wrong-Pass-0001!'] + $ssoForm());
        Assert::same('0', App::settings()->fresh('sso_entra_enabled'), 'needs the right password');
        $ctx->clearThrottle();
        // Someone who may manage integrations, but isn't an Admin, can't change sign-in.
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Integrations keeper', 'my_password' => 'Admin-Pass-0001!', 'permissions[0]' => 'integrations.manage']);
        $ctx->createUser('intkeeper', 'Integrations keeper', 'Intkeeper-Pass-0001!');
        $k = $ctx->login('intkeeper', 'Intkeeper-Pass-0001!');
        Assert::status(403, $k->post('/admin/integrations/sso', ['_csrf' => $k->get('/admin/integrations')->csrf(), 'my_password' => 'Intkeeper-Pass-0001!'] + $ssoForm()));
        Assert::notContains('Sign in with Microsoft', $ctx->client()->get('/login')->body, 'no button while off');
        $setup($ctx);
        Assert::same('1', App::settings()->fresh('sso_entra_enabled'));
        Assert::notContains('mock-client-secret-value', (string) $ctx->db->query("SELECT value FROM settings WHERE name = 'sso_entra_secret'")->fetchColumn(), 'secret stored encrypted');
        Assert::contains('Sign in with Microsoft', $ctx->client()->get('/login')->body);
        $loc = (string) $ctx->client()->get('/login/sso')->location();
        $q = [];
        parse_str((string) parse_url($loc, PHP_URL_QUERY), $q);
        Assert::contains('/entra/' . SSO_TENANT . '/oauth2/v2.0/authorize', $loc);
        Assert::same(SSO_CLIENT, $q['client_id'] ?? null);
        Assert::same('https://sentinel.example/login/sso/callback', $q['redirect_uri'] ?? null);
        Assert::same('S256', $q['code_challenge_method'] ?? null);
        Assert::same('3600', $q['max_age'] ?? null, 'asks for a recent sign-in');
        Assert::true(strlen((string) ($q['state'] ?? '')) >= 40 && strlen((string) ($q['nonce'] ?? '')) >= 40, 'random state and nonce');
        Assert::notContains('secret', $loc, 'the secret never goes to the browser');
    },

    'sso: an unlinked account never signs in (not even by email); users link their own from My profile' => function (TestContext $ctx) use ($setup, $scenario, $signIn, $link, $subject): void {
        $setup($ctx);
        $ctx->db->exec("UPDATE users SET sso_subject = NULL WHERE username = 'ssouser'");
        $scenario($ctx, ['email' => 'user@msp.example', 'amr' => ['pwd', 'mfa']]);
        $c = $ctx->client();
        Assert::redirect('/login', $signIn($c), 'the same email address is not enough');
        Assert::redirect('/login', $c->get('/'), 'not signed in');
        Assert::same(null, $subject($ctx), 'nothing linked');
        // Linking needs your password now, even in a signed-in session (1.43.2).
        $u = $ctx->login('ssouser', 'Ssouser-Pass-0001!');
        Assert::redirect('/profile', $u->post('/profile/sso-link', ['_csrf' => $u->get('/profile')->csrf(), 'my_password' => 'Wrong-Pass-0001!']));
        Assert::same(null, $subject($ctx), 'a wrong password links nothing');
        // Linking: signed in with password and code, then proven at Microsoft.
        Assert::redirect('/profile', $link($ctx));
        Assert::same(SSO_TENANT . ':0d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6', $subject($ctx), 'linked to tenant and account');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'user.sso_linked'")->fetchColumn() >= 1, 'link audited');
        Assert::contains('Example User', $ctx->login('ssouser', 'Ssouser-Pass-0001!')->get('/profile')->body, 'the linked account is named on My profile');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM notifications n JOIN users u ON u.id = n.user_id WHERE u.username = 'ssouser' AND n.kind = 'security'")->fetchColumn() >= 1, 'the user is told');
        // An existing link is never replaced quietly.
        $ctx->clearThrottle();
        $u = $ctx->login('ssouser', 'Ssouser-Pass-0001!');
        $res = $u->post('/profile/sso-link', ['_csrf' => $u->get('/profile')->csrf(), 'my_password' => 'Ssouser-Pass-0001!']);
        Assert::redirect('/profile', $res, 'no second link while one exists');
        // Now Microsoft sign-in works: straight in with a recent MFA, Sentinel's code otherwise.
        $c = $ctx->client();
        Assert::redirect('/', $signIn($c), 'straight in with MFA');
        Assert::contains('Ssouser Example', $c->get('/')->body);
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login' AND details LIKE '%sso%'")->fetchColumn() >= 1, 'sign-in audited');
        $scenario($ctx, ['amr' => ['pwd']]);
        $res = $signIn($ctx->client());
        Assert::true(in_array($res->location(), ['/2fa/setup', '/login/2fa'], true), 'no MFA claim: Sentinel asks its own code, got ' . $res->location());
        $scenario($ctx, [], ['stale_mfa']);
        $res = $signIn($ctx->client());
        Assert::true(in_array($res->location(), ['/2fa/setup', '/login/2fa'], true), 'MFA from two hours ago: Sentinel asks its own code');
        $scenario($ctx);
    },

    'sso: forged, tampered, guest or disabled sign-ins are refused, each by its own check' => function (TestContext $ctx) use ($setup, $scenario, $signIn, $link, $subject, $lastFailure): void {
        $setup($ctx);
        $scenario($ctx);
        if ($subject($ctx) === null) {
            $link($ctx);
        }
        $why = ['wrong_key' => 'signature', 'wrong_aud' => 'audience', 'wrong_iss' => 'issuer', 'wrong_tid' => 'tenant', 'expired' => 'expiry',
                'wrong_nonce' => 'nonce', 'guest' => 'member account'];
        foreach ($why as $tamper => $check) {
            $ctx->clearThrottle();
            $scenario($ctx, [], [$tamper]);
            $c = $ctx->client();
            Assert::redirect('/login', $signIn($c), $tamper);
            Assert::redirect('/login', $c->get('/'), 'not signed in after ' . $tamper);
            Assert::contains($check, $lastFailure($ctx), $tamper . ' refused by the ' . $check . ' check');
        }
        $ctx->clearThrottle();
        $scenario($ctx);
        Assert::redirect('/login', $signIn($ctx->client(), 'forged-state-value'), 'a callback with another state');
        Assert::redirect('/login', $ctx->client()->get('/login/sso/callback?code=abc&state=xyz'), 'a callback nobody started');
        // An account linked to nobody (even with an Admin's address), and a disabled user: no sign-in, nothing created.
        $users = (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn();
        $scenario($ctx, ['oid' => '9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a5b4', 'email' => 'admin@msp.example']);
        Assert::redirect('/login', $signIn($ctx->client()), 'an Admin\'s email address on an unlinked account');
        Assert::contains('not_linked', $lastFailure($ctx));
        Assert::same($users, (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn(), 'no account created');
        $ctx->db->exec("UPDATE users SET is_active = 0 WHERE username = 'ssouser'");
        $scenario($ctx);
        Assert::redirect('/login', $signIn($ctx->client()), 'a disabled user');
        $ctx->db->exec("UPDATE users SET is_active = 1 WHERE username = 'ssouser'");
        // Someone else can't link a Microsoft account that is already another user's.
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'othertech'")->fetchColumn() === 0) {
            $ctx->createUser('othertech', 'technician', 'Othertech-Pass-0001!');
        }
        Assert::redirect('/profile', $link($ctx, 'othertech', 'Othertech-Pass-0001!'));
        Assert::same(null, $subject($ctx, 'othertech'), 'not linked twice');
        Assert::contains('link_taken', $lastFailure($ctx));
        $ctx->clearThrottle();
    },

    'sso: password sign-in off per user (never for the last Admin); unlink; a new tenant clears links' => function (TestContext $ctx) use ($setup, $scenario, $signIn, $link, $subject, $ssoForm): void {
        $setup($ctx);
        $scenario($ctx);
        if ($subject($ctx) === null) {
            $link($ctx);
        }
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $uid = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'ssouser'")->fetchColumn();
        $tech = (string) App::roles()->idForKey('technician');
        $res = $admin->submit('/users/' . $uid, '/users/' . $uid, ['display_name' => 'Ssouser Example', 'email' => 'user@msp.example', 'role_id' => $tech,
            'is_active' => '1', 'password_field' => '1', 'my_password' => 'Admin-Pass-0001!']);
        Assert::redirect('/users', $res);
        Assert::same('0', (string) $ctx->db->query("SELECT password_login FROM users WHERE id = {$uid}")->fetchColumn(), 'turned off');
        $ctx->clearThrottle();
        Assert::contains('Password sign-in is turned off', $ctx->client()->submit('/login', '/login', ['username' => 'ssouser', 'password' => 'Ssouser-Pass-0001!'])->body);
        Assert::redirect('/', $signIn($ctx->client()), 'Microsoft sign-in still works');
        // The last Admin who sees every client keeps password sign-in (break-glass).
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        $adminRole = (int) App::roles()->idForKey('admin');
        Assert::same(App::roles()->passwordAdminsAfter($adminId, $adminRole, true, true, true) - 1, App::roles()->passwordAdminsAfter($adminId, $adminRole, true, true, false), 'counted');
        // Unlink by an admin; the user links again from My profile.
        $admin->post('/users/' . $uid . '/sso-unlink', ['_csrf' => $admin->get('/users/' . $uid)->csrf()]);
        Assert::same(null, $subject($ctx), 'unlinked');
        $ctx->db->exec("UPDATE users SET password_login = 1 WHERE id = {$uid}");
        Assert::redirect('/profile', $link($ctx));
        Assert::true($subject($ctx) !== null, 'linked again');
        // An admin password reset (or 2FA reset) clears the link: the account may be compromised.
        $admin->post('/users/' . $uid . '/password', ['_csrf' => $admin->get('/users/' . $uid)->csrf(), 'password' => 'Ssouser-Pass-0001!', 'my_password' => 'Admin-Pass-0001!']);
        Assert::same(null, $subject($ctx), 'a password reset clears the link');
        $ctx->db->exec("UPDATE users SET must_change_password = 0 WHERE id = {$uid}");
        Assert::redirect('/profile', $link($ctx));
        Assert::true($subject($ctx) !== null, 'linked again');
        // A new tenant: every link is cleared.
        $admin->submit('/admin/integrations', '/admin/integrations/sso', $ssoForm('cccccccc-cccc-4ccc-8ccc-cccccccccccc'));
        Assert::same(null, $subject($ctx), 'links cleared with the tenant');
        $admin->submit('/admin/integrations', '/admin/integrations/sso', $ssoForm());
    },
    'sso (1.63.1): forms may lead to Microsoft sign-in; linking works before the sign-in button is switched on' => function (TestContext $ctx) use ($setup, $follow, $subject): void {
        $setup($ctx);
        // "Link my Microsoft account" is a form whose answer redirects to Microsoft: browsers apply form-action to that
        // redirect, so Microsoft's sign-in address must be allowed there (it spun forever without it).
        $u = $ctx->login('ssouser', 'Ssouser-Pass-0001!');
        $csp = (string) $u->get('/profile')->header('content-security-policy');
        // In the test suite the "Microsoft" sign-in is the mock on 127.0.0.1; a real install allows login.microsoftonline.com.
        Assert::true(preg_match("~form-action 'self' http://127\\.0\\.0\\.1:[0-9]+(;|$)~", $csp) === 1, 'Microsoft sign-in (the mock here) allowed for forms: ' . $csp);
        Assert::same('https://login.microsoftonline.com', \Sentinel\Auth\EntraSso::DEFAULT_AUTHORITY, 'the real address');
        // Switch off: no button on the sign-in page and no sign-in, but linking (and the profile card) still work, so
        // admins can link and test before turning it on.
        App::settings()->set('sso_entra_enabled', '0');
        try {
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'ssolinkfirst'")->fetchColumn() === 0) {
                $ctx->createUser('ssolinkfirst', 'technician', 'Ssolinkfirst-Pass-01!');
            }
            // Other users' links are put back afterwards (a Microsoft account links to one user only).
            $saved = $ctx->db->query("SELECT id, sso_subject, sso_name FROM users WHERE sso_subject IS NOT NULL AND username <> 'ssolinkfirst'")->fetchAll();
            $ctx->db->exec("UPDATE users SET sso_subject = NULL WHERE sso_subject IS NOT NULL AND username <> 'ssolinkfirst'");
            Assert::notContains('Sign in with Microsoft', $ctx->client()->get('/login')->body);
            Assert::true(!str_contains((string) $ctx->client()->get('/login/sso')->location(), '/entra/'), 'no sign-in while off');
            $first = $ctx->login('ssolinkfirst', 'Ssolinkfirst-Pass-01!');
            Assert::contains('Link my Microsoft account', $first->get('/profile')->body, 'the card shows while off');
            $ctx->clearThrottle();
            $follow($first, $first->post('/profile/sso-link', ['_csrf' => $first->get('/profile')->csrf(), 'my_password' => 'Ssolinkfirst-Pass-01!']));
            Assert::true($subject($ctx, 'ssolinkfirst') !== null, 'linked while the button is off');
            Assert::contains('works once an admin turns it on', $first->get('/profile')->body, 'the message says sign-in is still off');
            // A sign-in flow can't get through the callback while the switch is off.
            $anon = $ctx->client();
            Assert::true(!str_contains((string) $anon->get('/login/sso')->location(), '/entra/'), 'no sign-in flow starts');
            // Password sign-in can't be turned off while Microsoft sign-in is off (the user couldn't sign in at all).
            $admin = $ctx->login('admin', 'Admin-Pass-0001!');
            $uid = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'ssolinkfirst'")->fetchColumn();
            $ctx->db->exec("UPDATE users SET all_clients = 1 WHERE id = {$uid}");
            $res = $admin->post('/users/' . $uid, ['_csrf' => $admin->get('/users/' . $uid . '/edit')->csrf(), 'display_name' => 'Ssolinkfirst Example', 'email' => '',
                'role_id' => (string) $ctx->db->query("SELECT role_id FROM users WHERE id = {$uid}")->fetchColumn(), 'all_clients' => '1', 'is_active' => '1',
                'password_field' => '1', 'my_password' => 'Admin-Pass-0001!']);
            Assert::contains('Turn on Sign in with Microsoft under Integrations first', $res->body, 'refused with a reason');
            Assert::same('1', (string) $ctx->db->query("SELECT password_login FROM users WHERE id = {$uid}")->fetchColumn(), 'password sign-in stays on while Microsoft sign-in is off');
        } finally {
            App::settings()->set('sso_entra_enabled', '1');
            $ctx->db->exec("UPDATE users SET sso_subject = NULL WHERE username = 'ssolinkfirst'");
            $put = $ctx->db->prepare('UPDATE users SET sso_subject = :s, sso_name = :n WHERE id = :id');
            foreach ($saved ?? [] as $row) {
                $put->execute(['s' => $row['sso_subject'], 'n' => $row['sso_name'], 'id' => $row['id']]);
            }
        }
    },
    'sso (1.64): an Admin can let a Microsoft sign-in replace Sentinel\'s code; off, the code is asked without proof of MFA' => function (TestContext $ctx) use ($setup, $ssoForm, $scenario, $signIn, $link, $subject): void {
        $setup($ctx);
        if ($subject($ctx) === null) {
            $scenario($ctx, ['email' => 'user@msp.example']);
            $link($ctx);
        }
        // Microsoft didn't report MFA (as for most real Entra ID tokens): Sentinel asks its code while the switch is off.
        $scenario($ctx, ['amr' => ['pwd']]);
        Assert::same('0', App::settings()->fresh('sso_trust_mfa'), 'off by default');
        Assert::true(in_array($signIn($ctx->client())->location(), ['/2fa/setup', '/login/2fa'], true), 'code asked while off');
        // Only through the Admin's form, with their password (a technician is refused like every SSO change).
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('Microsoft sign-in replaces Sentinel', $page);
        Assert::contains('Conditional Access', $page, 'the admin is told what it relies on');
        $admin->submit('/admin/integrations', '/admin/integrations/sso', ['trust_mfa' => '1', 'my_password' => 'Wrong-Pass-0001!'] + $ssoForm());
        Assert::same('0', App::settings()->fresh('sso_trust_mfa'), 'needs the right password');
        $ctx->clearThrottle();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/integrations', '/admin/integrations/sso', ['trust_mfa' => '1'] + $ssoForm());
        Assert::same('1', App::settings()->fresh('sso_trust_mfa'));
        Assert::contains('sso_trust_mfa', (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'settings.sso_updated' ORDER BY id DESC LIMIT 1")->fetchColumn(), 'audited');
        // On: straight in after Microsoft, recorded as trusted.
        $c = $ctx->client();
        Assert::redirect('/', $signIn($c), 'straight in when the admin trusts Microsoft');
        Assert::contains('Ssouser Example', $c->get('/')->body);
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.sso_trusted' AND username = 'ssouser'")->fetchColumn() >= 1, 'recorded as trusted');
        // Never for an unlinked Microsoft account, and password sign-ins still need the code.
        $scenario($ctx, ['oid' => '9a9a9a9a-9a9a-4a9a-8a9a-9a9a9a9a9a9a', 'amr' => ['pwd']]);
        Assert::true($signIn($ctx->client())->location() !== '/', 'an unlinked account still gets nothing');
        $p = $ctx->client();
        $res = $p->submit('/login', '/login', ['username' => 'ssouser', 'password' => 'Ssouser-Pass-0001!']);
        Assert::true(in_array($res->location(), ['/2fa/setup', '/login/2fa'], true), 'password sign-in still asks the code');
        // Off again.
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/integrations', '/admin/integrations/sso', $ssoForm());
        Assert::same('0', App::settings()->fresh('sso_trust_mfa'), 'unticking turns it off');
        $scenario($ctx);
    },
];
