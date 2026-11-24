<?php

declare(strict_types=1);

/**
 * End-to-end tests for "Sign in with Microsoft" (1.43) against the mock Entra ID (tests/mocks/entra_mock.php), never
 * Microsoft: only existing users sign in (linked by email the first time, then by account ID), Sentinel's code is
 * skipped only with MFA, every forged or tampered ID token and callback is refused, password sign-in can be turned
 * off per user (never for the last Admin), and links can be removed. Made-up tenant, app and accounts only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\HttpClient;
use Sentinel\Tests\TestContext;

const SSO_TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SSO_CLIENT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

/** Turn SSO on (as an admin, through the Integrations form) and give the made-up user its email address. */
$setup = static function (TestContext $ctx): void {
    if (App::settings()->fresh('sso_entra_enabled') === '1') {
        return;
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $admin->submit('/admin/integrations', '/admin/integrations/sso', ['tenant_id' => SSO_TENANT, 'client_id' => SSO_CLIENT,
        'client_secret' => 'mock-client-secret-value', 'enabled' => '1']);
    $uid = $ctx->createUser('ssouser', 'technician', 'Ssouser-Pass-0001!');
    $ctx->db->exec("UPDATE users SET email = 'User@msp.example' WHERE id = {$uid}");
};
/** The mock's scenario: claims to set, tamper options. */
$scenario = static function (TestContext $ctx, array $claims = [], array $tamper = []): void {
    $dir = dirname($ctx->configPath) . '/entra';
    @mkdir($dir, 0700, true);
    file_put_contents($dir . '/scenario.json', json_encode(['claims' => (object) $claims, 'tamper' => $tamper]));
};
/**
 * One sign-in through the mock: Sentinel → Microsoft's authorize (mock) → back to the callback. Returns the callback's
 * answer. $state overrides the state sent back (forged callback).
 */
$signIn = static function (HttpClient $c, ?string $state = null): \Sentinel\Tests\HttpResult {
    $start = $c->get('/login/sso');
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

return [
    'sso: set up by an admin; the button shows; the request to Microsoft is well formed' => function (TestContext $ctx) use ($setup): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/integrations', '/admin/integrations/sso', ['tenant_id' => 'not-a-guid', 'client_id' => SSO_CLIENT, 'client_secret' => 'x', 'enabled' => '1']);
        Assert::same('0', App::settings()->fresh('sso_entra_enabled'), 'a bad tenant ID is refused');
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
        Assert::true(strlen((string) ($q['state'] ?? '')) >= 40 && strlen((string) ($q['nonce'] ?? '')) >= 40, 'random state and nonce');
        Assert::notContains('secret', $loc, 'the secret never goes to the browser');
    },

    'sso: an existing user signs in (linked by email, then by account); MFA skips Sentinel\'s code, no MFA asks for it' => function (TestContext $ctx) use ($setup, $scenario, $signIn): void {
        $setup($ctx);
        $scenario($ctx, ['email' => 'user@msp.example', 'amr' => ['pwd', 'mfa']]);
        $c = $ctx->client();
        $res = $signIn($c);
        Assert::redirect('/', $res, 'straight in with MFA');
        Assert::contains('Ssouser Example', $c->get('/')->body);
        $subject = (string) $ctx->db->query("SELECT sso_subject FROM users WHERE username = 'ssouser'")->fetchColumn();
        Assert::same(SSO_TENANT . ':0d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6', $subject, 'linked to tenant and account');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'user.sso_linked'")->fetchColumn() >= 1, 'link audited');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login' AND details LIKE '%sso%'")->fetchColumn() >= 1, 'sign-in audited');
        // The same account with another email still signs in as the linked user.
        $scenario($ctx, ['email' => 'renamed@msp.example', 'amr' => ['pwd', 'mfa']]);
        Assert::redirect('/', $signIn($ctx->client()), 'by account ID once linked');
        // Without MFA: Sentinel's own two-factor step, exactly as after a password.
        $scenario($ctx, ['email' => 'user@msp.example', 'amr' => ['pwd']]);
        $res = $signIn($ctx->client());
        Assert::true(in_array($res->location(), ['/2fa/setup', '/login/2fa'], true), 'no MFA claim: Sentinel asks its own code, got ' . $res->location());
    },

    'sso: forged, tampered or unknown sign-ins are refused' => function (TestContext $ctx) use ($setup, $scenario, $signIn): void {
        $setup($ctx);
        $why = ['wrong_key' => 'signature', 'wrong_aud' => 'audience', 'wrong_iss' => 'issuer', 'wrong_tid' => 'tenant', 'expired' => 'expiry', 'wrong_nonce' => 'nonce'];
        foreach ($why as $tamper => $check) {
            $ctx->clearThrottle();
            $scenario($ctx, ['email' => 'user@msp.example'], [$tamper]);
            $c = $ctx->client();
            Assert::redirect('/login', $signIn($c), $tamper);
            Assert::redirect('/login', $c->get('/'), 'not signed in after ' . $tamper);
            $reason = (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'auth.sso_failed' ORDER BY id DESC LIMIT 1")->fetchColumn();
            Assert::contains($check, $reason, $tamper . ' refused by the ' . $check . ' check');
        }
        $ctx->clearThrottle();
        $scenario($ctx, ['email' => 'user@msp.example']);
        Assert::redirect('/login', $signIn($ctx->client(), 'forged-state-value'), 'a callback with another state');
        Assert::redirect('/login', $ctx->client()->get('/login/sso/callback?code=abc&state=xyz'), 'a callback nobody started');
        // An account matching no user, or a disabled user: no sign-in, nothing created.
        $users = (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn();
        $scenario($ctx, ['oid' => '9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a5b4', 'email' => 'stranger@msp.example']);
        Assert::redirect('/login', $signIn($ctx->client()));
        Assert::same($users, (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn(), 'no account created');
        $ctx->db->exec("UPDATE users SET is_active = 0 WHERE username = 'ssouser'");
        $scenario($ctx, ['email' => 'user@msp.example']);
        Assert::redirect('/login', $signIn($ctx->client()), 'a disabled user');
        $ctx->db->exec("UPDATE users SET is_active = 1 WHERE username = 'ssouser'");
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.sso_failed'")->fetchColumn() >= 8, 'failures audited');
        $ctx->clearThrottle();
    },

    'sso: password sign-in can be turned off per user, never for the last Admin; links can be removed' => function (TestContext $ctx) use ($setup, $scenario, $signIn): void {
        $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $uid = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'ssouser'")->fetchColumn();
        $tech = (string) App::roles()->idForKey('technician');
        $res = $admin->submit('/users/' . $uid, '/users/' . $uid, ['display_name' => 'Ssouser Example', 'email' => 'User@msp.example', 'role_id' => $tech,
            'is_active' => '1', 'password_field' => '1', 'my_password' => 'Admin-Pass-0001!']);
        Assert::redirect('/users', $res);
        Assert::same('0', (string) $ctx->db->query("SELECT password_login FROM users WHERE id = {$uid}")->fetchColumn(), 'turned off');
        $ctx->clearThrottle();
        $res = $ctx->client()->submit('/login', '/login', ['username' => 'ssouser', 'password' => 'Ssouser-Pass-0001!']);
        Assert::contains('Password sign-in is turned off', $res->body);
        // The last Admin who sees every client keeps password sign-in (break-glass).
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        $others = App::roles()->passwordAdminsAfter($adminId, (int) App::roles()->idForKey('admin'), true, true, false);
        $all = App::roles()->passwordAdminsAfter($adminId, (int) App::roles()->idForKey('admin'), true, true, true);
        Assert::same($all - 1, $others, 'turning it off for one Admin is counted');
        // Unlink: the next Microsoft sign-in links again by email.
        $admin->post('/users/' . $uid . '/sso-unlink', ['_csrf' => $admin->get('/users/' . $uid)->csrf()]);
        Assert::same(null, $ctx->db->query("SELECT sso_subject FROM users WHERE id = {$uid}")->fetchColumn() ?: null, 'unlinked');
        $scenario($ctx, ['email' => 'user@msp.example', 'amr' => ['pwd', 'mfa']]);
        Assert::redirect('/', $signIn($ctx->client()), 'links again');
        $ctx->db->exec("UPDATE users SET password_login = 1 WHERE id = {$uid}");
    },
];
