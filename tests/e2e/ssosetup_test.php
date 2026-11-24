<?php

declare(strict_types=1);

/**
 * End-to-end tests for the automatic "Sign in with Microsoft" setup (1.46): the one-time setup code on the
 * Integrations page and POST /sso-setup/v1/receive, which entra-sso-setup.ps1 calls with the new Entra app's details.
 * The script itself talks to Microsoft Graph and is not run here (tests/unit/powershell_test.php checks it parses);
 * these tests send what it sends. Made-up IDs and secrets only; never contacts Microsoft.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

const SETUP_TENANT = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const SETUP_CLIENT = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

/** Send what the setup script sends; returns [HTTP status, decoded answer]. */
$receive = static function (TestContext $ctx, array $body): array {
    $raw = (string) @file_get_contents($ctx->baseUrl . '/sso-setup/v1/receive', false, stream_context_create(['http' => ['method' => 'POST',
        'header' => "Content-Type: application/json\r\n", 'content' => json_encode($body), 'ignore_errors' => true]]));
    $status = (int) substr((string) ($http_response_header[0] ?? ''), 9, 3);
    return [$status, (array) json_decode($raw, true)];
};
/** A setup code, created on the Integrations page by the admin (with their password). */
$newCode = static function (TestContext $ctx): string {
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $admin->submit('/admin/integrations', '/admin/integrations/sso/setup-code', ['my_password' => 'Admin-Pass-0001!']);
    $page = $admin->get('/admin/integrations')->body;
    Assert::true(preg_match('/data-testid="sso-setup-code">(SSO(?:-[A-Z2-9]{5}){4})</', $page, $m) === 1, 'the code is shown');
    return $m[1];
};
$body = static fn (string $code, array $over = []): array => $over + ['code' => $code, 'tenant_id' => SETUP_TENANT, 'client_id' => SETUP_CLIENT,
    'client_secret' => 'Made~Up.Secret_Value-0123456789abcdefABCDEF', 'secret_expires' => gmdate('Y-m-d\TH:i:s\Z', time() + 365 * 86400),
    'redirect_uri' => 'https://sentinel.example/login/sso/callback'];

return [
    'SSO setup (1.46): only an Admin with every client and their password gets a setup code, shown once' => function (TestContext $ctx) use ($newCode): void {
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'setuptech'")->fetchColumn() === 0) {
            $ctx->createUser('setuptech', 'technician', 'Setuptech-Pass-001!');
        }
        $tech = $ctx->login('setuptech', 'Setuptech-Pass-001!');
        Assert::status(403, $tech->post('/admin/integrations/sso/setup-code', ['_csrf' => $tech->get('/')->csrf(), 'my_password' => 'Setuptech-Pass-001!']));
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::status(400, $admin->post('/admin/integrations/sso/setup-code', ['my_password' => 'Admin-Pass-0001!']), 'CSRF checked');
        $admin->submit('/admin/integrations', '/admin/integrations/sso/setup-code', ['my_password' => 'wrong-password-123']);
        $page = $admin->get('/admin/integrations')->body;
        Assert::notContains('data-testid="sso-setup-code"', $page, 'no code without the right password');
        Assert::same('', App::settings()->fresh('sso_setup_code'));
        $ctx->clearThrottle();
        $code = $newCode($ctx);
        $raw = App::settings()->fresh('sso_setup_code');
        Assert::true($raw !== '' && !str_contains($raw, $code), 'only a hash of the code is stored');
        $page = $admin->get('/admin/integrations')->body;
        Assert::notContains($code, $page, 'shown once');
        Assert::contains('A setup code is waiting to be used', $page);
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'settings.sso_setup_code' AND username = 'admin'")->fetchColumn() >= 1, 'audited');
        // An Admin limited to some clients can't.
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'setupadmin'")->fetchColumn() === 0) {
            $uid = $ctx->createUser('setupadmin', 'admin', 'Setupadmin-Pass-01!');
            $ctx->db->exec("UPDATE users SET all_clients = 0 WHERE id = {$uid}");
        }
        $limited = $ctx->login('setupadmin', 'Setupadmin-Pass-01!');
        Assert::status(403, $limited->post('/admin/integrations/sso/setup-code', ['_csrf' => $limited->get('/')->csrf(), 'my_password' => 'Setupadmin-Pass-01!']));
    },
    'SSO setup (1.46): the script hands over the app once, with the code; nothing is turned on by it' => function (TestContext $ctx) use ($receive, $newCode, $body): void {
        $s = App::settings();
        $before = ['sso_entra_tenant' => $s->fresh('sso_entra_tenant'), 'sso_entra_client' => $s->fresh('sso_entra_client'), 'sso_entra_enabled' => $s->fresh('sso_entra_enabled')];
        $beforeSecret = $s->getSecret('sso_entra_secret');
        $s->set('sso_entra_enabled', '0');
        $code = $newCode($ctx);
        // Wrong, malformed or missing codes are refused.
        Assert::same(403, $receive($ctx, $body('SSO-AAAAA-AAAAA-AAAAA-AAAAA'))[0], 'wrong code');
        Assert::same(403, $receive($ctx, $body('not-a-code'))[0], 'malformed code');
        Assert::same(403, $receive($ctx, ['tenant_id' => SETUP_TENANT])[0], 'no code');
        // Bad details are refused without using the code.
        Assert::same(422, $receive($ctx, $body($code, ['tenant_id' => 'not-a-guid']))[0], 'bad tenant ID');
        Assert::same(422, $receive($ctx, $body($code, ['client_secret' => "bad\nsecret"]))[0], 'bad secret');
        [$st, $ans] = $receive($ctx, $body($code, ['redirect_uri' => 'https://other.example/login/sso/callback']));
        Assert::same(422, $st, 'another redirect address');
        Assert::contains('Sentinel expects https://sentinel.example/login/sso/callback', (string) ($ans['message'] ?? ''));
        // The right details: saved, the secret encrypted, the expiry kept, sign-in still off.
        $ctx->clearThrottle();
        [$st, $ans] = $receive($ctx, $body($code));
        Assert::same(200, $st, json_encode($ans));
        Assert::true(($ans['ok'] ?? false) === true, 'ok');
        Assert::contains('turn on "Sign in with Microsoft"', (string) $ans['message']);
        Assert::same([SETUP_TENANT, SETUP_CLIENT, '0'], [$s->fresh('sso_entra_tenant'), $s->fresh('sso_entra_client'), $s->fresh('sso_entra_enabled')]);
        Assert::same('Made~Up.Secret_Value-0123456789abcdefABCDEF', $s->getSecret('sso_entra_secret'));
        Assert::notContains('Made~Up.Secret', (string) $ctx->db->query("SELECT value FROM settings WHERE name = 'sso_entra_secret'")->fetchColumn(), 'stored encrypted');
        Assert::notContains('Made~Up.Secret', implode("\n", $ctx->db->query('SELECT details FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)), 'never audited');
        Assert::same(gmdate('Y-m-d', time() + 365 * 86400), substr($s->fresh('sso_entra_secret_expires'), 0, 10), 'expiry kept');
        Assert::same('admin', (string) $ctx->db->query("SELECT username FROM audit_log WHERE action = 'settings.sso_setup_received' ORDER BY id DESC LIMIT 1")->fetchColumn(), 'audited as the admin who made the code');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE title LIKE 'Sign in with Microsoft: the setup script sent%'")->fetchColumn() >= 1, 'the admin is told');
        // Used once.
        Assert::same(403, $receive($ctx, $body($code))[0], 'a used code is refused');
        // The card shows the expiry; a renewal into another tenant clears every Microsoft link.
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('The client secret expires on ' . gmdate('Y-m-d', time() + 365 * 86400), $admin->get('/admin/integrations')->body);
        $ctx->db->exec("UPDATE users SET sso_subject = '" . SETUP_TENANT . ":eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' WHERE username = 'setuptech'");
        $code = $newCode($ctx);
        [$st] = $receive($ctx, $body($code, ['tenant_id' => 'ffffffff-ffff-4fff-8fff-ffffffffffff']));
        Assert::same(200, $st);
        Assert::same(0, (int) $ctx->db->query('SELECT COUNT(*) FROM users WHERE sso_subject IS NOT NULL')->fetchColumn(), 'another tenant clears the links');
        // An expired code is refused.
        $code = $newCode($ctx);
        $s->set('sso_setup_expires', (string) (time() - 1));
        Assert::same(403, $receive($ctx, $body($code))[0], 'expired');
        // Typing a secret in by hand forgets the script's expiry date.
        $admin->submit('/admin/integrations', '/admin/integrations/sso', ['tenant_id' => 'ffffffff-ffff-4fff-8fff-ffffffffffff', 'client_id' => SETUP_CLIENT,
            'client_secret' => 'typed-by-hand-secret-0123', 'my_password' => 'Admin-Pass-0001!']);
        Assert::same('', $s->fresh('sso_entra_secret_expires'), 'expiry unknown after a typed secret');
        // Too many failures from one address: refused for a while, even with a right code.
        for ($i = 0; $i < 10; $i++) {
            $receive($ctx, $body('SSO-BBBBB-BBBBB-BBBBB-BBBBB'));
        }
        $code = $newCode($ctx);
        Assert::same(429, $receive($ctx, $body($code))[0], 'rate limited');
        $ctx->clearThrottle();
        App::limiter()->clear('sso-setup:' . \Sentinel\Auth\Auth::ipBucketKey('127.0.0.1'));
        // Put back what the earlier tests set.
        foreach ($before as $k => $v) {
            $s->set($k, $v);
        }
        $s->setSecret('sso_entra_secret', $beforeSecret);
        $s->set('sso_entra_secret_expires', '');
        $s->set('sso_setup_code', '');
    },
    'SSO setup (1.46): admins are reminded 30 and 7 days before the secret expires, and when it has' => function (TestContext $ctx): void {
        $s = App::settings();
        $enabled = $s->fresh('sso_entra_enabled');
        $count = static fn (): int => (int) $ctx->db->query("SELECT COUNT(*) FROM notifications WHERE kind = 'sso_secret'")->fetchColumn();
        $s->set('sso_entra_enabled', '1');
        $s->set('sso_secret_warned', '');
        $s->set('sso_entra_secret_expires', gmdate('Y-m-d H:i:s', time() + 60 * 86400));
        App::alerts()->ssoSecretExpiring($s);
        Assert::same(0, $count(), 'not yet at 60 days');
        $s->set('sso_entra_secret_expires', gmdate('Y-m-d H:i:s', time() + 20 * 86400));
        App::alerts()->ssoSecretExpiring($s);
        $first = $count();
        Assert::true($first >= 1, 'reminded at 30 days');
        App::alerts()->ssoSecretExpiring($s);
        Assert::same($first, $count(), 'once per stage');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('Renew it: create a setup code below', $admin->get('/admin/integrations')->body);
        $s->set('sso_entra_secret_expires', gmdate('Y-m-d H:i:s', time() + 3 * 86400));
        App::alerts()->ssoSecretExpiring($s);
        Assert::true($count() > $first, 'reminded again at 7 days');
        $second = $count();
        $s->set('sso_entra_secret_expires', gmdate('Y-m-d H:i:s', time() - 86400));
        App::alerts()->ssoSecretExpiring($s);
        Assert::true($count() > $second, 'told when it expired');
        Assert::contains('stopped working', (string) $ctx->db->query("SELECT title FROM notifications WHERE kind = 'sso_secret' ORDER BY id DESC LIMIT 1")->fetchColumn());
        $s->set('sso_entra_enabled', $enabled);
        $s->set('sso_entra_secret_expires', '');
        $s->set('sso_secret_warned', '');
    },
];
