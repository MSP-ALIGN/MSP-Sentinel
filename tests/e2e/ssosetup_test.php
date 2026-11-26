<?php

declare(strict_types=1);

/**
 * End-to-end tests for "Connect to Microsoft 365" (1.63), which replaced the PowerShell setup script: an Admin signs in
 * at Microsoft with a code (device authorization) and Sentinel creates the Entra app through Microsoft Graph. Uses the
 * mock sign-in service and the mock Microsoft Graph (tests/mocks/entra_mock.php, graph_mock.php); made-up tenants, apps
 * and secrets only. Never contacts Microsoft. Also: the secret-expiry reminders (1.46).
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

const CONNECT_TENANT = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const CONNECT_OTHER = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

/** The mocks' scenario ("device" and "graph" options, see the mocks); a fresh Graph state unless $keepGraph. */
$mock = static function (TestContext $ctx, array $device = [], array $graph = [], bool $keepGraph = false): string {
    $dir = dirname($ctx->configPath) . '/entra';
    @mkdir($dir, 0700, true);
    file_put_contents($dir . '/scenario.json', json_encode(['device' => (object) $device, 'graph' => (object) ($graph + ['tenant' => CONNECT_TENANT])]));
    if (!$keepGraph) {
        @unlink($dir . '/graph.json');
    }
    @unlink($dir . '/graph-log.json');
    return $dir;
};
/** Start a connection as the admin (with their password); returns the signed-in client. */
$start = static function (TestContext $ctx, array $extra = []) {
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $admin->submit('/admin/integrations', '/admin/integrations/sso/connect', ['my_password' => 'Admin-Pass-0001!'] + $extra);
    return $admin;
};
/** One check as the page's script does it (JSON). */
$check = static function ($client): array {
    $res = $client->post('/admin/integrations/sso/connect/check', ['_csrf' => $client->get('/admin/integrations')->csrf()], ['Accept' => 'application/json']);
    return (array) json_decode($res->body, true);
};
/** Forget the saved app (tenant, client, secret) so a test starts clean. */
$reset = static function (): void {
    $s = App::settings();
    foreach (['sso_entra_tenant', 'sso_entra_client', 'sso_entra_secret_expires', 'sso_secret_warned'] as $k) {
        $s->set($k, '');
    }
    $s->setSecret('sso_entra_secret', '');
    $s->setSecret('sso_connect', '');
    $s->set('sso_entra_enabled', '0');
};

return [
    'connect (1.63): only an Admin with every client and their password can start; CSRF; the code is shown with the link' => function (TestContext $ctx) use ($mock, $start, $reset): void {
        $reset();
        $mock($ctx);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'setuptech'")->fetchColumn() === 0) {
            $ctx->createUser('setuptech', 'technician', 'Setuptech-Pass-001!');
        }
        $tech = $ctx->login('setuptech', 'Setuptech-Pass-001!');
        Assert::status(403, $tech->post('/admin/integrations/sso/connect', ['_csrf' => $tech->get('/')->csrf(), 'my_password' => 'Setuptech-Pass-001!']));
        Assert::status(403, $tech->post('/admin/integrations/sso/connect/check', ['_csrf' => $tech->get('/')->csrf()]));
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::status(400, $admin->post('/admin/integrations/sso/connect', ['my_password' => 'Admin-Pass-0001!']), 'CSRF checked');
        $admin->submit('/admin/integrations', '/admin/integrations/sso/connect', ['my_password' => 'wrong-password-123']);
        Assert::notContains('data-testid="sso-user-code"', $admin->get('/admin/integrations')->body, 'nothing without the right password');
        Assert::same('', App::settings()->getSecret('sso_connect'));
        $ctx->clearThrottle();
        // An Admin limited to some clients can't.
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'setupadmin'")->fetchColumn() === 0) {
            $uid = $ctx->createUser('setupadmin', 'admin', 'Setupadmin-Pass-01!');
            $ctx->db->exec("UPDATE users SET all_clients = 0 WHERE id = {$uid}");
        }
        $limited = $ctx->login('setupadmin', 'Setupadmin-Pass-01!');
        Assert::status(403, $limited->post('/admin/integrations/sso/connect', ['_csrf' => $limited->get('/')->csrf(), 'my_password' => 'Setupadmin-Pass-01!']));

        $admin = $start($ctx);
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('data-testid="sso-user-code">MOCK1234<', $page);
        Assert::contains('href="https://microsoft.com/devicelogin"', $page);
        Assert::contains('data-sso-poll', $page);
        $req = (array) json_decode((string) file_get_contents(dirname($ctx->configPath) . '/entra/device-request.json'), true);
        Assert::same('14d82eec-204b-4c2f-b7e8-296a70dab67e', $req['client_id'] ?? '', 'Microsoft Graph command-line tools client');
        foreach (['Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'User.Read'] as $scope) {
            Assert::contains($scope, (string) ($req['scope'] ?? ''));
        }
        $stored = App::settings()->fresh('sso_connect');
        Assert::true($stored !== '' && !str_contains($stored, 'mock-device-'), 'the device code is stored encrypted');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'settings.sso_connect_started' AND username = 'admin'")->fetchColumn() >= 1, 'audited');
        // Another admin sees that one is in progress, not its code.
        Assert::status(303, $admin->post('/admin/integrations/sso/connect/cancel', ['_csrf' => $admin->get('/admin/integrations')->csrf()]));
        Assert::same('', App::settings()->getSecret('sso_connect'), 'canceled');
        Assert::notContains('data-testid="sso-user-code"', $admin->get('/admin/integrations')->body);
    },
    'connect (1.63): waits while pending, then creates the app, consent and a 24-month secret; never turns sign-in on' => function (TestContext $ctx) use ($mock, $start, $check, $reset): void {
        $reset();
        $dir = $mock($ctx, ['pending' => 1]);
        $admin = $start($ctx);
        $r = $check($admin);
        Assert::same('pending', $r['status'] ?? '', 'still waiting for the sign-in');
        Assert::same('', App::settings()->fresh('sso_entra_client'), 'nothing saved while pending');
        sleep(1); // the mock asks for 1 second between checks
        $r = $check($admin);
        Assert::same('done', $r['status'] ?? '', json_encode($r));
        Assert::contains('Connected to Example MSP Tenant', $r['message']);
        $s = App::settings();
        Assert::same(CONNECT_TENANT, $s->fresh('sso_entra_tenant'));
        Assert::true(\Sentinel\Auth\EntraSso::validGuid($s->fresh('sso_entra_client')), 'client ID saved');
        Assert::true(str_starts_with($s->getSecret('sso_entra_secret'), 'Mock~Secret.'), 'secret saved');
        $days = \Sentinel\Auth\SsoSetup::secretDaysLeft();
        Assert::true($days !== null && $days >= 728 && $days <= 730, '24-month secret: ' . var_export($days, true));
        Assert::same('0', $s->fresh('sso_entra_enabled'), 'never switched on');
        Assert::same('', $s->getSecret('sso_connect'), 'the connection is used up');
        // What Graph was asked: the app (single tenant, Sentinel's callback, sign-in permissions, auth_time), its service
        // principal, consent for openid/profile/email only, a secret.
        $log = (array) json_decode((string) file_get_contents($dir . '/graph-log.json'), true);
        $post = array_values(array_filter($log, static fn (array $l): bool => $l['method'] === 'POST' && $l['path'] === '/graph/v1.0/applications'))[0]['body'] ?? [];
        Assert::same('AzureADMyOrg', $post['signInAudience'] ?? '');
        Assert::same(['https://sentinel.example/login/sso/callback'], $post['web']['redirectUris'] ?? []);
        Assert::same(['msp-sentinel-sso:sentinel.example'], $post['tags'] ?? []);
        Assert::same('auth_time', $post['optionalClaims']['idToken'][0]['name'] ?? '');
        Assert::same(3, count($post['requiredResourceAccess'][0]['resourceAccess'] ?? []), 'openid, profile, email only');
        $grant = array_values(array_filter($log, static fn (array $l): bool => $l['method'] === 'POST' && $l['path'] === '/graph/v1.0/oauth2PermissionGrants'))[0]['body'] ?? [];
        Assert::same(['AllPrincipals', 'openid profile email', '99999999-9999-4999-8999-999999999999'], [$grant['consentType'] ?? '', $grant['scope'] ?? '', $grant['resourceId'] ?? '']);
        $pw = array_values(array_filter($log, static fn (array $l): bool => str_ends_with($l['path'], '/addPassword')))[0]['body'] ?? [];
        Assert::true(str_starts_with((string) ($pw['passwordCredential']['displayName'] ?? ''), 'MSP Sentinel sign-in'), 'named secret');
        // Audited (without the secret), and the admin is told.
        $audit = (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'settings.sso_connect_done' ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::true($audit !== '' && !str_contains($audit, 'Mock~Secret'), 'audited without the secret');
        Assert::contains('the Entra app is set up', (string) $ctx->db->query("SELECT title FROM notifications ORDER BY id DESC LIMIT 1")->fetchColumn());
        Assert::contains('Connected to Example MSP Tenant', $admin->get('/admin/integrations')->body, 'the result is shown after the reload');

        // Renewing: the same app is updated (found by its tag), a new secret is saved and the older one removed.
        $client = $s->fresh('sso_entra_client');
        $secret = $s->getSecret('sso_entra_secret');
        $mock($ctx, [], [], true);
        $admin = $start($ctx);
        Assert::same('done', $check($admin)['status'] ?? '');
        Assert::same($client, $s->fresh('sso_entra_client'), 'same app');
        Assert::true($s->getSecret('sso_entra_secret') !== $secret, 'new secret');
        $state = (array) json_decode((string) file_get_contents($dir . '/graph.json'), true);
        Assert::same(1, count($state['apps']), 'no second app');
        Assert::same(1, count(array_values($state['apps'])[0]['passwordCredentials']), 'the older secret was removed');
        Assert::true(count(array_filter((array) json_decode((string) file_get_contents($dir . '/graph-log.json'), true), static fn (array $l): bool => $l['method'] === 'PATCH')) >= 1, 'existing app updated');
        // Permissions an admin added by hand are kept when the app is updated (1.63 fix from review).
        $state = (array) json_decode((string) file_get_contents($dir . '/graph.json'), true);
        $id = array_key_first($state['apps']);
        $state['apps'][$id]['requiredResourceAccess'][0]['resourceAccess'][] = ['id' => 'e1fe6dd8-ba31-4d61-89e7-88639da4683d', 'type' => 'Scope'];
        $state['apps'][$id]['requiredResourceAccess'][] = ['resourceAppId' => '00000002-0000-0ff1-ce00-000000000000', 'resourceAccess' => [['id' => 'made-up', 'type' => 'Scope']]];
        file_put_contents($dir . '/graph.json', json_encode($state));
        $mock($ctx, [], [], true);
        $admin = $start($ctx);
        Assert::same('done', $check($admin)['status'] ?? '');
        $access = ((array) json_decode((string) file_get_contents($dir . '/graph.json'), true))['apps'][$id]['requiredResourceAccess'];
        Assert::same(2, count($access), 'the other API is kept');
        Assert::same(4, count($access[0]['resourceAccess']), 'the hand-added Graph permission is kept');
        // Another tab polling after the connection ended gets a quiet answer: nothing audited.
        $before = (int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'settings.sso_connect_failed'")->fetchColumn();
        $check($admin);
        Assert::same($before, (int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'settings.sso_connect_failed'")->fetchColumn(), 'no false failure logged');
        // A check that outlived the browser's request: the next poll still reports the result.
        $mock($ctx, [], [], true);
        $admin = $start($ctx);
        App::entraAppSetup()->check((int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn());
        $r = $check($admin);
        Assert::same('done', $r['status'] ?? '', 'the result is kept for the next poll: ' . json_encode($r));
    },
    'connect (1.63): wrong tenant, declined, blocked, no permission and replication delays are handled' => function (TestContext $ctx) use ($mock, $start, $check, $reset): void {
        $reset();
        $s = App::settings();
        $s->set('sso_entra_tenant', CONNECT_TENANT);
        $s->set('sso_entra_client', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
        $s->setSecret('sso_entra_secret', 'existing-secret-value');
        // Another tenant: nothing is created in it and nothing changes here.
        $dir = $mock($ctx, [], ['tenant' => CONNECT_OTHER, 'org' => 'Other Example Tenant']);
        $admin = $start($ctx);
        $r = $check($admin);
        Assert::same('failed', $r['status'] ?? '');
        Assert::contains('but Sentinel uses tenant ' . CONNECT_TENANT, $r['message']);
        Assert::same(0, count(array_filter((array) json_decode((string) file_get_contents($dir . '/graph-log.json'), true), static fn (array $l): bool => $l['method'] !== 'GET')), 'nothing created in the other tenant');
        Assert::same('existing-secret-value', $s->getSecret('sso_entra_secret'));
        // ...unless switching was allowed: every Microsoft link is cleared and password sign-in turned back on.
        $uid = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        $ctx->db->exec("UPDATE users SET sso_subject = 'made-up-subject', password_login = 1 WHERE id = {$uid}");
        $mock($ctx, [], ['tenant' => CONNECT_OTHER]);
        $admin = $start($ctx, ['new_tenant' => '1']);
        Assert::same('done', $check($admin)['status'] ?? '');
        Assert::same(CONNECT_OTHER, $s->fresh('sso_entra_tenant'));
        Assert::same(null, $ctx->db->query("SELECT sso_subject FROM users WHERE id = {$uid}")->fetchColumn() ?: null, 'links cleared');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!'); // the switch signed everyone out

        // Declined at Microsoft; a blocked code sign-in (Conditional Access) is explained; Microsoft's text never shown.
        foreach (['authorization_declined' => 'declined', 'invalid_grant' => 'set the app up by hand'] as $error => $want) {
            $mock($ctx, ['error' => $error], ['tenant' => CONNECT_OTHER]);
            $admin = $start($ctx);
            $r = $check($admin);
            Assert::same('failed', $r['status'] ?? '', $error);
            Assert::contains($want, $r['message']);
            Assert::notContains('<script>', $r['message']);
            Assert::notContains('AADSTS', $r['message']);
            Assert::same('', $s->getSecret('sso_connect'), 'cleared after a failure');
        }
        // An account that can't register apps.
        $mock($ctx, [], ['tenant' => CONNECT_OTHER, 'forbidden' => true]);
        $admin = $start($ctx);
        $r = $check($admin);
        Assert::same('failed', $r['status'] ?? '');
        Assert::contains('Application Administrator', $r['message']);
        // A slow_down answer waits longer; a new app's service principal that isn't replicated yet is retried; consent
        // that can't be granted is reported but doesn't stop the setup.
        $mock($ctx, ['slow_down' => true], ['tenant' => CONNECT_OTHER, 'sp_fail' => 2, 'consent_fail' => true]);
        $admin = $start($ctx);
        Assert::same('pending', $check($admin)['status'] ?? '', 'slow_down');
        Assert::same('pending', $check($admin)['status'] ?? '', 'waits the longer interval before asking again');
        $state = (array) json_decode((string) $s->getSecret('sso_connect'), true);
        $state['next'] = time();
        $s->setSecret('sso_connect', (string) json_encode($state));
        $r = $check($admin);
        Assert::same('done', $r['status'] ?? '', json_encode($r));
        Assert::contains('Grant admin consent', $r['message']);
        // Only the admin who started can finish.
        $mock($ctx, [], ['tenant' => CONNECT_OTHER]);
        $start($ctx);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'setupadmin3'")->fetchColumn() === 0) {
            $ctx->createUser('setupadmin3', 'admin', 'Setupadmin3-Pass-1!');
        }
        $other = $ctx->login('setupadmin3', 'Setupadmin3-Pass-1!');
        Assert::same('failed', $check($other)['status'] ?? '', 'another admin cannot finish it');
        Assert::notContains('data-testid="sso-user-code"', $other->get('/admin/integrations')->body, 'nor see its code');
        Assert::contains('Another admin has a connection in progress', $other->get('/admin/integrations')->body);
        $reset();
    },
    'connect (1.63): the old setup-script endpoint is gone' => function (TestContext $ctx): void {
        $raw = @file_get_contents($ctx->baseUrl . '/sso-setup/v1/receive', false, stream_context_create(['http' => ['method' => 'POST',
            'header' => "Content-Type: application/json\r\n", 'content' => '{}', 'ignore_errors' => true]]));
        Assert::true(!str_contains((string) ($http_response_header[0] ?? ''), ' 200'), 'no longer answers');
        Assert::true(!is_file(SENTINEL_ROOT . '/entra-sso-setup.ps1'), 'script removed');
    },
    'SSO setup (1.46): admins are reminded 30 and 7 days before the secret expires, and when it has' => function (TestContext $ctx): void {
        $s = App::settings();
        $enabled = $s->fresh('sso_entra_enabled');
        $secretBefore = $s->getSecret('sso_entra_secret');
        $s->setSecret('sso_entra_secret', 'reminder-test-secret-0123');
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
        Assert::contains('Renew it: click &quot;Connect to Microsoft 365&quot; below', $admin->get('/admin/integrations')->body);
        $s->set('sso_entra_secret_expires', gmdate('Y-m-d H:i:s', time() + 3 * 86400));
        App::alerts()->ssoSecretExpiring($s);
        Assert::true($count() > $first, 'reminded again at 7 days');
        $second = $count();
        $s->set('sso_entra_secret_expires', gmdate('Y-m-d H:i:s', time() - 86400));
        App::alerts()->ssoSecretExpiring($s);
        Assert::true($count() > $second, 'told when it expired');
        Assert::contains('stopped working', (string) $ctx->db->query("SELECT title FROM notifications WHERE kind = 'sso_secret' ORDER BY id DESC LIMIT 1")->fetchColumn());
        // Reminders come while the switch is off too (a secret saved but not yet in use).
        $s->set('sso_entra_enabled', '0');
        $s->set('sso_secret_warned', '');
        $before = $count();
        App::alerts()->ssoSecretExpiring($s);
        Assert::true($count() > $before, 'reminded while sign-in is off');
        $s->set('sso_entra_enabled', $enabled);
        $s->setSecret('sso_entra_secret', $secretBefore);
        $s->set('sso_entra_secret_expires', '');
        $s->set('sso_secret_warned', '');
    },
];
