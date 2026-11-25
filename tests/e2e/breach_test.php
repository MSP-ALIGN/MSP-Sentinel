<?php

declare(strict_types=1);

/**
 * End-to-end tests for breach monitoring (1.33): addresses of verified domains found in data breaches (mock
 * XposedOrNot API on 127.0.0.1) are given to the client whose authorisation lists the domain; a breach in the last
 * 12 months is a Fail, older ones a Warning; nothing for domains in no register; the key is a secret; errors change
 * nothing; addresses no longer listed resolve. Made-up addresses on *.example domains only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$brKey = 'xon-test-key-0123456789abcdef';
$brSetup = static function (TestContext $ctx): int {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Breach Example'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Breach Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
            'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '', 'scope' => "breachco.example\n*.branch.example", 'confirm' => '1']);
    }
    return $cid;
};
$brData = static function (TestContext $ctx, array $entries): void {
    $recent = gmdate('Y-m-d', strtotime('-2 months')) . 'T00:00:00';
    file_put_contents(dirname($ctx->feedsLog) . '/xon-domain-breaches.json', json_encode(['status' => 'success', 'metrics' => [
        'Yearly_Metrics' => ['2016' => 2],
        'Domain_Summary' => ['breachco.example' => 3, 'sub.branch.example' => 1, 'branch.example' => 1, 'unrelated.example' => 1],
        'Breaches_Details' => array_map(static fn (array $e): array => ['email' => $e[0], 'domain' => $e[1], 'breach' => $e[2]], $entries),
        'Detailed_Breach_Info' => [
            'RecentLeak' => ['breached_date' => $recent, 'xposed_data' => 'Email addresses;Passwords;Names', 'xposure_desc' => 'Made-up recent breach <script>x</script>'],
            'OldLeak' => ['breached_date' => '2016-03-01T00:00:00', 'xposed_data' => 'Email addresses;Usernames', 'xposure_desc' => 'Made-up old breach'],
        ],
    ]]));
};
$brAll = [['alice@breachco.example', 'breachco.example', 'RecentLeak'], ['alice@breachco.example', 'breachco.example', 'OldLeak'],
    ['bob@breachco.example', 'breachco.example', 'OldLeak'], ['carol@sub.branch.example', 'sub.branch.example', 'OldLeak'],
    ['dave@branch.example', 'branch.example', 'OldLeak'], ['eve@unrelated.example', 'unrelated.example', 'OldLeak'],
    ['mallory@evil.example', 'breachco.example', 'RecentLeak'], ['<b>x</b>@breachco.example', 'breachco.example', 'OldLeak']];
$finding = static fn (TestContext $ctx, int $cid, string $email): array|false => $ctx->db->query("SELECT severity, status, title, detail FROM findings WHERE client_id = {$cid} AND finding_key = " . $ctx->db->quote('breach:' . $email))->fetch();

return [
    'breach monitoring: admins set the key (a secret); recent breaches are Fails, older Warnings, only for the client\'s domains' => function (TestContext $ctx) use ($brSetup, $brData, $brAll, $brKey, $finding): void {
        $cid = $brSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        @unlink(dirname($ctx->feedsLog) . '/xon-mode.txt');
        $brData($ctx, $brAll);
        $admin->submit('/admin/integrations', '/admin/integrations/breach', ['api_key' => 'not a key!', 'enabled' => '1']);
        Assert::contains('look like an XposedOrNot API key', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/breach', ['api_key' => $brKey, 'enabled' => '1']);
        $page = $admin->get('/admin/integrations')->body;
        Assert::notContains($brKey, $page, 'the key is never shown');
        Assert::notContains($brKey, json_encode($ctx->db->query("SELECT * FROM settings")->fetchAll()), 'stored encrypted');
        $admin->submit('/admin/integrations', '/admin/integrations/breach/check', []);
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('breached address(es)', $page);
        Assert::contains('branch.example, unrelated.example', $page, 'verified domains in no register are listed, and ignored');
        $alice = $finding($ctx, $cid, 'alice@breachco.example');
        Assert::true($alice !== false && $alice['severity'] === 'fail', 'a breach in the last 12 months: Fail');
        Assert::contains('appeared in 2 data breach(es) (latest: RecentLeak, ' . gmdate('Y-m', strtotime('-2 months')), (string) $alice['title']);
        Assert::contains('Passwords', (string) $alice['detail'], 'what was exposed');
        Assert::contains('a***@breachco.example appeared', (string) $alice['title'], 'masked in the title (alerts, chat)');
        Assert::notContains('alice@', (string) $alice['title']);
        Assert::contains('alice@breachco.example', (string) $alice['detail'], 'in full in the detail');
        Assert::same('warn', ($finding($ctx, $cid, 'bob@breachco.example') ?: [])['severity'] ?? null, 'only old breaches: Warning');
        Assert::same('warn', ($finding($ctx, $cid, 'carol@sub.branch.example') ?: [])['severity'] ?? null, '*.branch.example covers sub.branch.example');
        Assert::same(false, $finding($ctx, $cid, 'dave@branch.example'), '*.branch.example does not cover branch.example itself');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM breach_exposures WHERE email IN ('eve@unrelated.example', 'mallory@evil.example') OR email LIKE '%<%'")->fetchColumn(),
            'no other domains, no address listed under a domain it is not on, no malformed address');
        $client = $ctx->clientPages($admin, $cid);
        Assert::contains('Breached accounts', $client);
        Assert::contains('alice@breachco.example', $client);
        Assert::contains('RecentLeak (' . gmdate('Y-m-d', strtotime('-2 months')) . ')', $client);
        Assert::notContains('<script>x</script>', $client);
        $id = App::reportService()->generate(App::clients()->find($cid), 'technical', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        Assert::contains('multi-factor sign-in', (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$id}")->fetchColumn(), 'guidance in reports');
        // Check now at most once an hour; viewers and technicians can't change it.
        $admin->submit('/admin/integrations', '/admin/integrations/breach/check', []);
        Assert::contains('less than an hour ago', $admin->get('/admin/integrations')->body);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'brview'")->fetchColumn() === 0) {
            $ctx->createUser('brview', 'technician', 'Brview-Pass-0001!');
        }
        $tech = $ctx->login('brview', 'Brview-Pass-0001!');
        Assert::status(403, $tech->post('/admin/integrations/breach', ['_csrf' => $tech->get('/findings')->csrf(), 'api_key' => 'x', 'enabled' => '0']));
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'brviewer'")->fetchColumn() === 0) {
            $ctx->createUser('brviewer', 'viewer', 'Brviewer-Pass-0001!');
        }
        $viewer = $ctx->login('brviewer', 'Brviewer-Pass-0001!');
        $vp = $ctx->clientSection($viewer, $cid, 'website');
        Assert::contains('a***@breachco.example', $vp, 'viewers see masked addresses');
        Assert::notContains('alice@breachco.example', $vp);
    },
    'breach monitoring: errors change nothing; addresses no longer listed resolve; weekly schedule' => function (TestContext $ctx) use ($brSetup, $brData, $brAll, $finding): void {
        $cid = $brSetup($ctx);
        $dir = dirname($ctx->feedsLog);
        foreach (['429' => 'slow down', 'garbage' => 'unexpected answer'] as $mode => $msg) {
            file_put_contents($dir . '/xon-mode.txt', $mode);
            Assert::contains($msg, App::breachMonitor()->run());
            Assert::same('open', ($finding($ctx, $cid, 'alice@breachco.example') ?: [])['status'] ?? null, 'a failed read changes nothing (' . $mode . ')');
        }
        @unlink($dir . '/xon-mode.txt');
        // A failed check is tried again after a few hours, not a week.
        App::settings()->set('breach_last_run', gmdate('Y-m-d H:i:s', time() - 7 * 3600));
        App::settings()->set('breach_last_ok_run', gmdate('Y-m-d H:i:s', time() - 8 * 86400));
        Assert::true(App::breachMonitor()->runIfDue() !== null, 'retried after a failure');
        // An answer that would remove most of what is known (an outage, a lapsed verification) removes nothing.
        $brData($ctx, []);
        $guarded = App::breachMonitor()->run();
        Assert::contains('Nothing was removed', $guarded);
        Assert::same('open', ($finding($ctx, $cid, 'alice@breachco.example') ?: [])['status'] ?? null, 'kept');
        // Bob is no longer listed: his row goes and his finding resolves.
        $brData($ctx, array_values(array_filter($brAll, static fn (array $e): bool => $e[0] !== 'bob@breachco.example')));
        App::breachMonitor()->run();
        Assert::same('resolved', ($finding($ctx, $cid, 'bob@breachco.example') ?: [])['status'] ?? null);
        Assert::same('open', ($finding($ctx, $cid, 'alice@breachco.example') ?: [])['status'] ?? null);
        // Weekly: not again within 7 days; again after.
        @unlink($dir . '/xon-calls.log');
        Assert::same(null, App::breachMonitor()->runIfDue(), 'not due yet');
        App::settings()->set('breach_last_run', gmdate('Y-m-d H:i:s', time() - 8 * 86400));
        App::settings()->set('breach_last_ok_run', gmdate('Y-m-d H:i:s', time() - 8 * 86400));
        Assert::true(App::breachMonitor()->runIfDue() !== null, 'due after a week');
        Assert::same(1, count(file($dir . '/xon-calls.log') ?: []), 'one call per check');
        Assert::notContains('xon-test-key', (string) file_get_contents($dir . '/xon-calls.log'), 'the key is never logged');
        // A wrong key: the reason is shown, nothing changes.
        App::settings()->setSecret('xon_api_key', 'xon-wrong-key-0123456789abcdef');
        Assert::contains('refused the API key', App::breachMonitor()->run());
        Assert::same('open', ($finding($ctx, $cid, 'alice@breachco.example') ?: [])['status'] ?? null);
        // An expired authorisation is not a fix: the client's addresses stay.
        App::settings()->setSecret('xon_api_key', 'xon-test-key-0123456789abcdef');
        $ctx->db->exec("UPDATE scan_authorisations SET valid_until = UTC_DATE() - INTERVAL 1 DAY WHERE client_id = {$cid}");
        $brData($ctx, [['carol@sub.branch.example', 'sub.branch.example', 'OldLeak']]);
        App::breachMonitor()->run();
        Assert::same('open', ($finding($ctx, $cid, 'alice@breachco.example') ?: [])['status'] ?? null, 'not removed while the authorization is expired');
        $ctx->db->exec("UPDATE scan_authorisations SET valid_until = UTC_DATE() + INTERVAL 200 DAY WHERE client_id = {$cid}");
        App::settings()->set('breach_enabled', '0');
        Assert::same(null, App::breachMonitor()->runIfDue(), 'off: never runs');
    },
];
