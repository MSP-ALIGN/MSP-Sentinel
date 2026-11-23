<?php

declare(strict_types=1);

/**
 * End-to-end tests for the ITFlow client sync (phase 1), against the mock ITFlow API (tests/mocks/itflow_mock.php on
 * 127.0.0.1, its client list in itflow-clients.json). Never contacts a real ITFlow. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$base = static fn (TestContext $ctx): string => str_replace('/ninja', '/itflow', (string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
$alignBase = static fn (TestContext $ctx): string => str_replace('/ninja', '/align', (string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
$setItflow = static function (TestContext $ctx, array $clients): void {
    file_put_contents(dirname($ctx->feedsLog) . '/itflow-clients.json', json_encode(array_map(static fn (array $c): array => [
        'client_id' => $c[0], 'client_name' => $c[1], 'client_archived_at' => $c[2] ?? null, 'client_updated_at' => '2026-11-22 10:00:00',
    ], $clients)));
};
$key = 'itflow-test-key-0123456789abcdef';

return [
    'ITFlow: admins connect it; the key is encrypted and never shown; test connection reads the clients' => function (TestContext $ctx) use ($base, $setItflow, $key): void {
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Co'], [803, 'Gone Example', '2026-01-01 00:00:00']]);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'ittech'")->fetchColumn() === 0) {
            $ctx->createUser('ittech', 'technician', 'Ittech-Pass-001!');
        }
        $tech = $ctx->login('ittech', 'Ittech-Pass-001!');
        Assert::status(403, $tech->post('/admin/integrations/itflow/sync', ['_csrf' => $tech->get('/')->csrf()]), 'technicians cannot sync');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('id="itflow"', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => 'ftp://itflow.example', 'api_key' => $key, 'enabled' => '1']);
        Assert::contains('must be an https:// address', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx) . '/api/v1', 'api_key' => $key, 'enabled' => '0']);
        Assert::same($base($ctx), App::settings()->fresh('itflow_url'), 'a pasted API address becomes ITFlow\'s address');
        $raw = (string) $ctx->db->query("SELECT value FROM settings WHERE name = 'itflow_api_key'")->fetchColumn();
        Assert::true($raw !== '' && !str_contains($raw, $key), 'key stored encrypted');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/test', []);
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('Connected: the key can see 3 client(s) in ITFlow (2 active)', $page);
        Assert::notContains($key, $page, 'key never shown');
        Assert::notContains($key, implode("\n", $ctx->db->query('SELECT details FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)), 'key never audited');
        // Off: Sync now refuses, and the worker doesn't sync.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/sync', []);
        Assert::contains('Turn on the ITFlow client sync', $admin->get('/admin/integrations')->body);
        Assert::same(null, App::itflowSync()->syncIfDue(), 'off: no sync');
        // A wrong key: the test says so.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => 'wrong-key-0123456789abcdef', 'enabled' => '0']);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/test', []);
        Assert::contains('ITFlow refused the API key', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1']);
    },
    'ITFlow sync: new clients are added (never scanned without authorisation), same names linked, archives followed' => function (TestContext $ctx) use ($setItflow, $alignBase): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $mk = static function (string $name) use ($admin): int {
            $res = $admin->submit('/clients/new', '/clients', ['name' => $name, 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
            return (int) basename((string) $res->location());
        };
        $lighthouse = $mk('lighthouse example'); // same name in another case: linked, not duplicated
        $dock = $mk('Dock Example');
        $ctx->db->exec("UPDATE clients SET itflow_client_id = 899 WHERE id = {$dock}"); // already linked to another ITFlow client
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Co'], [803, 'Gone Example', '2026-01-01 00:00:00'], [804, 'Dock Example'], [805, "Bad\u{202E}Name\x07 Example"]]);
        // MSP Align connected too: ITFlow client 802 is MSP Align client 502 (psa_id 802).
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => $alignBase($ctx), 'api_key' => 'msa_TESTKEY1_' . str_repeat('a', 32), 'enabled' => '1']);

        $admin->submit('/admin/integrations', '/admin/integrations/itflow/sync', []);
        $flash = $admin->get('/admin/integrations')->body;
        Assert::contains('ITFlow sync: 3 new, 1 linked by name', $flash);
        Assert::contains('1 linked to MSP Align by ITFlow ID', $flash);
        $c = static fn (int $itflowId): array => $ctx->db->query("SELECT * FROM clients WHERE itflow_client_id = {$itflowId}")->fetch() ?: [];
        Assert::same($lighthouse, (int) $c(801)['id'], 'linked by name');
        $pier = $c(802);
        Assert::same('Pier Example Co', $pier['name']);
        Assert::same(0, (int) $ctx->db->query('SELECT COUNT(*) FROM scan_authorisations WHERE client_id = ' . (int) $pier['id'])->fetchColumn(), 'no authorisation: never scanned');
        Assert::contains('Not scanned until its authorisation is recorded', (string) $pier['notes']);
        Assert::same(1, (int) $ctx->db->query('SELECT COUNT(*) FROM sites WHERE client_id = ' . (int) $pier['id'])->fetchColumn(), 'default site');
        Assert::same(502, (int) $pier['align_client_id'], 'linked to MSP Align by ITFlow ID');
        Assert::same([], $c(803), 'already archived in ITFlow: not created');
        Assert::same('Dock Example (ITFlow #804)', $c(804)['name'], 'a name clash gets the ITFlow number');
        Assert::same('BadName Example', $c(805)['name'], 'control and direction characters removed');
        Assert::same(null, $c(805)['align_client_id'], 'an ITFlow ID on two MSP Align clients: linked to neither');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE username = 'itflow-sync' AND action = 'client.created'")->fetchColumn() >= 3, 'audited');

        // Not due again for 15 minutes.
        Assert::same(null, App::itflowSync()->syncIfDue(), 'not due');

        // Changes in ITFlow: a rename, an archive; and a client an admin archived in Sentinel.
        $admin->submit('/clients/' . $lighthouse, '/clients/' . $lighthouse . '/archive', ['archive' => '1']); // archived by hand in Sentinel
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Company'], [804, 'Dock Example', '2026-11-20 09:00:00'], [805, 'BadName Example']]);
        $r = App::itflowSync()->sync();
        Assert::contains('1 renamed, 1 archived, 0 restored', $r, $r);
        Assert::same('Pier Example Company', $c(802)['name']);
        Assert::same([1, 1], [(int) $c(804)['is_archived'], (int) $c(804)['itflow_archived']], 'archived because ITFlow archived it');
        Assert::same(1, (int) $c(801)['is_archived'], 'archived by hand in Sentinel: the sync leaves it alone');
        // Unarchived in ITFlow: restored, because the sync archived it.
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Company'], [804, 'Dock Example'], [805, 'BadName Example']]);
        Assert::contains('1 restored', App::itflowSync()->sync());
        Assert::same(0, (int) $c(804)['is_archived']);
        Assert::same(1, (int) $c(801)['is_archived'], 'still archived (an admin did that)');
        // An admin restores a client the sync archived and archives it again by hand: the sync never undoes that.
        $ctx->db->exec('UPDATE clients SET is_archived = 1, itflow_archived = 1 WHERE itflow_client_id = 804');
        $dockId = (int) $c(804)['id'];
        $admin->submit('/clients/' . $dockId, '/clients/' . $dockId . '/archive', ['archive' => '0']);
        $admin->submit('/clients/' . $dockId, '/clients/' . $dockId . '/archive', ['archive' => '1']);
        App::itflowSync()->sync();
        Assert::same(1, (int) $c(804)['is_archived'], 'archived by hand: stays archived although ITFlow has it active');
        // Gone from ITFlow's answer: left alone (the key may not see it any more).
        $setItflow($ctx, [[801, 'Lighthouse Example']]);
        Assert::contains('0 new', App::itflowSync()->sync());
        Assert::same(0, (int) $c(802)['is_archived'], 'not archived just because it is missing');
        // A failed sync is reported and changes nothing.
        App::settings()->setSecret('itflow_api_key', 'wrong-key-0123456789abcdef');
        Assert::contains('Failed: ITFlow refused the API key', App::itflowSync()->sync());
        Assert::same('0', App::settings()->fresh('itflow_last_ok'));
        // Off again for later tests.
        App::settings()->set('itflow_enabled', '0');
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => '', 'clear_key' => '1', 'enabled' => '0']);
    },
];
