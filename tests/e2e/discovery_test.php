<?php

declare(strict_types=1);

/**
 * End-to-end tests: passive discovery against the mock DNS server and mock
 * crt.sh (both on 127.0.0.1), suggestions, the approval flow into a new
 * authorisation, permissions, kill switches and the weekly CLI job.
 * Made-up clients, *.example names and documentation addresses only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\HttpClient;
use Sentinel\Tests\TestContext;

$newClient = static function (TestContext $ctx, HttpClient $admin, string $name, string $scope): int {
    $res = $admin->submit('/clients/new', '/clients', ['name' => $name, 'itflow_client_id' => '', 'timezone' => 'UTC',
        'scan_window_start' => '22:00', 'scan_window_end' => '06:00', 'notes' => '']);
    preg_match('#/clients/(\d+)$#', (string) $res->location(), $m);
    $id = (int) $m[1];
    $admin->submit('/clients/' . $id . '/authorisations/new', '/clients/' . $id . '/authorisations', [
        'approved_by_name' => 'Robin Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
        'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 200),
        'document_ref' => '', 'notes' => '', 'scope' => $scope, 'confirm' => '1',
    ]);
    return $id;
};
$suggestions = static function (TestContext $ctx, int $clientId, string $status = 'pending'): array {
    $stmt = $ctx->db->prepare('SELECT value, kind, source, third_party_hint, detail FROM target_suggestions WHERE client_id = :c AND status = :s ORDER BY value');
    $stmt->execute(['c' => $clientId, 's' => $status]);
    $out = [];
    foreach ($stmt->fetchAll() as $r) {
        $out[$r['value']] = $r;
    }
    return $out;
};

return [
    'manual discovery suggests own names and addresses, never third-party names' => function (TestContext $ctx) use ($newClient, $suggestions): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $newClient($ctx, $admin, 'Discovery Example Ltd', "discovery.example\n203.0.113.10");
        @unlink($ctx->dnsLog);
        $res = $admin->submit('/clients/' . $id, '/clients/' . $id . '/discover', []);
        Assert::redirect('/clients/' . $id . '/discovery', $res);
        $page = $ctx->clientPages($admin, (int) $id);
        Assert::contains('Discovery finished with some problems', $page, 'the mock has a timing-out and a garbage name, so the run is partial');

        $s = $suggestions($ctx, $id);
        foreach (['mail.discovery.example', 'www.discovery.example', 'vpn.discovery.example', 'shop.discovery.example', 'gw.discovery.example',
                  '203.0.113.20', '203.0.113.30', '203.0.113.40', '2001:db8:10::30', '198.51.100.50'] as $expected) {
            Assert::true(isset($s[$expected]), "suggested: {$expected}");
        }
        foreach (['discovery.example', '203.0.113.10', 'mx1.mailhost.example', '203.0.113.99', 'unrelated.example', 'portal.discovery.example', 'ns1.dnshost.example', 'discovery-site.cdnhost.example',
                  'intranet.discovery.example', '10.0.0.5', 'old.discovery.example', 'unrelated.other.example', 'remote.discovery.example'] as $never) {
            Assert::true(!isset($s[$never]), "not suggested: {$never}");
        }
        Assert::same(1, (int) $s['198.51.100.50']['third_party_hint'], 'address behind an outside alias is flagged');
        Assert::contains('cdnhost.example', $s['198.51.100.50']['detail']);
        Assert::same(0, (int) $s['203.0.113.30']['third_party_hint']);
        Assert::same('crtsh', $s['billing.discovery.example']['source'], 'name only known from certificate logs');
        Assert::same('ptr', $s['gw.discovery.example']['source']);

        Assert::contains('mx1.mailhost.example', $page, 'third-party names listed for information');
        Assert::contains('Names at other providers, not suggested', $page);
        Assert::contains('no longer resolve', $page, 'stale certificate names counted');
        Assert::contains('DNS lookup of remote.discovery.example failed', $page);
        // The pre-ticked state: own names ticked, third-party flagged ones not.
        Assert::true((bool) preg_match('/value="\d+" id="sg-\d+" checked>\s*<\/td>\s*<td>\s*<label for="sg-\d+"><code>vpn\.discovery\.example/', $page), 'own name pre-ticked');
        Assert::true((bool) preg_match('/value="\d+" id="sg-\d+" >\s*<\/td>\s*<td>\s*<label for="sg-\d+"><code>198\.51\.100\.50/', $page), 'third-party not pre-ticked');

        // Only the configured mock resolver was asked, and only about this client's names.
        $log = (string) file_get_contents($ctx->dnsLog);
        Assert::contains('MX discovery.example', $log);
        Assert::contains('PTR 10.113.0.203.in-addr.arpa', $log);
        Assert::notContains('A mx1.mailhost.example', $log, 'third-party mail host is not even resolved');
        $run = $ctx->db->query("SELECT status, trigger_type FROM discovery_runs WHERE client_id = {$id}")->fetch();
        Assert::same(['status' => 'partial', 'trigger_type' => 'manual'], $run);
        Assert::true(isset($s['files.discovery.example'], $s['203.0.113.70']), 'records for the asked name are used');
        Assert::contains('DNS lookup of portal.discovery.example failed', $page, 'a CNAME with invalid bytes is rejected without crashing the run');
    },
    'running again does not duplicate; dismissed stays dismissed; restore works' => function (TestContext $ctx) use ($suggestions): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Discovery Example Ltd'")->fetchColumn();
        $before = count($suggestions($ctx, $id));
        $sid = (int) $ctx->db->query("SELECT id FROM target_suggestions WHERE client_id = {$id} AND value = 'gw.discovery.example'")->fetchColumn();
        Assert::redirect('/clients/' . $id . '/discovery', $admin->submit('/clients/' . $id, '/suggestions/' . $sid . '/dismiss', []));
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/discover', []);
        $after = $suggestions($ctx, $id);
        Assert::same($before - 1, count($after), 'no duplicates, dismissed one not back');
        Assert::true(isset($suggestions($ctx, $id, 'dismissed')['gw.discovery.example']), 'still dismissed after re-run');
        Assert::contains('Dismissed suggestions (1)', $ctx->clientSection($admin, (int) $id, 'discovery'));
        $admin->submit('/clients/' . $id, '/suggestions/' . $sid . '/restore', []);
        Assert::true(isset($suggestions($ctx, $id)['gw.discovery.example']), 'restored');
    },
    'approving suggestions creates a replacing authorisation and puts them in scope' => function (TestContext $ctx) use ($suggestions): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Discovery Example Ltd'")->fetchColumn();
        $oldAuth = (int) $ctx->db->query("SELECT id FROM scan_authorisations WHERE client_id = {$id} AND revoked_at IS NULL")->fetchColumn();
        $pick = $ctx->db->query("SELECT id FROM target_suggestions WHERE client_id = {$id} AND value IN ('vpn.discovery.example', '203.0.113.30') ORDER BY id")->fetchAll(PDO::FETCH_COLUMN);
        Assert::true(!App::scope()->isInScope($id, 'vpn.discovery.example'), 'not in scope before approval');

        $form = $admin->get('/clients/' . $id . '/authorisations/new?' . http_build_query(['suggestion' => $pick]));
        Assert::status(200, $form);
        Assert::contains('will replace authorisation(s) #' . $oldAuth, $form->body);
        Assert::contains("# Current scope\ndiscovery.example\n203.0.113.10\n# Added from discovery\n", html_entity_decode($form->body));
        Assert::contains('vpn.discovery.example', $form->body);
        Assert::true((bool) preg_match('/name="approved_by_name" value=""/', $form->body), 'approver must be entered again');
        preg_match('/<textarea[^>]*id="scope"[^>]*>(.*?)<\/textarea>/s', $form->body, $m);
        $res = $admin->post('/clients/' . $id . '/authorisations', [
            '_csrf' => $form->csrf(), 'approved_by_name' => 'Robin Example', 'approved_by_role' => 'Owner',
            'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d'), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 300),
            'document_ref' => 'TICKET-2002', 'notes' => '', 'scope' => html_entity_decode($m[1]), 'confirm' => '1', 'replaces' => (string) $oldAuth,
        ]);
        Assert::redirect('/clients/' . $id . '/authorisations', $res);
        Assert::contains('replaces authorisation(s) #' . $oldAuth, $ctx->clientSection($admin, (int) $id, 'authorisations'));
        Assert::contains('Replaced by authorisation #', (string) $ctx->db->query("SELECT revoke_reason FROM scan_authorisations WHERE id = {$oldAuth}")->fetchColumn());
        Assert::true(App::scope()->isInScope($id, 'vpn.discovery.example'), 'approved name now in scope');
        Assert::true(App::scope()->isInScope($id, '203.0.113.10'), 'old scope carried over');
        $accepted = $suggestions($ctx, $id, 'accepted');
        Assert::true(isset($accepted['vpn.discovery.example'], $accepted['203.0.113.30']), 'suggestions marked accepted');
        Assert::true(!isset($suggestions($ctx, $id)['vpn.discovery.example']), 'no longer pending');
    },
    'replace rules: no future start, expired history untouched, revoked-meanwhile warning' => function (TestContext $ctx) use ($newClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $newClient($ctx, $admin, 'Replace Rules Example', "203.0.113.150");
        $active = (int) $ctx->db->query("SELECT id FROM scan_authorisations WHERE client_id = {$id}")->fetchColumn();
        $ctx->db->exec("INSERT INTO scan_authorisations (client_id, approved_by_name, approved_by_role, approved_on, valid_from, valid_until, recorded_by, created_at)
                        VALUES ({$id}, 'Old Example', 'Owner', '2024-01-01', '2024-01-01', '2024-12-31', 1, UTC_TIMESTAMP())");
        $expired = (int) $ctx->db->lastInsertId();
        $form = $admin->get('/clients/' . $id . '/authorisations/new?replace=1');
        Assert::contains('will replace authorisation(s) #' . $active, $form->body);
        Assert::notContains('#' . $expired . '.', $form->body, 'expired one is not offered for replacing');
        $fields = ['approved_by_name' => 'Robin Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d', time() + 86400 * 5), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 100),
            'document_ref' => '', 'notes' => '', 'scope' => "203.0.113.150\n203.0.113.151", 'confirm' => '1', 'replaces' => $active . ',' . $expired];
        $res = $admin->post('/clients/' . $id . '/authorisations', $fields + ['_csrf' => $form->csrf()]);
        Assert::status(422, $res, 'future start refused when replacing');
        Assert::contains('A replacement must start today', $res->body);
        Assert::same(null, $ctx->db->query("SELECT revoked_at FROM scan_authorisations WHERE id = {$active}")->fetchColumn(), 'nothing revoked');

        // Someone revokes the active one while the form is open.
        $ctx->db->exec("UPDATE scan_authorisations SET revoked_at = UTC_TIMESTAMP(), revoked_by = 1, revoke_reason = 'Client withdrew consent' WHERE id = {$active}");
        $res = $admin->post('/clients/' . $id . '/authorisations', ['valid_from' => gmdate('Y-m-d')] + $fields + ['_csrf' => $res->csrf()]);
        Assert::status(422, $res);
        Assert::contains('was revoked after you opened this form', $res->body);
        Assert::same('Client withdrew consent', $ctx->db->query("SELECT revoke_reason FROM scan_authorisations WHERE id = {$active}")->fetchColumn(), 'reason kept');

        // Saving again (now without the revoked one) works and leaves the expired entry's history alone.
        Assert::redirect('/clients/' . $id . '/authorisations', $admin->post('/clients/' . $id . '/authorisations', ['valid_from' => gmdate('Y-m-d'), 'replaces' => (string) $expired] + $fields + ['_csrf' => $res->csrf()]));
        Assert::same(null, $ctx->db->query("SELECT revoked_at FROM scan_authorisations WHERE id = {$expired}")->fetchColumn(), 'expired authorisation not rewritten');
    },
    'an accepted suggestion comes back when it drops out of scope; archived clients are read-only' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Discovery Example Ltd'")->fetchColumn();
        App::suggestions()->upsert($id, 'hostname', 'vpn.discovery.example', 'dns-common', 'answers DNS', false);
        Assert::same('pending', $ctx->db->query("SELECT status FROM target_suggestions WHERE client_id = {$id} AND value = 'vpn.discovery.example'")->fetchColumn());
        App::suggestions()->upsert($id, 'ip', '203.0.113.20', 'dns', 'address of x (through an alias)', true);
        Assert::same(1, (int) $ctx->db->query("SELECT third_party_hint FROM target_suggestions WHERE client_id = {$id} AND value = '203.0.113.20'")->fetchColumn(), 'third-party flag raised on a later run');
        $sid = (int) $ctx->db->query("SELECT id FROM target_suggestions WHERE client_id = {$id} AND status = 'pending' LIMIT 1")->fetchColumn();
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/archive', ['archive' => '1']);
        $admin->submit('/clients/' . $id, '/suggestions/' . $sid . '/dismiss', []);
        Assert::same('pending', $ctx->db->query("SELECT status FROM target_suggestions WHERE id = {$sid}")->fetchColumn(), 'archived client: no dismissing');
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/archive', ['archive' => '0']);
    },
    'replacing is refused for another client\'s authorisation' => function (TestContext $ctx) use ($newClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $victim = (int) $ctx->db->query("SELECT id FROM scan_authorisations WHERE revoked_at IS NULL ORDER BY id LIMIT 1")->fetchColumn();
        $victimClient = (int) $ctx->db->query("SELECT client_id FROM scan_authorisations WHERE id = {$victim}")->fetchColumn();
        $other = $newClient($ctx, $admin, 'Replace Guard Example', 'replaceguard.example');
        Assert::true($other !== $victimClient, 'different clients');
        $res = $admin->submit('/clients/' . $other . '/authorisations/new', '/clients/' . $other . '/authorisations', [
            'approved_by_name' => 'X Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'),
            'valid_from' => gmdate('Y-m-d'), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 30), 'document_ref' => '', 'notes' => '',
            'scope' => 'replaceguard.example', 'confirm' => '1', 'replaces' => (string) $victim,
        ]);
        Assert::status(400, $res);
        Assert::same(null, $ctx->db->query("SELECT revoked_at FROM scan_authorisations WHERE id = {$victim}")->fetchColumn(), 'other client\'s authorisation untouched');
    },
    'permissions: technician runs and dismisses, viewer cannot, only admin approves' => function (TestContext $ctx): void {
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Discovery Example Ltd'")->fetchColumn();
        $sid = (int) $ctx->db->query("SELECT id FROM target_suggestions WHERE client_id = {$id} AND status = 'pending' LIMIT 1")->fetchColumn();
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'dtech'")->fetchColumn() === 0) {
            $ctx->createUser('dtech', 'technician', 'Dtech-Pass-0001!');
            $ctx->createUser('dview', 'viewer', 'Dview-Pass-0001!');
        }
        $view = $ctx->login('dview', 'Dview-Pass-0001!');
        $page = $view->get('/clients/' . $id);
        $all = $ctx->clientPages($view, (int) $id);
        Assert::notContains('Discover now', $all);
        Assert::notContains('>Dismiss<', $all);
        $t = $page->csrf();
        Assert::status(403, $view->post('/clients/' . $id . '/discover', ['_csrf' => $t]), 'viewer cannot run discovery');
        Assert::status(403, $view->post('/suggestions/' . $sid . '/dismiss', ['_csrf' => $t]), 'viewer cannot dismiss');

        $tech = $ctx->login('dtech', 'Dtech-Pass-0001!');
        $page = $ctx->clientPages($tech, (int) $id);
        Assert::contains('Discover now', $page);
        Assert::notContains('Add selected to a new authorisation', $page, 'technician cannot approve');
        Assert::status(403, $tech->get('/clients/' . $id . '/authorisations/new?suggestion[]=' . $sid));
        Assert::redirect('/clients/' . $id . '/discovery', $tech->submit('/clients/' . $id, '/suggestions/' . $sid . '/dismiss', []));
        Assert::same('dismissed', $ctx->db->query("SELECT status FROM target_suggestions WHERE id = {$sid}")->fetchColumn());
    },
    'discovery refuses without an active authorisation, or when paused' => function (TestContext $ctx) use ($newClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'No Auth Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '22:00', 'scan_window_end' => '06:00', 'notes' => '']);
        $bare = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $bare, '/clients/' . $bare . '/discover', []);
        Assert::contains('no active authorisation', $ctx->clientPages($admin, (int) $bare));

        $id = $newClient($ctx, $admin, 'Paused Discovery Example', 'quiet.example');
        $admin->submit('/', '/scanning/pause', []);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/discover', []);
        Assert::contains('Scanning is paused, so discovery is paused too', $ctx->clientPages($admin, (int) $id));
        $admin->submit('/', '/scanning/resume', []);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/pause', []);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/discover', []);
        Assert::contains('Scanning is paused', $ctx->clientPages($admin, (int) $id));
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM discovery_runs WHERE client_id IN ({$bare}, {$id})")->fetchColumn(), 'no runs recorded');
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/resume', []);
    },
    'a clean run is "completed"; an unreachable resolver marks the run failed' => function (TestContext $ctx) use ($newClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Paused Discovery Example'")->fetchColumn();
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/discover', []);
        $page = $ctx->clientPages($admin, (int) $id);
        Assert::contains('Discovery finished: 2 new suggestion(s).', $page, 'www.quiet.example and the domain\'s address 203.0.113.60');
        Assert::contains('Completed', $page);
        $values = $ctx->db->query("SELECT value FROM target_suggestions WHERE client_id = {$id} ORDER BY value")->fetchAll(PDO::FETCH_COLUMN);
        Assert::same(['203.0.113.60', 'www.quiet.example'], $values);

        $dead = $newClient($ctx, $admin, 'Dead Resolver Example', 'deadzone.example');
        $admin->submit('/clients/' . $dead, '/clients/' . $dead . '/discover', []);
        $page = $ctx->clientPages($admin, (int) $dead);
        Assert::contains('DNS resolver is not answering', $page);
        Assert::same('failed', $ctx->db->query("SELECT status FROM discovery_runs WHERE client_id = {$dead}")->fetchColumn());
    },
    'crt.sh outage makes the run partial, not failed' => function (TestContext $ctx) use ($newClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $newClient($ctx, $admin, 'Crtsh Outage Example', 'crtsh-down.example');
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/discover', []);
        $page = $ctx->clientPages($admin, (int) $id);
        Assert::contains('Certificate log lookup for crtsh-down.example failed: crt.sh returned HTTP 500', $page);
        Assert::same('partial', $ctx->db->query("SELECT status FROM discovery_runs WHERE client_id = {$id}")->fetchColumn());
    },
    'weekly CLI job runs eligible clients and skips the rest' => function (TestContext $ctx): void {
        $cmd = [PHP_BINARY, $ctx->root . '/bin/discover.php'];
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $ctx->root, ['SENTINEL_CONFIG' => $ctx->configPath, 'PATH' => getenv('PATH')]);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        proc_close($proc);
        Assert::contains('ok - Discovery finished', $out);
        Assert::contains('refused - This client has no active authorisation', $out);
        $scheduled = (int) $ctx->db->query("SELECT COUNT(*) FROM discovery_runs WHERE trigger_type = 'scheduled'")->fetchColumn();
        Assert::true($scheduled >= 3, 'scheduled runs recorded');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'discovery.run' AND username = 'cli'")->fetchColumn() >= 3, 'CLI runs audited');
    },
];
