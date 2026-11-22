<?php

declare(strict_types=1);

/**
 * End-to-end tests: clients, sites, the "authorised to scan" register, the
 * scope check and the kill switches. Made-up clients, documentation IPs and
 * *.example domains only. Nothing is ever scanned.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\HttpClient;
use Sentinel\Tests\TestContext;

/** Create a client through the UI and return its ID. */
$makeClient = static function (TestContext $ctx, HttpClient $admin, string $name, string $tz = 'Europe/London'): int {
    $res = $admin->submit('/clients/new', '/clients', [
        'name' => $name, 'itflow_client_id' => '', 'timezone' => $tz,
        'scan_window_start' => '22:00', 'scan_window_end' => '06:00', 'notes' => '',
    ]);
    if (!preg_match('#^/clients/(\d+)$#', (string) $res->location(), $m)) {
        throw new \Sentinel\Tests\AssertionFailed('client not created: HTTP ' . $res->status);
    }
    return (int) $m[1];
};

/** Valid authorisation form values (dates relative to today, UTC). */
$authForm = static function (string $scope, array $overrides = []): array {
    return $overrides + [
        'approved_by_name' => 'Dana Example', 'approved_by_role' => 'Managing Director',
        'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400 * 2),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 300), 'document_ref' => 'TICKET-1001',
        'notes' => '', 'scope' => $scope, 'confirm' => '1',
    ];
};

/** The scope check exactly as later scan steps will call it. */
$inScope = static function (TestContext $ctx, int $clientId, string $target): bool {
    return App::scope()->isInScope($clientId, $target);
};

return [
    'admin creates a client with a default site; validation errors are shown' => function (TestContext $ctx) use ($makeClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $bad = $admin->submit('/clients/new', '/clients', ['name' => '', 'itflow_client_id' => 'abc', 'timezone' => 'Mars/Base',
            'scan_window_start' => '25:00', 'scan_window_end' => '06:00', 'notes' => '']);
        Assert::status(422, $bad);
        foreach (['Enter a name', 'numeric ITFlow client ID', 'Choose a timezone', '24-hour time'] as $msg) {
            Assert::contains($msg, $bad->body);
        }
        $same = $admin->submit('/clients/new', '/clients', ['name' => 'Same Time Ltd', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '22:00', 'scan_window_end' => '22:00', 'notes' => '']);
        Assert::contains('must not start and end at the same time', $same->body);

        $id = $makeClient($ctx, $admin, 'Contoso Example Ltd');
        $page = $admin->get('/clients/' . $id);
        Assert::status(200, $page);
        Assert::contains('Main site', $page->body);
        Assert::contains('No authorisation recorded', $page->body);
        Assert::contains('Cannot be scanned', $page->body);
        $dup = $admin->submit('/clients/new', '/clients', ['name' => 'CONTOSO EXAMPLE LTD', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '22:00', 'scan_window_end' => '06:00', 'notes' => '']);
        Assert::contains('Another client already has this name', $dup->body);
    },
    'viewers and technicians can see clients but not change them' => function (TestContext $ctx) use ($makeClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $makeClient($ctx, $admin, 'Readonly Example Co');
        foreach (['cleo' => 'Cleo-Viewer-Pass1!', 'carl' => 'Carl-Techie-Pass1!'] as $user => $pass) {
            if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = '{$user}'")->fetchColumn() === 0) {
                $ctx->createUser($user, $user === 'cleo' ? 'viewer' : 'technician', $pass);
            }
            $ctx->allowFreshCode($user);
            $c = $ctx->login($user, $pass);
            Assert::status(200, $c->get('/clients'), "{$user} sees the list");
            $page = $c->get('/clients/' . $id);
            Assert::status(200, $page, "{$user} sees the client");
            Assert::notContains('Record authorisation', $page->body, "{$user} has no record button");
            foreach (['/clients/new', '/clients/' . $id . '/edit', '/clients/' . $id . '/authorisations/new'] as $path) {
                Assert::status(403, $c->get($path), "{$user} GET {$path}");
            }
            $t = $page->csrf();
            foreach (['/clients' => ['name' => 'X'], '/clients/' . $id => ['name' => 'X'], '/clients/' . $id . '/archive' => ['archive' => '1'],
                      '/clients/' . $id . '/sites' => ['name' => 'X'], '/clients/' . $id . '/authorisations' => [], '/clients/' . $id . '/resume' => [],
                      '/scanning/resume' => []] as $path => $fields) {
                Assert::status(403, $c->post($path, $fields + ['_csrf' => $t]), "{$user} POST {$path}");
            }
        }
        Assert::same('Readonly Example Co', $ctx->db->query("SELECT name FROM clients WHERE id = {$id}")->fetchColumn(), 'unchanged');
    },
    'recording an authorisation validates dates, confirmation and scope' => function (TestContext $ctx) use ($makeClient, $authForm): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $makeClient($ctx, $admin, 'Fabrikam Example Inc');
        $form = '/clients/' . $id . '/authorisations/new';
        $post = '/clients/' . $id . '/authorisations';

        $res = $admin->submit($form, $post, $authForm("203.0.113.10\n10.0.0.0/24\n198.51.100.0/23\nnot a domain", [
            'approved_by_name' => '', 'confirm' => '', 'valid_until' => gmdate('Y-m-d', time() + 86400 * 900),
            'approved_on' => gmdate('Y-m-d', time() + 86400 * 5),
        ]));
        Assert::status(422, $res);
        foreach (['Enter the name of the person', 'Confirm that the client', 'at most 2 years', 'cannot be in the future',
                  'Line 2', 'Private, internal or reserved', 'Line 3', 'Range too large', 'Line 4', 'Not a valid domain'] as $msg) {
            Assert::contains($msg, $res->body);
        }
        Assert::contains('203.0.113.10', $res->body, 'scope text kept for correction');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_authorisations WHERE client_id = {$id}")->fetchColumn(), 'nothing saved');

        $past = $admin->submit($form, $post, $authForm('203.0.113.10', ['valid_from' => '2024-01-01', 'valid_until' => '2024-06-30']));
        Assert::contains('end date is in the past', $past->body);
        // One malformed date must give a form error, not a server error.
        Assert::status(422, $admin->submit($form, $post, $authForm('203.0.113.10', ['valid_from' => '1'])), 'bad valid_from');
        Assert::status(422, $admin->submit($form, $post, $authForm('203.0.113.10', ['valid_until' => '2026-02-30'])), 'impossible valid_until');
        $from = gmdate('Y-m-d');
        $twoYears = (new DateTimeImmutable($from))->modify('+2 years');
        Assert::status(422, $admin->submit($form, $post, $authForm('203.0.113.10', ['valid_from' => $from, 'valid_until' => $twoYears->modify('+1 day')->format('Y-m-d')])), 'two years and a day refused');

        $ok = $admin->submit($form, $post, $authForm("# public IPs\n203.0.113.10\n198.51.100.0/24\nfabrikam.example\n*.fabrikam.example"));
        Assert::redirect('/clients/' . $id, $ok);
        $page = $admin->get('/clients/' . $id);
        Assert::contains('Authorisation recorded with 4 scope entries', $page->body);
        Assert::contains('Dana Example', $page->body);
        Assert::contains('*.fabrikam.example', $page->body);
        Assert::contains('Can be scanned: 1 active authorisation', $page->body);
    },
    'scope check: only in-scope targets of an active authorisation pass' => function (TestContext $ctx) use ($makeClient, $authForm, $inScope): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $makeClient($ctx, $admin, 'Scope Check Example');
        $admin->submit('/clients/' . $id . '/authorisations/new', '/clients/' . $id . '/authorisations',
            $authForm("203.0.113.64\n198.51.100.0/25\nportal.scopecheck.example\n*.apps.scopecheck.example\n2001:db8:5::/120"));
        foreach (['203.0.113.64', '198.51.100.0', '198.51.100.127', 'portal.scopecheck.example',
                  'crm.apps.scopecheck.example', 'a.b.apps.scopecheck.example', '2001:db8:5::ff'] as $yes) {
            Assert::true($inScope($ctx, $id, $yes), "should be in scope: {$yes}");
        }
        foreach (['203.0.113.65', '198.51.100.128', 'scopecheck.example', 'apps.scopecheck.example', 'evilapps.scopecheck.example',
                  'portal.scopecheck.example.attacker.example', 'xportal.scopecheck.example', '2001:db8:5::100', '', '203.0.113.64/32',
                  '../etc/passwd', 'portal..scopecheck.example',
                  // Non-canonical forms are refused, not cleaned up: callers must scan exactly what was checked.
                  'PORTAL.scopecheck.example', 'portal.scopecheck.example.', "portal.scopecheck.example\n", " 203.0.113.64",
                  '203.0.113.64.', '2001:DB8:5::FF', '2001:db8:5:0::ff', '.apps.scopecheck.example', '-.apps.scopecheck.example'] as $no) {
            Assert::true(!$inScope($ctx, $id, $no), 'should NOT be in scope: ' . json_encode($no));
        }
        Assert::true(!App::scope()->isInScope(999999, '203.0.113.64'), 'unknown client fails closed');
        Assert::same('2001:db8:5::ff', \Sentinel\Scope\ScopeService::canonicalTarget('2001:DB8:5:0::FF'), 'canonicalTarget normalises');
        Assert::same(null, \Sentinel\Scope\ScopeService::canonicalTarget('-.x.example'), 'canonicalTarget rejects bad labels');
        // Pausing in the database is seen at once by the same caller (no stale client row).
        $ctx->db->exec("UPDATE clients SET scanning_paused = 1 WHERE id = {$id}");
        Assert::true(!$inScope($ctx, $id, '203.0.113.64'), 'pause seen immediately');
        $ctx->db->exec("UPDATE clients SET scanning_paused = 0, timezone = 'Not/AZone' WHERE id = {$id}");
        Assert::true(!$inScope($ctx, $id, '203.0.113.64'), 'invalid timezone fails closed');
        $ctx->db->exec("UPDATE clients SET timezone = 'Europe/London' WHERE id = {$id}");
        $other = $makeClient($ctx, $admin, 'Unrelated Example');
        Assert::true(!$inScope($ctx, $other, '203.0.113.64'), 'another client\'s scope never counts');
    },
    'expired, future, revoked, archived and paused all block scanning' => function (TestContext $ctx) use ($makeClient, $authForm, $inScope): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $makeClient($ctx, $admin, 'Lifecycle Example');
        $base = '/clients/' . $id;
        // Future authorisation: recorded, but not active yet.
        $admin->submit($base . '/authorisations/new', $base . '/authorisations', $authForm('203.0.113.80', [
            'valid_from' => gmdate('Y-m-d', time() + 86400 * 10), 'valid_until' => gmdate('Y-m-d', time() + 86400 * 40)]));
        Assert::true(!$inScope($ctx, $id, '203.0.113.80'), 'not active before valid_from');
        Assert::contains('Starts later', $admin->get($base)->body);

        $admin->submit($base . '/authorisations/new', $base . '/authorisations', $authForm('203.0.113.81'));
        Assert::true($inScope($ctx, $id, '203.0.113.81'), 'active');

        // Expiry: simulate the end date passing.
        $ctx->db->exec("UPDATE scan_authorisations SET valid_from = '2025-01-01', valid_until = '2025-12-31' WHERE client_id = {$id} AND id = (SELECT MAX(id) FROM (SELECT id FROM scan_authorisations WHERE client_id = {$id}) t)");
        Assert::true(!$inScope($ctx, $id, '203.0.113.81'), 'expired');
        Assert::contains('Expired', $admin->get($base)->body);

        $admin->submit($base . '/authorisations/new', $base . '/authorisations', $authForm('203.0.113.82'));
        Assert::true($inScope($ctx, $id, '203.0.113.82'), 'new active authorisation');
        $authId = (int) $ctx->db->query("SELECT MAX(id) FROM scan_authorisations WHERE client_id = {$id}")->fetchColumn();

        // Per-client pause by a technician; only an admin can resume.
        $ctx->allowFreshCode('carl');
        $tech = $ctx->login('carl', 'Carl-Techie-Pass1!');
        Assert::redirect($base, $tech->submit($base, $base . '/pause', ['reason' => 'client asked us to stop']));
        Assert::true(!$inScope($ctx, $id, '203.0.113.82'), 'paused client');
        Assert::status(403, $tech->submit($base, $base . '/resume', []), 'technician cannot resume');
        Assert::redirect($base, $admin->submit($base, $base . '/resume', []));
        Assert::true($inScope($ctx, $id, '203.0.113.82'), 'resumed');

        // Archive and restore.
        $admin->submit($base, $base . '/archive', ['archive' => '1']);
        Assert::true(!$inScope($ctx, $id, '203.0.113.82'), 'archived client');
        $before = (int) $ctx->db->query("SELECT COUNT(*) FROM scan_authorisations WHERE client_id = {$id}")->fetchColumn();
        Assert::redirect($base, $admin->submit($base, $base . '/authorisations', $authForm('203.0.113.83')));
        Assert::same($before, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_authorisations WHERE client_id = {$id}")->fetchColumn(), 'archived clients cannot get new authorisations');
        $admin->submit($base, $base . '/archive', ['archive' => '0']);
        Assert::true($inScope($ctx, $id, '203.0.113.82'), 'restored');

        // Revoke: needs a reason, works once.
        Assert::redirect($base, $admin->submit($base, '/authorisations/' . $authId . '/revoke', ['reason' => '']));
        Assert::true($inScope($ctx, $id, '203.0.113.82'), 'revoke without reason refused');
        $admin->submit($base, '/authorisations/' . $authId . '/revoke', ['reason' => 'Contract ended']);
        Assert::true(!$inScope($ctx, $id, '203.0.113.82'), 'revoked');
        $page = $admin->get($base)->body;
        Assert::contains('Contract ended', $page);
        $admin->submit($base, '/authorisations/' . $authId . '/revoke', ['reason' => 'again']);
        Assert::same('Contract ended', $ctx->db->query("SELECT revoke_reason FROM scan_authorisations WHERE id = {$authId}")->fetchColumn(), 'revoked only once');
    },
    'global kill switch: technician pauses, only admin resumes' => function (TestContext $ctx) use ($makeClient, $authForm, $inScope): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $makeClient($ctx, $admin, 'Kill Switch Example');
        $admin->submit('/clients/' . $id . '/authorisations/new', '/clients/' . $id . '/authorisations', $authForm('203.0.113.90'));
        Assert::true($inScope($ctx, $id, '203.0.113.90'), 'before pause');
        $ctx->allowFreshCode('carl');
        $tech = $ctx->login('carl', 'Carl-Techie-Pass1!');
        Assert::redirect('/', $tech->submit('/', '/scanning/pause', ['reason' => 'IDS alerts at client']));
        Assert::true(!$inScope($ctx, $id, '203.0.113.90'), 'globally paused');
        Assert::contains('All scanning is paused', $tech->get('/clients')->body, 'banner shown everywhere');
        Assert::status(403, $tech->submit('/', '/scanning/resume', []), 'technician cannot resume');
        Assert::redirect('/', $admin->submit('/', '/scanning/resume', []));
        Assert::true($inScope($ctx, $id, '203.0.113.90'), 'resumed');
        $actions = $ctx->db->query("SELECT action FROM audit_log WHERE action LIKE 'scanning.%'")->fetchAll(PDO::FETCH_COLUMN);
        Assert::true(in_array('scanning.global_paused', $actions, true) && in_array('scanning.global_resumed', $actions, true), 'audited');
    },
    'overlapping scope with another client triggers a warning' => function (TestContext $ctx) use ($makeClient, $authForm): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $a = $makeClient($ctx, $admin, 'Overlap One Example');
        $b = $makeClient($ctx, $admin, 'Overlap Two Example');
        $admin->submit('/clients/' . $a . '/authorisations/new', '/clients/' . $a . '/authorisations', $authForm("198.51.100.128/26\nshared.example"));
        $admin->submit('/clients/' . $b . '/authorisations/new', '/clients/' . $b . '/authorisations', $authForm("198.51.100.130\nshared.example\n203.0.113.200"));
        $page = $admin->get('/clients/' . $b)->body;
        Assert::contains('198.51.100.130 is also in scope for client &quot;Overlap One Example&quot;', $page);
        Assert::contains('shared.example is also in scope', $page);
        Assert::notContains('203.0.113.200 is also in scope', $page);
        // Wildcards overlap with names under them, in both directions.
        $c = $makeClient($ctx, $admin, 'Overlap Three Example');
        $admin->submit('/clients/' . $c . '/authorisations/new', '/clients/' . $c . '/authorisations', $authForm("www.wild.example\nwww.unrelated.example"));
        $d = $makeClient($ctx, $admin, 'Overlap Four Example');
        $admin->submit('/clients/' . $d . '/authorisations/new', '/clients/' . $d . '/authorisations', $authForm("*.wild.example\nwww.lonely.example"));
        $page = $admin->get('/clients/' . $d)->body;
        Assert::contains('*.wild.example is also in scope for client &quot;Overlap Three Example&quot;', $page, 'wildcard covers another client\'s exact name');
        Assert::notContains('www.lonely.example is also in scope', $page);
        Assert::true(\Sentinel\Scope\AuthorisationRepository::domainsOverlap('www.shared.example', '*.shared.example'), 'exact under wildcard');
        Assert::true(!\Sentinel\Scope\AuthorisationRepository::domainsOverlap('shared.example', '*.shared.example'), 'bare domain not under its wildcard');
        Assert::true(!\Sentinel\Scope\AuthorisationRepository::domainsOverlap('evilshared.example', '*.shared.example'), 'no partial-label match');
    },
    'sites: add, rename, reject duplicates' => function (TestContext $ctx) use ($makeClient): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $makeClient($ctx, $admin, 'Sites Example');
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/sites', ['name' => 'Warehouse', 'itflow_location_id' => '42']);
        Assert::contains('Site Warehouse added', $admin->get('/clients/' . $id)->body);
        $admin->submit('/clients/' . $id, '/clients/' . $id . '/sites', ['name' => 'warehouse', 'itflow_location_id' => '']);
        Assert::contains('already has a site with that name', $admin->get('/clients/' . $id)->body);
        $siteId = (int) $ctx->db->query("SELECT id FROM sites WHERE client_id = {$id} AND name = 'Warehouse'")->fetchColumn();
        $admin->submit('/clients/' . $id, '/sites/' . $siteId, ['name' => 'North Warehouse', 'itflow_location_id' => 'x']);
        Assert::contains('numeric ITFlow location ID', $admin->get('/clients/' . $id)->body);
        $admin->submit('/clients/' . $id, '/sites/' . $siteId, ['name' => 'North Warehouse', 'itflow_location_id' => '43']);
        Assert::same('North Warehouse', $ctx->db->query("SELECT name FROM sites WHERE id = {$siteId}")->fetchColumn());
    },
    'client and authorisation text is escaped (no stored XSS)' => function (TestContext $ctx) use ($makeClient, $authForm): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = $makeClient($ctx, $admin, '<script>alert(1)</script> Example');
        $admin->submit('/clients/' . $id . '/authorisations/new', '/clients/' . $id . '/authorisations',
            $authForm('203.0.113.99', ['approved_by_name' => '"><img src=x onerror=alert(2)>', 'notes' => '<b onmouseover=alert(3)>hi</b>']));
        foreach (['/clients', '/clients/' . $id, '/admin/audit'] as $path) {
            $body = $admin->get($path)->body;
            Assert::notContains('<script>alert(1)</script>', $body, $path);
            Assert::notContains('<img src=x', $body, $path);
            Assert::notContains('<b onmouseover', $body, $path);
        }
    },
    'dashboard counts clients and active authorisations; audit records the register' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $admin->get('/')->body;
        Assert::contains('active scan authorisations', $page);
        Assert::contains('Pause all scanning', $page);
        $actions = $ctx->db->query('SELECT DISTINCT action FROM audit_log')->fetchAll(PDO::FETCH_COLUMN);
        foreach (['client.created', 'client.archived', 'client.restored', 'authorisation.created', 'authorisation.revoked',
                  'scanning.client_paused', 'scanning.client_resumed', 'site.created', 'site.updated'] as $expected) {
            Assert::true(in_array($expected, $actions, true), "audit has {$expected}");
        }
        $details = (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'authorisation.created' ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::contains('"confirmed_by_admin":true', $details);
    },
];
