<?php

declare(strict_types=1);

/**
 * End-to-end tests for search (1.34): the top bar's search across clients, findings (title, target, CVE) and help;
 * text filters on the findings list and the audit log; LIKE wildcards match literally; everything escaped; every
 * signed-in user may search. Made-up data only.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$srSetup = static function (TestContext $ctx): int {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Searchable Example Ltd'")->fetchColumn();
    if ($cid === 0) {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Searchable Example Ltd', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, cve_id, status, first_seen, last_seen, opened_at)
                           VALUES (:c, 'vuln:203.0.113.99:22:CVE-2099-7777', 'vuln', 'fail', 'CVE-2099-7777 in Example <b>SSH</b> (9.8 Critical)', 'Made-up.', '203.0.113.99:22', 'x',
                                   'CVE-2099-7777', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())")->execute(['c' => $cid]);
        $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at)
                           VALUES (:c, 'port:203.0.113.98:3389', 'port', 'fail', 'Remote Desktop 100% open', 'Made-up.', '203.0.113.98:3389', 'x', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())")
            ->execute(['c' => $cid]);
    }
    return $cid;
};

return [
    'search: clients, findings by CVE or target, help; escaped; wildcards literal; viewers allowed' => function (TestContext $ctx) use ($srSetup): void {
        $cid = $srSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('id="sn-search-q"', $admin->get('/')->body, 'the search box is in the top bar');
        $r = $admin->get('/search?q=Searchable')->body;
        Assert::contains('/clients/' . $cid . '"', $r, 'client found');
        $r = $admin->get('/search?q=CVE-2099-7777')->body;
        Assert::contains('CVE-2099-7777 in Example &lt;b&gt;SSH&lt;/b&gt;', $r, 'finding found by CVE, escaped');
        Assert::notContains('<b>SSH</b>', $r);
        Assert::contains('Searchable Example Ltd', $r, 'with its client');
        Assert::contains('/findings/', $admin->get('/search?q=203.0.113.98')->body, 'finding found by target');
        Assert::contains('Help', $admin->get('/search?q=authorisation')->body, 'help topics found');
        // LIKE wildcards are literal: "%" matches only titles that contain a percent sign.
        $pct = $admin->get('/search?q=' . rawurlencode('0% o'))->body;
        Assert::contains('Remote Desktop 100% open', $pct);
        Assert::notContains('CVE-2099-7777', $pct);
        Assert::contains('Nothing found', $admin->get('/search?q=' . rawurlencode('_x_no_such_thing_'))->body);
        Assert::contains('at least 2 characters', $admin->get('/search?q=a')->body);
        $xss = $admin->get('/search?q=' . rawurlencode('<script>alert(1)</script>'))->body;
        Assert::notContains('<script>alert(1)</script>', $xss, 'the query is escaped');
        $ctx->createUser('srviewer', 'viewer', 'Srviewer-Pass-0001!');
        $viewer = $ctx->login('srviewer', 'Srviewer-Pass-0001!');
        Assert::contains('CVE-2099-7777', $viewer->get('/search?q=7777')->body, 'viewers can search');
    },
    'list filters: findings "contains", audit log text filter, instant filter boxes' => function (TestContext $ctx) use ($srSetup): void {
        $cid = $srSetup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $f = $admin->get('/findings?client=' . $cid . '&q=7777')->body;
        Assert::contains('CVE-2099-7777', $f);
        Assert::notContains('Remote Desktop 100% open', $f, 'only matching findings');
        $flat = $admin->get('/findings?view=flat&client=' . $cid . '&q=' . rawurlencode('3389'))->body;
        Assert::contains('Remote Desktop 100% open', $flat);
        Assert::notContains('CVE-2099-7777', $flat);
        $audit = $admin->get('/admin/audit?q=client.created')->body;
        Assert::contains('client.created', $audit);
        Assert::contains('matching entries', $audit);
        Assert::notContains('user.login_failed', $admin->get('/admin/audit?q=client.created')->body);
        foreach (['/clients' => 'clients-filter', '/users' => 'users-filter', '/help' => 'help-filter'] as $url => $id) {
            Assert::contains('id="' . $id . '"', $admin->get($url)->body, 'filter box on ' . $url);
        }
    },
];
