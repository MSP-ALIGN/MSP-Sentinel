<?php

declare(strict_types=1);

/**
 * End-to-end tests for the DNS checks (1.28): zone transfers asked of a domain's own listed nameservers, and
 * subdomain takeover (a CNAME to a cloud name that no longer exists, or the provider's "no such site" page on one
 * request). Everything is answered by the mock DNS server and mock web servers on 127.0.0.1; made-up names only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$setup = static function (TestContext $ctx): int {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'DNS Checks Example'")->fetchColumn();
    if ($cid > 0) {
        return $cid;
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'DNS Checks Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
        'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
        'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '',
        'scope' => "axfr-open.example\naxfr-closed.example\naxfr-private.example\n*.wildzone.example\nshop.takeover.example\nold.takeover.example\nlive.takeover.example\nflaky.takeover.example\nintra.takeover.example\ngone-lb.takeover.example", 'confirm' => '1']);
    $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
    $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
    $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
    return $cid;
};
$finding = static fn (TestContext $ctx, int $cid, string $key): ?array => $ctx->db->query("SELECT id, severity, status, finding_type, title, detail FROM findings WHERE client_id = {$cid} AND finding_key = " . $ctx->db->quote($key))->fetch() ?: null;

return [
    'an open zone transfer is a Fail; a refusing nameserver is fine' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        $open = $finding($ctx, $cid, 'dns:axfr-open.example:ns1.axfr-open.example:zone_transfer');
        Assert::true($open !== null && $open['severity'] === 'fail' && $open['finding_type'] === 'dns', 'open zone transfer found');
        Assert::contains('axfr-open.example', (string) $open['title']);
        $stored = json_decode((string) $ctx->db->query("SELECT result FROM domain_checks WHERE client_id = {$cid} AND kind = 'zone' AND name = 'axfr-open.example'")->fetchColumn(), true);
        $ns = $stored['nameservers'][0] ?? [];
        Assert::same('open', $ns['status'] ?? null);
        Assert::true(in_array('secret-backup.axfr-open.example', $ns['sample'] ?? [], true), 'a sample of the names handed out: ' . implode(', ', $ns['sample'] ?? []));
        Assert::true(in_array('*.axfr-open.example', $ns['sample'] ?? [], true), 'a wildcard record in the zone is read, not a parse error');
        Assert::true(($ns['records'] ?? 0) >= 6, 'records across both messages, SOA to SOA');
        $closed = json_decode((string) $ctx->db->query("SELECT result FROM domain_checks WHERE client_id = {$cid} AND kind = 'zone' AND name = 'axfr-closed.example'")->fetchColumn(), true);
        Assert::same('refused', $closed['nameservers'][0]['status'] ?? null);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'dns:axfr-closed.example:%'")->fetchColumn());
    },
    'takeover: an unclaimed bucket and a dangling name are Fails; a live site is not' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        $shop = $finding($ctx, $cid, 'dns:shop.takeover.example:takeover');
        Assert::true($shop !== null && $shop['severity'] === 'fail', 'unclaimed S3 bucket');
        Assert::contains('Amazon S3', (string) $shop['title']);
        $old = $finding($ctx, $cid, 'dns:old.takeover.example:takeover');
        Assert::true($old !== null && $old['severity'] === 'fail', 'dangling Azure name');
        Assert::same(null, $finding($ctx, $cid, 'dns:live.takeover.example:takeover'), 'a live GitHub Pages site is not flagged');
        // Domains without a CNAME are checked but have nothing to report.
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key = 'dns:axfr-open.example:takeover'")->fetchColumn());
    },
    'only authorized names are checked, and not again within 20 hours' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $names = $ctx->db->query("SELECT DISTINCT name FROM domain_checks WHERE client_id = {$cid} ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
        Assert::true(!in_array('wildzone.example', $names, true), 'only names in scope are checked: ' . implode(', ', $names));
        $names = $ctx->db->query("SELECT name FROM domain_checks WHERE client_id = {$cid} AND kind = 'takeover' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
        // Takeover: flaky (DNS failure) and intra (private address) couldn't be decided: no result stored, nothing reported.
        Assert::same(['axfr-closed.example', 'axfr-open.example', 'axfr-private.example', 'gone-lb.takeover.example', 'live.takeover.example', 'old.takeover.example', 'shop.takeover.example'], $names);
        Assert::same([], json_decode((string) $ctx->db->query("SELECT result FROM domain_checks WHERE client_id = {$cid} AND kind = 'zone' AND name = 'axfr-private.example'")->fetchColumn(), true)['nameservers'] ?? null,
            'a nameserver at a private address is never contacted');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'dns:gone-lb.takeover.example:%'")->fetchColumn(),
            'a deleted load balancer name (nobody else can claim it) is not a takeover');
        $log = (string) @file_get_contents($ctx->dnsLog ?? '');
        Assert::notContains('AXFR takeover.example', $log, 'never a zone transfer for a domain that is not itself authorized');
        Assert::notContains('AXFR wildzone.example', $log, '*.wildzone.example does not authorize wildzone.example itself');
        Assert::notContains('AXFR axfr-private.example', $log);
        $before = substr_count($log, 'AXFR axfr-open.example');
        Assert::true($before >= 1, 'the zone transfer was asked over DNS');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
        Assert::same($before, substr_count((string) @file_get_contents($ctx->dnsLog ?? ''), 'AXFR axfr-open.example'), 'throttled: not asked again');
    },
    'findings page, guidance and filter' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $f = $finding($ctx, $cid, 'dns:shop.takeover.example:takeover');
        Assert::true($f !== null, 'finding exists');
        Assert::contains('shop.takeover.example', $admin->get('/findings/' . (int) $f['id'])->body);
        $id = App::reportService()->generate(App::clients()->find($cid), 'technical', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        $html = (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$id}")->fetchColumn();
        Assert::contains('Delete the DNS record (CNAME)', $html, 'plain-English fix in the report');
        Assert::contains('Allow zone transfers only to your own secondary nameservers', $html);
        $list = $admin->get('/findings?type=dns&client=' . $cid)->body;
        Assert::contains('can be taken over', $list);
        Assert::contains('DNS zone transfer allowed', $list);
        $client = $ctx->clientPages($admin, $cid);
        Assert::contains('hands out the zone', $client);
        Assert::contains('secret-backup.axfr-open.example', $client);
        Assert::contains('ns1.axfr-closed.example (203.0.113.54) refuses', $client);
        Assert::contains('Can be taken over: old.takeover.example', $client);
    },
    'a failed lookup keeps the earlier result; a name leaving scope clears its finding' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        // An earlier run found flaky.takeover.example vulnerable; today its lookups fail (SERVFAIL): the finding stays.
        $ctx->db->exec("INSERT INTO domain_checks (client_id, name, kind, result, checked_at) VALUES ({$cid}, 'flaky.takeover.example', 'takeover',
            '{\"finding\":{\"host\":\"flaky.takeover.example\",\"cname\":\"flaky.herokuapp.com\",\"provider\":\"Heroku\",\"reason\":\"dangling\",\"evidence\":\"x\"}}',
            UTC_TIMESTAMP() - INTERVAL 2 DAY)");
        $ctx->db->exec("DELETE FROM scope_entries WHERE client_id = {$cid} AND value = 'shop.takeover.example'");
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
        $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
        $flaky = $finding($ctx, $cid, 'dns:flaky.takeover.example:takeover');
        Assert::true($flaky !== null && $flaky['status'] === 'open', 'kept open: the check could not decide');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM domain_checks WHERE client_id = {$cid} AND name = 'shop.takeover.example'")->fetchColumn(), 'out of scope: result removed');
        $shop = $finding($ctx, $cid, 'dns:shop.takeover.example:takeover');
        Assert::true($shop === null || $shop['status'] !== 'open', 'out of scope: finding no longer open');
    },
];
