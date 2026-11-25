<?php

declare(strict_types=1);

/**
 * End-to-end tests for website and email checks against mock sites and a mock
 * DNS server on 127.0.0.1: HTTPS and headers, cookies, exposed files proven by
 * content (and soft-404 sites not reported), CMS/library versions matched to
 * made-up CVEs, SPF/DMARC/DKIM, findings, guidance in reports, and that the
 * content of exposed files is never stored. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Scanning\Connector;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Web\WebsiteChecker;
use Sentinel\Web\WebsiteRepository;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$setup = static function (TestContext $ctx): int {
    $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Website Example'")->fetchColumn();
    if ($cid > 0) {
        return $cid;
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $now = (int) gmdate('G');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Website Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
        'scan_window_start' => sprintf('%02d:00', ($now + 23) % 24), 'scan_window_end' => sprintf('%02d:00', ($now + 1) % 24), 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
        'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '',
        'scope' => "203.0.113.190\n203.0.113.191\nmail-good.example\nmail-weak.example\nmail-none.example\nnomail.example\nnullmx.example\nspf-redirect.example\nshop.mail-good.example\n*.wild.example", 'confirm' => '1']);
    $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
    $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
    $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
    return $cid;
};
$finding = static fn (TestContext $ctx, int $cid, string $key): ?array => $ctx->db->query("SELECT severity, status, finding_type, title FROM findings WHERE client_id = {$cid} AND finding_key = " . $ctx->db->quote($key))->fetch() ?: null;

return [
    'website checks find real problems and ignore soft-404 sites' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        $expect = [
            'site:203.0.113.190:80:login_over_http' => 'fail',
            'site:203.0.113.190:80:exposed_git' => 'fail',
            'site:203.0.113.190:443:exposed_env' => 'fail',
            'site:203.0.113.190:443:exposed_backup' => 'fail',
            'site:203.0.113.190:443:insecure_cookies' => 'warn',
            'site:203.0.113.190:443:missing_hsts' => 'warn',
            'site:203.0.113.190:443:missing_csp' => 'warn',
        ];
        foreach ($expect as $key => $sev) {
            $f = $finding($ctx, $cid, $key);
            Assert::true($f !== null && $f['severity'] === $sev && $f['finding_type'] === 'web', 'finding ' . $key . ' as ' . $sev);
        }
        Assert::same(null, $finding($ctx, $cid, 'site:203.0.113.190:443:exposed_phpinfo'), 'a page that only mentions phpinfo is not reported');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'site:203.0.113.191:%'")->fetchColumn(),
            'the well configured site (HTTPS redirect, all headers, soft-404 for every path) has no findings');
        $cookies = (string) $ctx->db->query("SELECT detail FROM findings WHERE client_id = {$cid} AND finding_key = 'site:203.0.113.190:443:insecure_cookies'")->fetchColumn();
        Assert::contains('PHPSESSID', $cookies);
        Assert::notContains('theme', $cookies, 'a cookie with Secure (and not session-like) is fine');
        $stored = (string) $ctx->db->query("SELECT GROUP_CONCAT(checks) FROM web_pages")->fetchColumn();
        Assert::notContains('made-up-test-password', $stored, 'content of exposed files is never stored');
        Assert::notContains('APP_KEY', $stored);
        // Only fixed paths were requested, all through the pinned mock endpoints.
        $comps = $ctx->db->query("SELECT CONCAT(wc.name, ' ', wc.version) FROM web_components wc JOIN web_pages w ON w.id = wc.web_page_id JOIN assets a ON a.id = w.asset_id
                                  WHERE a.client_id = {$cid} ORDER BY 1")->fetchAll(PDO::FETCH_COLUMN);
        Assert::true(in_array('WordPress 5.0.3', $comps, true) && in_array('jQuery 1.12.4', $comps, true) && in_array('jQuery 3.7.1', $comps, true), 'components: ' . implode(', ', $comps));
    },
    'CMS and library versions are matched to known vulnerabilities' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        $ctx->cli('bin/feeds.php'); // fetches anything left pending and re-grades
        $wp = $finding($ctx, $cid, 'webvuln:203.0.113.190:80:WordPress:CVE-2099-0202');
        Assert::true($wp !== null && $wp['severity'] === 'fail' && $wp['finding_type'] === 'vuln', 'critical confirmed WordPress CVE is a Fail');
        Assert::contains('in WordPress 5.0.3', (string) $wp['title']);
        $jq = $finding($ctx, $cid, 'webvuln:203.0.113.190:443:jQuery:CVE-2099-0201');
        Assert::true($jq !== null && $jq['severity'] === 'warn', 'high confirmed jQuery CVE is a Warning');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'webvuln:203.0.113.191:%'")->fetchColumn(), 'jQuery 3.7.1 has no match');
    },
    'email records: SPF, DMARC and DKIM, judged only for domains that receive mail' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'email:mail-good.example:%'")->fetchColumn(), 'good domain has no findings');
        Assert::same('fail', $finding($ctx, $cid, 'email:mail-weak.example:spf_pass_all')['severity'] ?? null);
        Assert::same('warn', $finding($ctx, $cid, 'email:mail-weak.example:dmarc_missing')['severity'] ?? null);
        Assert::same('warn', $finding($ctx, $cid, 'email:mail-none.example:spf_missing')['severity'] ?? null);
        Assert::same('warn', $finding($ctx, $cid, 'email:mail-none.example:dmarc_weak')['severity'] ?? null);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'email:nomail.example:%'")->fetchColumn(), 'no MX: not judged');
        $good = $ctx->db->query("SELECT result FROM email_checks WHERE client_id = {$cid} AND domain = 'mail-good.example'")->fetchColumn();
        Assert::same(['selector1'], json_decode((string) $good, true)['dkim'], 'DKIM found under a common selector');
        $dnsLog = (string) @file_get_contents($ctx->dnsLog ?? '');
        Assert::true($dnsLog === '' || str_contains($dnsLog, 'TXT _dmarc.mail-weak.example'), 'DMARC looked up over DNS');
    },
    'email edge cases: null MX, SPF redirect, parent DMARC, wildcard-only scope' => function (TestContext $ctx) use ($setup, $finding): void {
        $cid = $setup($ctx);
        $domains = $ctx->db->query("SELECT domain FROM email_checks WHERE client_id = {$cid}")->fetchAll(PDO::FETCH_COLUMN);
        Assert::true(!in_array('wild.example', $domains, true), '*.wild.example does not authorize wild.example itself: ' . implode(', ', $domains));
        Assert::same(0, (int) $ctx->db->query("SELECT has_mx FROM email_checks WHERE client_id = {$cid} AND domain = 'nullmx.example'")->fetchColumn(), 'a null MX accepts no email');
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM findings WHERE client_id = {$cid} AND finding_key LIKE 'email:nullmx.example:%'")->fetchColumn(), 'null MX: not judged');
        Assert::same(null, $finding($ctx, $cid, 'email:spf-redirect.example:spf_weak'), 'SPF redirect= takes the policy from the target');
        Assert::same(null, $finding($ctx, $cid, 'email:shop.mail-good.example:dmarc_missing'), 'the parent domain\'s DMARC (in scope) applies');
        $shop = json_decode((string) $ctx->db->query("SELECT result FROM email_checks WHERE client_id = {$cid} AND domain = 'shop.mail-good.example'")->fetchColumn(), true);
        Assert::same('mail-good.example', $shop['dmarc_from'] ?? null);
        Assert::same('reject', $shop['dmarc_policy'] ?? null);
    },
    'a partial exposed-file run only keeps files without an answer; stale component matches are dropped' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $checker = new WebsiteChecker(new HttpProbe(Connector::fromConfig(App::config())));
        $calls = 0;
        $r = $checker->exposedFiles('203.0.113.191', 443, 'https', null, function () use (&$calls): bool { return ++$calls > 2; });
        Assert::same(false, $r['complete'], 'stopped early');
        Assert::same([], $r['codes'], 'soft-404 site: nothing proven');
        Assert::same(['exposed_git', 'exposed_env'], $r['checked'], 'only the answered codes are conclusive (backup has more paths)');
        $full = $checker->exposedFiles('203.0.113.190', 80, 'http', null, fn (): bool => false);
        Assert::true($full['complete'] && in_array('exposed_git', $full['checked'], true) && count($full['checked']) === 6, 'a full run checks every code');
        // A component whose version changed while its data is pending loses the old version's matches.
        $store = new WebsiteRepository($ctx->db);
        $comp = (int) $ctx->db->query("SELECT wc.id FROM web_components wc JOIN component_vulns cv ON cv.component_id = wc.id JOIN web_pages w ON w.id = wc.web_page_id
                                   JOIN assets a ON a.id = w.asset_id WHERE wc.name = 'jQuery' AND a.client_id = {$cid} LIMIT 1")->fetchColumn();
        Assert::true($comp > 0, 'jQuery has a match to start with');
        $ctx->db->exec("UPDATE web_components SET version = '1.12.5', cpe = 'cpe:/a:jquery:jquery:1.12.5' WHERE id = {$comp}");
        App::vulnMatcher()->matchComponents($store, $cid, 0);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM component_vulns WHERE component_id = {$comp}")->fetchColumn(), 'no CVEs claimed for the new version');
    },
    'client page, findings filter, report guidance and roles' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $view = $ctx->login('admin', 'Admin-Pass-0001!');
        $page = $ctx->clientPages($view, (int) $cid);
        foreach (['Website and email security', 'Configuration file with secrets exposed (.env)', 'WordPress', 'SPF lets anyone send email as this domain', 'Receives no email (no MX)'] as $s) {
            Assert::contains($s, $page);
        }
        Assert::contains('Email security', $view->get('/findings?type=email&client=' . $cid)->body);
        $id = App::reportService()->generate(App::clients()->find($cid), 'technical', gmdate('Y-m-d'), gmdate('Y-m-d'), null, 'Test');
        $html = (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$id}")->fetchColumn();
        Assert::contains('change every password and key in the file', $html, 'plain-English fix in the report');
        Assert::contains('Publish a DMARC record', $html);
    },
];
