<?php

declare(strict_types=1);

/**
 * End-to-end tests: threat feeds (mock NVD, KEV and EPSS on 127.0.0.1), matching of
 * scanned services to CVEs, the client panel, the dashboard and the feed status.
 * Runs after the scanning tests, which created services for 203.0.113.160 (OpenSSH 8.9p1)
 * and 203.0.113.161 (a web server without a version). Made-up CVE IDs only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;
use Sentinel\Vulns\FeedHttp;
use Sentinel\Vulns\FeedUpdater;

return [
    'the feeds job loads KEV, fetches NVD answers, matches services and scores them' => function (TestContext $ctx): void {
        @unlink($ctx->feedsLog);
        [$code, $out] = $ctx->cli('bin/feeds.php');
        Assert::same(0, $code, $out);
        Assert::contains('KEV: 3 entries', $out);
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Scan Example Ltd'")->fetchColumn();
        $rows = $ctx->db->query("SELECT a.ip, s.port, sv.cve_id, sv.confidence FROM service_vulns sv JOIN services s ON s.id = sv.service_id
                                 JOIN assets a ON a.id = s.asset_id WHERE a.client_id = {$id} ORDER BY sv.cve_id")->fetchAll();
        $found = array_map(static fn (array $r): string => "{$r['ip']}:{$r['port']} {$r['cve_id']} {$r['confidence']}", $rows);
        Assert::same([
            '203.0.113.160:22 CVE-2099-0001 confirmed',
            '203.0.113.160:22 CVE-2099-0002 confirmed',
            '203.0.113.160:22 CVE-2099-0003 confirmed',
            '203.0.113.160:22 CVE-2099-0006 confirmed',
            '203.0.113.161:80 CVE-2099-0101 possible',
        ], $found, 'versioned: NVD\'s CVEs from both version forms; no version: only the known-exploited one; rejected and platform-only CVEs ignored');
        Assert::same('0.97123', (string) $ctx->db->query("SELECT score FROM epss_scores WHERE cve_id = 'CVE-2099-0001'")->fetchColumn(), 'EPSS stored');

        // The API key travels as a header, never in the URL.
        $log = array_map(static fn (string $l): array => json_decode($l, true), file($ctx->feedsLog, FILE_IGNORE_NEW_LINES));
        foreach ($log as $req) {
            if ($req['path'] === '/rest/json/cves/2.0') {
                Assert::true($req['apikey_header'], 'NVD request carries the apiKey header');
                Assert::true(!isset($req['query']['apiKey']) && !isset($req['query']['apikey']), 'no key in the URL');
            }
        }
    },
    'the client page shows what matters first; lower severities are tucked away' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Scan Example Ltd'")->fetchColumn();
        $page = $admin->get('/clients/' . $id)->body;
        foreach (['CVE-2099-0001', 'Known exploited', 'Used by ransomware', 'Confirmed: reported version is affected', 'Product found, version unknown',
                  'CVE-2099-0101', '+2 lower-severity vulnerabilities', 'Coverage:', 'EPSS 97.1%', 'https://nvd.nist.gov/vuln/detail/CVE-2099-0001'] as $text) {
            Assert::contains($text, $page);
        }
        Assert::notContains('<script>alert(1)</script>', $page, 'feed text escaped');
        Assert::notContains('CVE-2099-0004', $page, 'rejected CVE never shown');
        Assert::true(strpos($page, 'CVE-2099-0001') < strpos($page, 'CVE-2099-0002'), 'known exploited listed first');
        $dash = $admin->get('/')->body;
        Assert::contains('Known exploited vulnerabilities (confirmed)', $dash);
        Assert::true((bool) preg_match('/\+\d+ possible \(version unknown\)/', $dash), 'possible KEV matches counted separately');
        $settings = $admin->get('/admin/settings')->body;
        Assert::contains('3 known exploited vulnerabilities.', $settings);
        Assert::contains('An NVD API key is configured', $settings);
        Assert::notContains((string) (require $ctx->configPath)['nvd']['api_key'], $settings, 'the key itself is never shown');
    },
    'large NVD answers are paginated; a broken KEV feed keeps the previous copy' => function (TestContext $ctx): void {
        $repo = App::vulns();
        $updater = new FeedUpdater($repo, new FeedHttp(10), $ctx->feedsUrl, null, $ctx->feedsUrl . '/kev-broken.json', $ctx->feedsUrl, 0.0);
        $repo->ensureQuery('cpe:2.3:a:example:bigproduct:1.0');
        Assert::true($updater->fetchQuery('cpe:2.3:a:example:bigproduct:1.0'), 'fetched');
        Assert::same(2500, count($repo->cvesForQuery('cpe:2.3:a:example:bigproduct:1.0')), 'all pages stored');

        // Rate limiting: NVD says 429 -> we stop and remember until when; no further requests are sent meanwhile.
        $repo->ensureQuery('cpe:2.3:a:example:ratelimited:1.0');
        try {
            $updater->fetchQuery('cpe:2.3:a:example:ratelimited:1.0');
            Assert::true(false, 'should report the rate limit');
        } catch (\Sentinel\Vulns\RateLimited $ex) {
            Assert::same(120, $ex->retryAfterSeconds, 'Retry-After honoured');
        }
        Assert::true($repo->nvdBlockedUntil() > time() + 100, 'back-off stored for all processes');
        $before = count(file($ctx->feedsLog));
        Assert::same(['ok' => 0, 'failed' => 0, 'blocked' => true], $updater->refreshNvd(50), 'the next run sends nothing');
        Assert::same($before, count(file($ctx->feedsLog)), 'no request while blocked');
        $ctx->db->exec("UPDATE feed_status SET blocked_until = NULL WHERE name = 'nvd'");
        $ctx->db->exec("UPDATE cpe_queries SET fail_count = 5 WHERE query = 'cpe:2.3:a:example:ratelimited:1.0'");
        Assert::true(!in_array('cpe:2.3:a:example:ratelimited:1.0', $repo->dueQueries(500), true), 'a query that keeps failing stops using the budget');
        $before = (int) $ctx->db->query('SELECT COUNT(*) FROM kev_catalog')->fetchColumn();
        try {
            $updater->refreshKev();
            Assert::true(false, 'should fail');
        } catch (RuntimeException $ex) {
            Assert::contains('HTTP 503', $ex->getMessage());
        }
        Assert::same($before, (int) $ctx->db->query('SELECT COUNT(*) FROM kev_catalog')->fetchColumn(), 'previous KEV copy kept');
        Assert::contains('HTTP 503', (string) $ctx->db->query("SELECT message FROM feed_status WHERE name = 'kev'")->fetchColumn(), 'failure recorded');
        Assert::true($ctx->db->query("SELECT last_success FROM feed_status WHERE name = 'kev'")->fetchColumn() !== null, 'last success time kept');
    },
    'distribution builds are never "confirmed"; a version change drops the old matches' => function (TestContext $ctx): void {
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Scan Example Ltd'")->fetchColumn();
        $svc = (int) $ctx->db->query("SELECT s.id FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id = {$id} AND a.ip = '203.0.113.160' AND s.port = 22")->fetchColumn();
        $ctx->db->exec("UPDATE services SET extra_info = 'Ubuntu Linux; protocol 2.0' WHERE id = {$svc}");
        App::vulnMatcher()->matchClient($id, 0);
        Assert::same(['distro'], $ctx->db->query("SELECT DISTINCT confidence FROM service_vulns WHERE service_id = {$svc}")->fetchAll(PDO::FETCH_COLUMN), 'backports possible: not confirmed');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('the fix may be backported', $admin->get('/clients/' . $id)->body);
        $ctx->db->exec("UPDATE services SET extra_info = '' WHERE id = {$svc}");

        // Upgrade to a version NVD hasn't been asked about yet (no fetch budget): old matches go.
        $ctx->db->exec("UPDATE services SET cpe = 'cpe:/a:openbsd:openssh:9.6p1' WHERE id = {$svc}");
        App::vulnMatcher()->matchClient($id, 0);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM service_vulns WHERE service_id = {$svc}")->fetchColumn(), 'no stale "confirmed" from the old version');
        $ctx->db->exec("UPDATE services SET cpe = 'cpe:/a:openbsd:openssh:8.9p1' WHERE id = {$svc}");
        App::vulnMatcher()->matchClient($id, 0);
    },
    'a later scan without the product removes its matches' => function (TestContext $ctx): void {
        $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Scan Example Ltd'")->fetchColumn();
        $svc = (int) $ctx->db->query("SELECT s.id FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id = {$id} AND a.ip = '203.0.113.160' AND s.port = 22")->fetchColumn();
        $ctx->db->exec("UPDATE services SET cpe = '' WHERE id = {$svc}");
        App::vulnMatcher()->matchClient($id, 0);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM service_vulns WHERE service_id = {$svc}")->fetchColumn(), 'matches follow the current product');
        $ctx->db->exec("UPDATE services SET cpe = 'cpe:/a:openbsd:openssh:8.9p1' WHERE id = {$svc}");
        App::vulnMatcher()->matchClient($id, 0);
        Assert::same(4, (int) $ctx->db->query("SELECT COUNT(*) FROM service_vulns WHERE service_id = {$svc}")->fetchColumn());
    },
];
