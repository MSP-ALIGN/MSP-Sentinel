<?php

declare(strict_types=1);

/**
 * Unit tests for CPE handling, feed parsing and vulnerability grading.
 * Made-up CVE IDs only (CVE-2099-...).
 */

use Sentinel\Scanning\ExposureRules;
use Sentinel\Vulns\Cpe;
use Sentinel\Vulns\FeedParser;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'CPE parsing turns nmap CPEs into NVD match strings and refuses junk' => function (TestContext $ctx): void {
        Assert::same('cpe:2.3:a:openbsd:openssh:8.9p1', Cpe::matchString(Cpe::parse('cpe:/a:openbsd:openssh:8.9p1')));
        Assert::same(['cpe:2.3:a:openbsd:openssh:8.9p1', 'cpe:2.3:a:openbsd:openssh:8.9:p1'], Cpe::matchStrings(Cpe::parse('cpe:/a:openbsd:openssh:8.9p1')), 'p-release also asked in NVD\'s split form');
        Assert::same('cpe:2.3:a:example:some\\~tool:1.0\\+b', Cpe::matchString(Cpe::parse('cpe:/a:example:some~tool:1.0+b')), 'CPE 2.3 special characters escaped');
        Assert::same('cpe:2.3:a:example:webserver', Cpe::matchString(Cpe::parse('cpe:/a:example:webserver')), 'no version: product-level query');
        Assert::same('', Cpe::parse('cpe:/a:example:webserver:%27or%201=1')['version'], 'garbled version treated as unknown');
        Assert::same(null, Cpe::parse('cpe:/o:linux:linux_kernel'), 'OS without version is too vague');
        Assert::true(Cpe::parse('cpe:/o:linux:linux_kernel:5.15') !== null, 'OS with version accepted');
        foreach (['', 'cpe:2.3:a:x:y:1', 'cpe:/x:vendor:product', 'cpe:/a:Vendor With Space:p', 'cpe:/a::product', 'cpe:/a:v:p&evil=1', 'javascript:alert(1)'] as $bad) {
            Assert::same(null, Cpe::parse($bad), 'refused: ' . $bad);
        }
        Assert::true(Cpe::isCveId('CVE-2099-0001') && Cpe::isCveId('CVE-2024-1234567') && !Cpe::isCveId('CVE-99-1') && !Cpe::isCveId("CVE-2099-0001\n"), 'CVE ID format');
    },
    'NVD pages: CVSS choice, rejected entries, hostile text' => function (TestContext $ctx): void {
        $page = json_decode((string) file_get_contents($ctx->root . '/tests/fixtures/feeds/nvd_openssh.json'), true);
        $r = FeedParser::nvdPage($page, 'cpe:2.3:a:openbsd:openssh:');
        $byId = array_column($r['cves'], null, 'cve_id');
        Assert::same(['CVE-2099-0001', 'CVE-2099-0002', 'CVE-2099-0003'], array_keys($byId), 'rejected, malformed and platform-only entries skipped');
        Assert::true(in_array('CVE-2099-0005', array_column(FeedParser::nvdPage($page)['cves'], 'cve_id'), true), 'without a product filter the platform-only CVE would have matched');
        Assert::same(9.8, $byId['CVE-2099-0001']['cvss_score'], 'primary (NVD) metric preferred');
        Assert::same('CRITICAL', $byId['CVE-2099-0001']['cvss_severity']);
        Assert::same(['HIGH', '4.0'], [$byId['CVE-2099-0002']['cvss_severity'], $byId['CVE-2099-0002']['cvss_version']], 'severity derived when missing; v4 used when no v3.1');
        Assert::notContains("\x07", $byId['CVE-2099-0001']['summary'], 'control characters removed');
        Assert::same('2099-01-15', $byId['CVE-2099-0001']['published']);
        Assert::same(['total' => 0, 'cves' => []], FeedParser::nvdPage(['vulnerabilities' => 'nope']));
    },
    'KEV and EPSS parsing validates every row' => function (TestContext $ctx): void {
        $kev = FeedParser::kev(json_decode((string) file_get_contents($ctx->root . '/tests/fixtures/feeds/kev.json'), true));
        Assert::same(['CVE-2099-0001', 'CVE-2099-0101', 'CVE-2099-0103'], array_column($kev, 'cve_id'));
        Assert::same('Known', $kev[0]['ransomware']);
        $epss = FeedParser::epss(['data' => [['cve' => 'CVE-2099-0001', 'epss' => '1.7', 'percentile' => '0.5'], ['cve' => 'x', 'epss' => '0.1', 'percentile' => '0.1'], ['cve' => 'CVE-2099-0002', 'epss' => 'abc', 'percentile' => '0.1']]]);
        Assert::same(1, count($epss), 'invalid rows skipped');
        Assert::same(1.0, $epss[0]['score'], 'scores clamped to 0..1');
    },
    'vulnerability grading follows the agreed rules' => function (TestContext $ctx): void {
        $g = static fn (string $conf, int $kev, string $sev): string => ExposureRules::vulnSeverity(['confidence' => $conf, 'in_kev' => $kev, 'cvss_severity' => $sev]);
        Assert::same('fail', $g('confirmed', 1, 'MEDIUM'), 'confirmed KEV fails');
        Assert::same('fail', $g('confirmed', 0, 'CRITICAL'), 'confirmed critical fails');
        Assert::same('warn', $g('confirmed', 0, 'HIGH'), 'confirmed high warns');
        Assert::same('warn', $g('possible', 1, 'CRITICAL'), 'possible KEV warns (never fails without a version)');
        Assert::same('info', $g('confirmed', 0, 'MEDIUM'));
        Assert::same('info', $g('possible', 0, 'CRITICAL'));
        Assert::same('warn', $g('distro', 1, 'CRITICAL'), 'distribution build with a KEV: warning, not fail');
        Assert::same('info', $g('distro', 0, 'CRITICAL'));
        Assert::same('fail', ExposureRules::vulnSeverity(['confidence' => 'confirmed', 'in_kev' => 0, 'cvss_score' => 10.0, 'cvss_severity' => 'HIGH']), 'graded from the score: CVSS v2 10.0 counts as critical');
    },
];
