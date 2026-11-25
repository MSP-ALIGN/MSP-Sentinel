<?php

declare(strict_types=1);

/**
 * Unit tests for report helpers: guidance texts, CSV formula neutralising,
 * host extraction, the SVG chart, periods and email attachments.
 */

use Sentinel\Alerts\SmtpMailer;
use Sentinel\Controllers\ReportController;
use Sentinel\Reports\CsvExport;
use Sentinel\Reports\Guidance;
use Sentinel\Reports\ReportBuilder;
use Sentinel\Reports\ReportRenderer;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'guidance explains each kind of finding in plain English' => function (TestContext $ctx): void {
        $g = Guidance::for(['finding_key' => 'port:203.0.113.5:3389', 'finding_type' => 'port']);
        Assert::contains('ransomware', $g['meaning']);
        Assert::contains('VPN', $g['fix']);
        Assert::contains('database', Guidance::for(['finding_key' => 'port:203.0.113.5:3306', 'finding_type' => 'port'])['meaning']);
        Assert::contains('Renew', Guidance::for(['finding_key' => 'tls:203.0.113.5:443::cert_expired', 'finding_type' => 'tls'])['fix']);
        Assert::contains('multi-factor', Guidance::for(['finding_key' => 'web:203.0.113.5:443:vpn_portal', 'finding_type' => 'web'])['fix']);
        $kev = Guidance::for(['finding_key' => 'vuln:203.0.113.5:22:CVE-2099-0001', 'finding_type' => 'vuln'], ['in_kev' => 1, 'kev_action' => 'Apply updates per vendor instructions.']);
        Assert::contains('known-exploited', $kev['meaning']);
        Assert::contains('Apply updates per vendor instructions.', $kev['fix']);
    },
    'CSV cells that look like formulas are neutralised' => function (TestContext $ctx): void {
        foreach (['=HYPERLINK("http://evil.example")', '+1+1', '-2', '@SUM(A1)', "\tx"] as $bad) {
            Assert::same("'" . $bad, CsvExport::cell($bad));
        }
        Assert::same("'\n=1", CsvExport::cell("\n=1"));
        Assert::same("'＝SUM(A1)", CsvExport::cell('＝SUM(A1)'), 'fullwidth equals sign');
        Assert::same("'=x\xff", CsvExport::cell("=x\xff"), 'invalid UTF-8 still neutralised');
        Assert::same('Remote Desktop', CsvExport::cell('Remote Desktop'));
        Assert::same('', CsvExport::cell(null));
    },
    'host extraction for grouping by asset' => function (TestContext $ctx): void {
        Assert::same('203.0.113.5', ReportBuilder::assetOf('203.0.113.5:443 (www.example.com)'));
        Assert::same('203.0.113.5', ReportBuilder::assetOf('https://203.0.113.5:8443'));
        Assert::same('2001:db8::5', ReportBuilder::assetOf('2001:db8::5:443'));
        Assert::same('2001:db8::5', ReportBuilder::assetOf('https://[2001:db8::5]:443'));
    },
    'trend chart is escaped and readable without color' => function (TestContext $ctx): void {
        $svg = ReportRenderer::trendChart([['label' => '<b>Jan</b>', 'fail' => 3, 'warn' => 5], ['label' => 'Now', 'fail' => 1, 'warn' => 2]]);
        Assert::contains('&lt;b&gt;Jan&lt;/b&gt;', $svg);
        Assert::contains('stroke-dasharray', $svg, 'warnings dashed');
        Assert::contains('<rect', $svg, 'different marker shapes');
        Assert::contains('>5</text>', $svg, 'values labeled');
        Assert::contains('role="img"', $svg);
        Assert::contains('<circle', ReportRenderer::trendChart([['label' => 'Now', 'fail' => 0, 'warn' => 0]]), 'single point works');
    },
    'only a locked-down document CSP may replace the app policy' => function (TestContext $ctx): void {
        $strict = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
        Assert::same($strict, \Sentinel\Core\SecurityHeaders::apply((new \Sentinel\Core\Response('x'))->header('Content-Security-Policy', $strict), false)->getHeader('Content-Security-Policy'));
        foreach (["default-src *", "default-src 'none'; script-src 'unsafe-inline'; sandbox", "default-src 'none'"] as $weak) {
            $csp = (string) \Sentinel\Core\SecurityHeaders::apply((new \Sentinel\Core\Response('x'))->header('Content-Security-Policy', $weak), false)->getHeader('Content-Security-Policy');
            Assert::contains("script-src 'self'", $csp, 'replaced: ' . $weak);
        }
    },
    'report periods' => function (TestContext $ctx): void {
        $now = new DateTimeImmutable('2026-03-15 10:00:00', new DateTimeZone('UTC'));
        Assert::same(['2026-02-01', '2026-02-28'], ReportController::period('month', $now));
        Assert::same(['2026-02-14', '2026-03-15'], ReportController::period('30', $now));
        Assert::same(['2025-12-16', '2026-03-15'], ReportController::period('90', $now));
    },
    'email attachments are base64 parts with sanitized names' => function (TestContext $ctx): void {
        $msg = SmtpMailer::buildMessage('s@msp.example', ['a@msp.example'], 'Reports', 'See attached.',
            [['name' => "../evil\"\r\nX-Injected: 1.html", 'type' => 'text/html', 'content' => "<p>Report</p>\r\n.\r\n"], ['name' => 'r.csv', 'type' => 'bad type', 'content' => 'a,b']]);
        Assert::contains('multipart/mixed; boundary="=_sentinel_', $msg);
        Assert::notContains("\r\nX-Injected", $msg, 'no header injection through the file name');
        Assert::contains('filename="..-evil-X-Injected-1.html"', $msg);
        Assert::contains('Content-Type: application/octet-stream; name="r.csv"', $msg, 'invalid type replaced');
        Assert::notContains("\r\n.\r\n", $msg, 'content is encoded, so it cannot end the SMTP DATA early');
        Assert::contains(base64_encode('a,b'), $msg);
    },
];
