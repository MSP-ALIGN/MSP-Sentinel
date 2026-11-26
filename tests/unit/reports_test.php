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
    'CSS strings in the page margins (1.59): escaped, and the space after punctuation survives' => function (TestContext $ctx): void {
        // CSS eats one whitespace after an escape, so each escape carries its own space: ": b" must stay ": b".
        Assert::same('"a\\00003A  b"', \Sentinel\Reports\ReportTheme::cssString('a: b'));
        Assert::same('"x\\000022 \\00003C \\00002F style\\00003E \\00005C "', \Sentinel\Reports\ReportTheme::cssString('x"</style>\\'));
        Assert::same('"line one line two"', \Sentinel\Reports\ReportTheme::cssString("line one\nline two"), 'control characters become spaces');
    },
    'branded report email (1.59): text + HTML alternative, inline logo, escaped, then attachments' => function (TestContext $ctx): void {
        $png = "\x89PNG\r\n\x1a\n" . 'made-up-image-bytes';
        $msg = SmtpMailer::buildMessage('s@msp.example', ['a@msp.example'], 'Reports', 'Plain text.',
            [['name' => 'r.html', 'type' => 'text/html', 'content' => '<p>R</p>']],
            ['html' => '<p>Hello</p>', 'inline' => [['cid' => "logo@x\r\nBcc: evil@evil.example", 'type' => 'image/svg+xml', 'content' => $png]]]);
        // Structure: mixed( alternative( text, related( html, logo ) ), attachment ), in that order.
        $order = array_map(static fn (string $t): int => (int) strpos($msg, $t), ['multipart/mixed', 'multipart/alternative', 'text/plain', 'multipart/related', 'Content-Type: text/html', 'Content-ID:', 'filename="r.html"']);
        $sorted = $order;
        sort($sorted);
        Assert::true($order === $sorted && !in_array(0, $order, true), 'MIME parts nested in the right order: ' . json_encode($order));
        Assert::contains('Content-ID: <logo@xBccevil@evil.example>', $msg, 'the cid keeps only safe characters (no line break)');
        Assert::notContains("\r\nBcc:", $msg);
        Assert::contains('Content-Type: application/octet-stream', $msg, 'only PNG or JPEG inline images');
        Assert::contains(base64_encode('<p>Hello</p>'), $msg);
        // Without attachments the top level is the alternative.
        Assert::contains('Content-Type: multipart/alternative', SmtpMailer::buildMessage('s@msp.example', ['a@msp.example'], 'R', 'T', [], ['html' => '<p>H</p>', 'inline' => []]));

        // The HTML itself: branding from settings, every value escaped, colors only when valid.
        $settings = new \Sentinel\Core\Settings($ctx->db);
        $old = [];
        foreach (['brand_logo_has_name' => '0', 'brand_name' => 'Example <MSP>', 'brand_color' => 'red;x', 'brand_accent' => '#123abc', 'brand_address' => "1 Example Road\nTown", 'brand_email' => 'hi@msp.example'] as $k => $v) {
            $old[$k] = $settings->get($k);
            $settings->set($k, $v);
        }
        try {
            $mail = \Sentinel\Reports\ReportEmail::build($settings, $png, 'Reports for <Client>', "Line one\n\n- Executive summary\n- Technical findings\n\n-- \nSent by Sentinel.");
            Assert::contains('Example &lt;MSP&gt;', $mail['html']);
            Assert::contains('Reports for &lt;Client&gt;', $mail['html']);
            Assert::contains('<li style="margin:2px 0">Executive summary</li>', $mail['html']);
            Assert::contains('1 Example Road<br>Town', $mail['html']);
            Assert::contains('background:#1f4e79', $mail['html'], 'an invalid brand color falls back to the default');
            Assert::contains('#123abc', $mail['html']);
            Assert::notContains('red;x', $mail['html']);
            Assert::contains('cid:' . \Sentinel\Reports\ReportEmail::LOGO_CID, $mail['html']);
            Assert::same(1, count($mail['inline']));
            Assert::same([], \Sentinel\Reports\ReportEmail::build($settings, 'not a png', 'S', 'B')['inline'], 'no logo unless it is a PNG');
            Assert::contains('font-size:16px;font-weight:600', $mail['html'], 'the name sits beside the logo by default');
            $settings->set('brand_logo_has_name', '1');
            Assert::notContains('font-size:16px;font-weight:600', \Sentinel\Reports\ReportEmail::build($settings, $png, 'S', 'B')['html'], 'a logo with the name stands alone');
            Assert::contains('font-size:16px;font-weight:600', \Sentinel\Reports\ReportEmail::build($settings, '', 'S', 'B')['html'], 'without a logo the name is always shown');
        } finally {
            foreach ($old as $k => $v) {
                $settings->set($k, $v);
            }
        }
    },
];
