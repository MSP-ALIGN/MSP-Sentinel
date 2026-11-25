<?php

declare(strict_types=1);

/**
 * Unit tests for port lists, scan windows, nmap arguments and the nmap XML parser.
 */

use Sentinel\Scanning\NmapRunner;
use Sentinel\Scanning\NmapXmlParser;
use Sentinel\Scanning\PortProfile;
use Sentinel\Scanning\ScanWindow;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'port lists parse, normalize and refuse junk' => function (TestContext $ctx): void {
        Assert::same([22, 8090, 9000, 9001, 9002], PortProfile::parseList('8090, 9000-9002 22 22'));
        Assert::same([], PortProfile::parseList('  '));
        foreach (['0', '65536', '80-70', 'abc', '80;rm -rf /', '1-2000', '-p 80', '80,,,,x'] as $bad) {
            Assert::true(is_string(PortProfile::parseList($bad)), "refused: {$bad}");
        }
        Assert::same('21-23,25,80,443', PortProfile::toNmapArg([21, 22, 23, 25, 80, 443]));
        $ports = PortProfile::forClient(['ports_extra' => '8090', 'ports_excluded' => '23,3389']);
        Assert::true(in_array(8090, $ports, true) && !in_array(23, $ports, true) && !in_array(3389, $ports, true) && in_array(445, $ports, true), 'extras added, exclusions removed');
    },
    'scan window handles normal and overnight windows, fails closed' => function (TestContext $ctx): void {
        $at = static fn (string $hm): DateTimeImmutable => new DateTimeImmutable('2026-11-21 ' . $hm . ':00', new DateTimeZone('UTC'));
        $day = ['timezone' => 'UTC', 'scan_window_start' => '09:00:00', 'scan_window_end' => '17:00:00'];
        Assert::true(ScanWindow::isOpen($day, $at('09:00')), 'start inclusive');
        Assert::true(!ScanWindow::isOpen($day, $at('17:00')), 'end exclusive');
        $night = ['timezone' => 'UTC', 'scan_window_start' => '22:00:00', 'scan_window_end' => '06:00:00'];
        Assert::true(ScanWindow::isOpen($night, $at('23:30')) && ScanWindow::isOpen($night, $at('05:59')), 'overnight');
        Assert::true(!ScanWindow::isOpen($night, $at('12:00')), 'midday outside');
        $london = ['timezone' => 'Asia/Tokyo', 'scan_window_start' => '22:00:00', 'scan_window_end' => '06:00:00'];
        Assert::true(ScanWindow::isOpen($london, $at('14:00')), '14:00 UTC is 23:00 in Tokyo');
        Assert::true(!ScanWindow::isOpen(['timezone' => 'Bad/Zone'] + $night, $at('23:30')), 'bad timezone fails closed');
    },
    'nmap arguments are fixed and gentle; bad targets refused' => function (TestContext $ctx): void {
        $r = new NmapRunner('/usr/bin/nmap');
        $args = $r->arguments('203.0.113.5', [22, 80, 443]);
        Assert::same(['/usr/bin/nmap', '-sT', '--unprivileged', '-Pn', '-n', '-T2', '--max-rate', '50', '--max-retries', '2', '--host-timeout', '20m',
                      '-sV', '--version-light', '--noninteractive', '-p', '22,80,443', '-oX', '-', '203.0.113.5'], $args);
        Assert::same('-6', $r->arguments('2001:db8::5', [22])[19], 'IPv6 flag');
        foreach (['-iL /etc/passwd', '203.0.113.5 --script x', 'example.com', '2001:DB8::5', '203.0.113.0/24', ''] as $bad) {
            try {
                $r->arguments($bad, [22]);
                Assert::true(false, "should refuse {$bad}");
            } catch (InvalidArgumentException) {
            }
        }
    },
    'nmap is always terminated, even when the stop check throws' => function (TestContext $ctx): void {
        $cfg = require $ctx->configPath;
        $runner = new NmapRunner($cfg['scanner']['nmap_path'], 60);
        $start = microtime(true);
        $r = $runner->scan('203.0.113.170', [22], static function (): bool {
            throw new RuntimeException('database went away');
        });
        Assert::true($r['stopped'], 'treated as stop');
        Assert::true(microtime(true) - $start < 5, 'the 30-second fake host was stopped quickly');
        exec('pgrep -f "[f]ake_nmap[.]php.*203[.]0[.]113[.]170"', $pids);
        Assert::same([], $pids, 'no nmap process left behind');
    },
    'nmap XML parser: real output, other hosts ignored, hostile values cleaned' => function (TestContext $ctx): void {
        $xml = '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><address addr="203.0.113.5" addrtype="ipv4"/><ports>'
            . '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service></port>'
            . '<port protocol="tcp" portid="23"><state state="closed"/></port>'
            . '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Bad&#10;Line&#9;" extrainfo="' . str_repeat('x', 500) . '"><cpe>javascript:alert(1)</cpe></service></port>'
            . '</ports></host><host><address addr="198.51.100.1"/><ports><port protocol="tcp" portid="1"><state state="open"/></port></ports></host>'
            . '<runstats><finished exit="success"/></runstats></nmaprun>';
        $r = NmapXmlParser::parse($xml, '203.0.113.5');
        Assert::true($r['complete'], 'complete');
        Assert::same([22, 80], array_column($r['open'], 'port'));
        Assert::same('cpe:/a:openbsd:openssh:8.9p1', $r['open'][0]['cpe']);
        Assert::same('Bad Line', $r['open'][1]['product'], 'control characters removed');
        Assert::same(200, mb_strlen($r['open'][1]['extra']), 'length capped');
        Assert::same('', $r['open'][1]['cpe'], 'non-CPE values dropped');
        $xxe = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun><host><address addr="203.0.113.5"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="&e;"/></port></ports></host></nmaprun>';
        try {
            $r = NmapXmlParser::parse($xxe, '203.0.113.5');
            Assert::notContains('root:', $r['open'][0]['service'] ?? '', 'external entities are not loaded');
        } catch (RuntimeException) {
            // Refusing the document outright is the expected, safest outcome.
        }
        Assert::true(!NmapXmlParser::parse(str_replace('<runstats><finished exit="success"/></runstats>', '', $xml), '203.0.113.5')['complete'], 'missing runstats = incomplete');
        $timedOut = '<?xml version="1.0"?><nmaprun><host timedout="true"><address addr="203.0.113.5"/></host><runstats><finished exit="success"/></runstats></nmaprun>';
        Assert::true(!NmapXmlParser::parse($timedOut, '203.0.113.5')['complete'], 'a host that hit nmap\'s host timeout is NOT complete');
        $noHost = '<?xml version="1.0"?><nmaprun><runstats><finished exit="success"/></runstats></nmaprun>';
        Assert::true(!NmapXmlParser::parse($noHost, '203.0.113.5')['complete'], 'a missing host is NOT complete');
        foreach (['', '<html/>', '<nmaprun><host>'] as $bad) {
            try {
                NmapXmlParser::parse($bad, '203.0.113.5');
                Assert::true(false, 'should fail: ' . $bad);
            } catch (RuntimeException) {
            }
        }
    },
];
