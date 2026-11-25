<?php

declare(strict_types=1);

/**
 * Unit tests for scope parsing and IP range maths.
 * Only documentation addresses and example names are used (RFC 5737 / 3849 / 2606).
 */

use Sentinel\Scope\IpRange;
use Sentinel\Scope\ScopeParser;
use Sentinel\Scope\ScopeService;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'IpRange parses single IPs and CIDRs, rejects host bits and junk' => function (TestContext $ctx): void {
        $r = IpRange::parse('198.51.100.0/24');
        Assert::same('198.51.100.0/24', $r->canonical());
        Assert::same(8, $r->hostBits());
        Assert::same('203.0.113.7', IpRange::parse('203.0.113.7')->canonical());
        Assert::same('2001:db8::/120', IpRange::parse('2001:db8:0:0::/120')->canonical(), 'IPv6 canonical form');
        foreach (['198.51.100.7/24', '198.51.100.0/33', '1.2.3', 'abc', '198.51.100.0/24/1', '2001:db8::/129', '198.51.100.0/-1', ' 198.51.100.1'] as $bad) {
            Assert::same(null, IpRange::parse($bad), $bad);
        }
    },
    'IpRange overlap and containment' => function (TestContext $ctx): void {
        $net = IpRange::parse('198.51.100.0/24');
        Assert::true(IpRange::parse('198.51.100.200')->within($net), 'inside');
        Assert::true(!IpRange::parse('198.51.101.1')->within($net), 'outside');
        Assert::true($net->overlaps(IpRange::parse('198.51.100.128/25')), 'overlap');
        Assert::true(!$net->overlaps(IpRange::parse('2001:db8::1')), 'different families never overlap');
    },
    'production parser refuses private, reserved and documentation targets' => function (TestContext $ctx): void {
        $p = new ScopeParser(false);
        foreach (['10.1.2.3', '172.16.0.0/24', '192.168.1.0/24', '127.0.0.1', '169.254.1.1', '100.64.0.1', '0.0.0.0',
                  '224.0.0.1', '255.255.255.255', '::1', 'fe80::1', 'fd00::1', '::ffff:10.0.0.1', '::ffff:198.51.100.1',
                  '192.0.2.10', '198.51.100.0/24', '2001:db8::1', 'client.example', 'www.example.com', 'server.local',
                  'nas.lan', 'host.internal', 'printer.home.arpa', 'dc01.corp', 'x.test', 'localhost',
                  // IPv6 allowlist: only global unicast (2000::/3)
                  '::127.0.0.1', '::a00:1', '::10.0.0.0/120', '::ffff:0:a00:1', 'fec0::1', '4000::1', '5f00::1', '64:ff9b::a00:1',
                  // shared public suffixes and RFC 9476 .alt
                  '*.co.uk', 'co.uk', '*.github.io', '*.azurewebsites.net', '*.com.au', 'host.alt', '*.s3.amazonaws.com', '*.bucket.core.windows.net', '*.eastus.cloudapp.azure.com'] as $bad) {
            Assert::true(is_string($p->parse($bad)), "must refuse {$bad}");
        }
    },
    'parser limits range size and validates domain syntax' => function (TestContext $ctx): void {
        $p = new ScopeParser(true);
        Assert::true(is_string($p->parse('198.51.100.0/23')), '/23 too large');
        Assert::true(is_array($p->parse('198.51.100.0/24')), '/24 allowed');
        Assert::true(is_string($p->parse('2001:db8::/119')), 'IPv6 /119 too large');
        Assert::true(is_array($p->parse('2001:db8::/120')), 'IPv6 /120 allowed');
        foreach (['-bad.example', 'bad-.example', 'a..b.example', 'under_score.example', 'sp ace.example', '*.*.client.example',
                  'client.example/path', 'http://client.example', "client.example\n", 'single', str_repeat('a', 64) . '.example', 'münchen.example'] as $bad) {
            Assert::true(is_string($p->parse($bad)), 'invalid domain ' . json_encode($bad));
        }
        $ok = $p->parse('WWW.Client-Domain.Example.');
        Assert::same('www.client-domain.example', $ok['value'], 'lower-cased, trailing dot removed');
        Assert::same('*.client.example', $p->parse('*.client.example')['value']);
        Assert::same('xn--mnchen-3ya.example', $p->parse('xn--mnchen-3ya.example')['value'], 'punycode accepted');
    },
    'parseLines collects per-line errors, ignores comments and duplicates' => function (TestContext $ctx): void {
        $p = new ScopeParser(true);
        $r = $p->parseLines("# office\n203.0.113.10\n203.0.113.10\n\n10.0.0.1\nclient.example  # main site\n");
        Assert::same(2, count($r['entries']), 'duplicate kept once');
        Assert::same(1, count($r['errors']));
        Assert::contains('Line 5', $r['errors'][0]);
        Assert::same(1, count($p->parseLines("   \n# nothing\n")['errors']), 'empty scope is an error');
        $many = implode("\n", array_map(static fn (int $i): string => "203.0.113.{$i}", range(0, 255))) . "\n" .
                implode("\n", array_map(static fn (int $i): string => "h{$i}.client.example", range(1, 5)));
        Assert::true(count($p->parseLines($many)['errors']) === 1, 'more than 256 entries refused');
    },
    'authorization status follows dates and revocation' => function (TestContext $ctx): void {
        $a = ['revoked_at' => null, 'valid_from' => '2026-01-01', 'valid_until' => '2026-12-31'];
        Assert::same('scheduled', ScopeService::status($a, '2025-12-31'));
        Assert::same('active', ScopeService::status($a, '2026-01-01'));
        Assert::same('active', ScopeService::status($a, '2026-12-31'), 'last day still active');
        Assert::same('expired', ScopeService::status($a, '2027-01-01'));
        Assert::same('revoked', ScopeService::status(['revoked_at' => '2026-02-01 10:00:00'] + $a, '2026-06-01'));
        Assert::same('2026-11-22', ScopeService::today('Pacific/Auckland', new DateTimeImmutable('2026-11-21 12:00:00', new DateTimeZone('UTC'))), 'timezone-aware today');
        Assert::same('2026-11-21', ScopeService::today('Not/AZone', new DateTimeImmutable('2026-11-21 12:00:00', new DateTimeZone('UTC'))), 'bad zone falls back to UTC');
    },
];
