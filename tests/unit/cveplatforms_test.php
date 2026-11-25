<?php

declare(strict_types=1);

/**
 * Unit tests for platform-limited CVEs (1.49): FeedParser::platformsFor reads NVD's "running on" configurations and
 * target_sw, and osFamily maps an inventory OS name to a family. Made-up CPEs and CVE data only.
 */

use Sentinel\Vulns\FeedParser;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$chrome = 'cpe:2.3:a:google:chrome:';
$vuln = static fn (string $crit): array => ['vulnerable' => true, 'criteria' => $crit];
$on = static fn (string $crit): array => ['vulnerable' => false, 'criteria' => $crit];

return [
    'CVE platforms: AND with an OS limits; any unlimited configuration means every platform' => function (TestContext $ctx) use ($chrome, $vuln, $on): void {
        $android = ['operator' => 'AND', 'nodes' => [['cpeMatch' => [$vuln($chrome . '120.0:*:*:*:*:*:*:*')]], ['cpeMatch' => [$on('cpe:2.3:o:google:android:-:*:*:*:*:*:*:*')]]]];
        $iosMac = ['operator' => 'AND', 'nodes' => [['cpeMatch' => [$vuln($chrome . '*:*:*:*:*:*:*:*')]],
            ['cpeMatch' => [$on('cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*'), $on('cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*')]]]];
        $plain = ['nodes' => [['cpeMatch' => [$vuln($chrome . '120.0:*:*:*:*:*:*:*')]]]];
        $target = ['nodes' => [['cpeMatch' => [$vuln($chrome . '120.0:*:*:*:*:windows:*:*')]]]];
        $other = ['nodes' => [['cpeMatch' => [$vuln('cpe:2.3:a:mozilla:firefox:1:*:*:*:*:*:*:*')]]]];
        Assert::same(['android'], FeedParser::platformsFor([$android], $chrome));
        Assert::same(['android', 'ios', 'macos'], FeedParser::platformsFor([$android, $iosMac], $chrome), 'limits add up');
        Assert::same([], FeedParser::platformsFor([$android, $plain], $chrome), 'one unlimited configuration: any platform');
        Assert::same(['windows'], FeedParser::platformsFor([$target], $chrome), 'target_sw in the product CPE');
        Assert::same([], FeedParser::platformsFor([$other], $chrome), 'product not in it: no limit (stricter old behaviour)');
        Assert::same([], FeedParser::platformsFor([['operator' => 'AND', 'nodes' => [['cpeMatch' => [$vuln($chrome . '1:*:*:*:*:*:*:*')]], ['cpeMatch' => [$on('cpe:2.3:a:example:lib:1:*:*:*:*:*:*:*')]]]]], $chrome), 'AND with an application, not an OS: no limit');
        Assert::same([], FeedParser::platformsFor(['junk', ['nodes' => 'junk']], $chrome), 'malformed input: no limit');
    },
    'CVE platforms: OS names from inventory map to families' => function (TestContext $ctx): void {
        foreach (['Windows 11 Pro' => 'windows', 'Windows Server 2022 Standard' => 'windows', 'macOS Sonoma 14.5' => 'macos', 'Mac OS X 10.15' => 'macos',
                  'Ubuntu 22.04 LTS' => 'linux', 'Android 14' => 'android', 'iOS 17.4' => 'ios', 'ChromeOS 120' => 'chromeos', '' => '', 'Phoenix BIOS 4.0' => ''] as $os => $family) {
            Assert::same($family, FeedParser::osFamily($os), $os === '' ? '(empty)' : $os);
        }
        Assert::same('windows', FeedParser::platformFamily('windows_10'));
        Assert::same('macos', FeedParser::platformFamily('mac_os_x'));
        Assert::same('ios', FeedParser::platformFamily('iphone_os'));
    },
];
