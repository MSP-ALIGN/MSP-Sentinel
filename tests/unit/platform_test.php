<?php

declare(strict_types=1);

/**
 * Unit tests for the agent's platform layer (src/AgentClient/Platform.php): Linux and Windows ARP tables parsed
 * strictly, default paths per platform, and the name listener off on Windows. Made-up addresses only.
 */

use Sentinel\AgentClient\Platform;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'platform: Linux and Windows ARP tables, strictly parsed' => function (TestContext $ctx): void {
        $linux = "IP address       HW type     Flags       HW address            Mask     Device\n"
            . "10.90.0.30       0x1         0x2         02:00:00:00:00:30     *        eth0\n"
            . "10.90.0.31       0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        Assert::same(['10.90.0.30' => '02:00:00:00:00:30'], Platform::parseLinuxArp($linux), 'incomplete entries skipped');
        $windows = "\r\nInterface: 10.90.0.5 --- 0x7\r\n  Internet Address      Physical Address      Type\r\n"
            . "  10.90.0.1             02-00-00-00-00-01     dynamic   \r\n"
            . "  10.90.0.40            02-00-00-AA-BB-40     dynamic   \r\n"
            . "  10.90.0.255           ff-ff-ff-ff-ff-ff     static    \r\n"
            . "  224.0.0.22            01-00-5e-00-00-16     static    \r\n"
            . "  239.255.255.250       01-00-5e-7f-ff-fa     static    \r\n"
            . "  10.90.0.99            not-a-mac             dynamic   \r\n"
            . "  999.1.1.1             02-00-00-00-00-02     dynamic   \r\n";
        Assert::same(['10.90.0.1' => '02:00:00:00:00:01', '10.90.0.40' => '02:00:00:aa:bb:40'], Platform::parseWindowsArp($windows),
            'unicast entries only, lowercase with colons; broadcast, multicast and junk skipped');
        Assert::same([], Platform::parseWindowsArp(''), 'no output: no MAC addresses (never an error)');
    },
    'platform: paths, nmap and the name listener per platform' => function (TestContext $ctx): void {
        $lin = Platform::detect(Platform::LINUX);
        Assert::same('/etc/sentinel-agent/agent.json', $lin->configFile());
        Assert::same('/var/lib/sentinel-agent-update', $lin->updateResultDir());
        Assert::true($lin->namesListener(), 'Linux listens for name requests');
        $win = Platform::detect(Platform::WINDOWS);
        Assert::true($win->isWindows(), 'forced Windows');
        Assert::contains('MSP Sentinel Agent\\config\\agent.json', $win->configFile());
        Assert::contains('MSP Sentinel Agent\\config\\release-key.pub', $win->releaseKeyFile());
        Assert::contains('MSP Sentinel Agent\\update', $win->updateResultDir());
        Assert::true(str_ends_with($win->nmapPath(), '\\Nmap\\nmap.exe'), 'nmap from its install folder');
        Assert::true(!$win->namesListener(), 'Windows owns UDP 137 and 5355: no listener');
        Assert::same(['uptime' => null, 'memory_mb' => null], $win->systemInfo());
        $file = dirname($ctx->configPath) . '/arp-windows.txt';
        file_put_contents($file, "  10.90.0.40            02-00-00-aa-bb-40     dynamic\n");
        Assert::same(['10.90.0.40' => '02:00:00:aa:bb:40'], Platform::detect(Platform::WINDOWS, $file)->arpTable(), 'the test suite reads arp -a output from a file');
    },
];
