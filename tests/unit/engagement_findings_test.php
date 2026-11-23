<?php

declare(strict_types=1);

/**
 * Unit tests for EngagementFindings: evidence from engagement tests (ports, nmap script results, UDP checks) turned
 * into pen-test findings with the right severity. Made-up addresses only.
 */

use Sentinel\Engagements\EngagementFindings;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'engagement findings: anonymous access, old protocols, SNMP and exposure' => function (TestContext $ctx): void {
        $udp = static fn (array $v): array => array_map(static fn ($x): string => (string) json_encode($x), $v);
        $results = [
            ['ip' => '203.0.113.3', 'origin' => 'external', 'ports_list' => [
                ['port' => 21, 'service' => 'ftp', 'scripts' => [['id' => 'ftp-anon', 'output' => "Anonymous FTP login allowed (FTP code 230)"]]],
                ['port' => 3389, 'service' => 'ms-wbt-server', 'scripts' => []],
                ['port' => 443, 'service' => 'https', 'scripts' => []]],
             'checks_list' => ['udp' => $udp(['snmp_public' => true, 'snmp_private' => false, 'ntp' => false, 'ssdp' => ['server' => 'Example UPnP/1.0']])]],
            ['ip' => '10.97.0.20', 'origin' => 'internal', 'ports_list' => [['port' => 23, 'service' => 'telnet'], ['port' => 111, 'service' => 'rpcbind',
                'scripts' => [['id' => 'nfs-showmount', 'output' => "/export/backups *\n/export/home 10.97.0.0/24"]]]],
             'checks_list' => ['hostscripts' => [
                ['id' => 'smb-protocols', 'output' => "dialects:\n  NT LM 0.12 (SMBv1) [dangerous, but default]\n  2.1"],
                ['id' => 'smb2-security-mode', 'output' => "3.1.1:\n  Message signing enabled but not required"],
                ['id' => 'smb-enum-shares', 'output' => "\\\\10.97.0.20\\Scans:\n  Anonymous access: READ/WRITE\n\\\\10.97.0.20\\Public:\n  Anonymous access: READ\n\\\\10.97.0.20\\IPC$:\n  Anonymous access: READ"]],
              'udp' => $udp(['snmp_public' => true, 'snmp_private' => true, 'ntp' => true, 'ssdp' => null])]],
        ];
        $f = EngagementFindings::analyse($results);
        $by = [];
        foreach ($f as $x) {
            $by[$x['key'] . '@' . $x['target']] = $x['severity'];
        }
        $expect = [
            'ftp_anon@203.0.113.3:21' => 'fail', 'exposed_3389@203.0.113.3:3389' => 'fail', 'snmp_public@203.0.113.3:161/udp' => 'fail', 'ssdp@203.0.113.3:1900/udp' => 'warn',
            'ftp@203.0.113.3:21' => 'warn', 'open_443@203.0.113.3:443' => 'info',
            'telnet@10.97.0.20:23' => 'fail', 'nfs_exports@10.97.0.20:111' => 'fail', 'smb1@10.97.0.20' => 'fail', 'smb_signing@10.97.0.20' => 'warn',
            'smb_anon_write@10.97.0.20' => 'fail', 'smb_anon_read@10.97.0.20' => 'warn', 'snmp_private@10.97.0.20:161/udp' => 'fail', 'snmp_public@10.97.0.20:161/udp' => 'warn',
            'ntp@10.97.0.20:123/udp' => 'info',
        ];
        foreach ($expect as $k => $sev) {
            Assert::same($sev, $by[$k] ?? 'missing', $k);
        }
        Assert::true(!isset($by['ntp@203.0.113.3:123/udp']), 'no NTP answer, no finding');
        Assert::same(2, count(array_filter($f, static fn (array $x): bool => str_starts_with($x['key'], 'smb_anon'))), 'IPC$ is not a finding');
        Assert::same('fail', $f[0]['severity'], 'fails first');
        $c = EngagementFindings::counts($f);
        Assert::true($c['fail'] === 8 && $c['warn'] === 5 && $c['info'] === 3, json_encode($c)); // 443, rpcbind (111) and NTP
    },
];
