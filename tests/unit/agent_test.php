<?php

declare(strict_types=1);

/**
 * Unit tests for the on-premises agent's safety rules: internal ranges,
 * signatures, and the exact discovery command line.
 */

use Sentinel\Agent\InternalRanges;
use Sentinel\Agent\Signer;
use Sentinel\Scanning\NmapRunner;
use Sentinel\Scanning\NmapXmlParser;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'internal ranges: private only, limited size, canonical' => function (TestContext $ctx): void {
        $r = InternalRanges::parseLines("# office\n10.20.0.0/16\n192.168.1.5\nfd12:3456::/112\n172.16.4.0/24");
        Assert::same(['10.20.0.0/16', '192.168.1.5/32', 'fd12:3456::/112', '172.16.4.0/24'], $r['ranges']);
        Assert::same([], $r['errors']);
        foreach (['8.8.8.8' => 'not a private', '10.0.0.0/8' => 'too large', '172.32.0.0/16' => 'not a private', '10.1.2.3/24' => 'host bits', '2001:db8::/112' => 'not a private',
                  'fd00::/64' => 'too large', '100.64.1.0/24' => 'not a private', '10.1.0.0/33' => 'too long', 'example.com' => 'not an IP'] as $in => $why) {
            $p = InternalRanges::parse($in);
            Assert::true(isset($p['error']) && str_contains($p['error'], $why), $in . ': ' . json_encode($p));
        }
        $five = InternalRanges::parseLines("10.1.0.0/16\n10.2.0.0/16\n10.3.0.0/16\n10.4.0.0/16\n10.5.0.0/16");
        Assert::true($five['errors'] !== [], 'more than four /16 in total');
        Assert::true(InternalRanges::within('10.20.3.0/24', '10.20.0.0/16') && !InternalRanges::within('10.20.0.0/16', '10.20.3.0/24'), 'containment');
        Assert::true(!InternalRanges::within('10.21.0.1', '10.20.0.0/16') && !InternalRanges::within('fd00::1', '10.0.0.0/8'), 'outside and other family');
    },
    'signatures: canonical, verified with the public key only, tamper-evident' => function (TestContext $ctx): void {
        $s = Signer::fromAppKey(str_repeat("\x01", 32));
        Assert::same($s->publicKey(), Signer::fromAppKey(str_repeat("\x01", 32))->publicKey(), 'the same app key gives the same key pair');
        $a = $s->sign(['b' => 1, 'a' => ['y' => [2, 1], 'x' => 'z']]);
        Assert::same('{"a":{"x":"z","y":[2,1]},"b":1}', $a['payload'], 'keys sorted, lists kept in order');
        Assert::true(Signer::verify($a['payload'], $a['signature'], $s->publicKey()), 'valid');
        Assert::true(!Signer::verify(str_replace('"b":1', '"b":2', $a['payload']), $a['signature'], $s->publicKey()), 'changed payload');
        Assert::true(!Signer::verify($a['payload'], $a['signature'], Signer::fromAppKey(str_repeat("\x02", 32))->publicKey()), 'other key');
        Assert::true(!Signer::verify($a['payload'], 'not-base64!', $s->publicKey()), 'garbage signature');
    },
    'discovery sweeps use fixed, gentle, unprivileged arguments' => function (TestContext $ctx): void {
        $n = new NmapRunner('/usr/bin/nmap');
        Assert::same(['/usr/bin/nmap', '-sn', '--unprivileged', '-n', '-T2', '--max-rate', '50', '--max-retries', '1', '--host-timeout', '2m', '-oX', '-', '10.20.0.0/16'],
            $n->discoveryArguments(['10.20.0.0/16']));
        Assert::same('-6', $n->discoveryArguments(['fd00::/112'])[13]);
        foreach ([['10.0.0.0/24; rm -rf /'], ['10.0.0.1/24', 'fd00::/112'], ['-oN/tmp/x'], []] as $bad) {
            $threw = false;
            try {
                $n->discoveryArguments($bad);
            } catch (\InvalidArgumentException) {
                $threw = true;
            }
            Assert::true($threw, 'refused: ' . json_encode($bad));
        }
        $hosts = NmapXmlParser::parseDiscovery('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><address addr="AA:BB:CC:00:11:22" addrtype="mac"/></host>'
            . '<host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host></nmaprun>');
        Assert::same([['ip' => '10.0.0.5', 'mac' => 'aa:bb:cc:00:11:22']], $hosts, 'only hosts that are up');
    },
    'agent state: job history and results kept until accepted' => function (TestContext $ctx): void {
        $dir = sys_get_temp_dir() . '/sentinel-agent-state-' . bin2hex(random_bytes(4));
        mkdir($dir, 0700);
        $st = new \Sentinel\AgentClient\State($dir . '/state.json');
        $st->markDone(7);
        $st->savePending(7, ['status' => 'done', 'hosts' => []]);
        Assert::same([7], $st->doneIds());
        Assert::same([7 => ['status' => 'done', 'hosts' => []]], $st->pending());
        Assert::same('600', substr(sprintf('%o', fileperms($dir . '/pending-7.json')), -3), 'readable by the agent only');
        $st->clearPending(7);
        Assert::same([], $st->pending());
        array_map('unlink', glob($dir . '/*') ?: []);
        rmdir($dir);
    },
    'discovery output cut short still gives the complete host entries' => function (TestContext $ctx): void {
        $xml = '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host><host><status state="up"/><address addr="10.0.0.6"';
        Assert::same([['ip' => '10.0.0.5', 'mac' => '']], NmapXmlParser::parseDiscovery($xml));
    },
];
