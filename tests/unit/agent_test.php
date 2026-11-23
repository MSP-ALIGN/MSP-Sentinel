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
    'agent timing profiles: exact arguments, never faster than -T3; the agent refuses any other timing' => function (TestContext $ctx): void {
        $n = new NmapRunner('/usr/bin/nmap');
        Assert::same(['-T2', '--max-rate', '50'], array_slice($n->arguments('10.0.0.5', [22]), 5, 3), 'default: gentle');
        Assert::same(['-T2', '--max-rate', '10', '--max-parallelism', '1'], array_slice($n->withProfile('very_gentle')->arguments('10.0.0.5', [22]), 5, 5));
        Assert::same(['-T3', '--max-rate', '200'], array_slice($n->withProfile('normal')->discoveryArguments(['10.0.0.0/24']), 4, 3));
        foreach (NmapRunner::PROFILES as $args) {
            Assert::true(!array_intersect($args, ['-T4', '-T5', '--min-rate', '--privileged']), 'nothing aggressive in a profile');
        }
        $threw = false;
        try {
            $n->withProfile('insane');
        } catch (\InvalidArgumentException) {
            $threw = true;
        }
        Assert::true($threw, 'unknown profile refused');
        // A signed job with an unknown timing is refused by the agent; none means gentle.
        $s = Signer::fromAppKey(str_repeat("\x03", 32));
        $auth = $s->sign(['v' => 1, 'type' => 'internal_authorisation', 'site_id' => 1, 'client_id' => 1, 'timezone' => 'UTC',
            'valid_from' => gmdate('Y-m-d', time() - 86400), 'valid_until' => gmdate('Y-m-d', time() + 86400), 'ranges' => ['10.0.0.0/24']]);
        $job = static fn (array $extra): array => $s->sign($extra + ['v' => 1, 'type' => 'agent_job', 'job_id' => 7, 'agent_id' => 1, 'site_id' => 1, 'client_id' => 1,
            'kind' => 'full', 'ports' => [22], 'targets' => ['10.0.0.0/24'], 'udp_ports' => [], 'issued_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'expires_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 3600), 'authorisation' => $auth]);
        $v = new \Sentinel\AgentClient\JobVerifier($s->publicKey(), 1, 1, 1);
        $ok = $job([]);
        Assert::same('gentle', $v->verify($ok['payload'], $ok['signature'], [])['timing'] ?? null, 'none: gentle');
        $fast = $job(['timing' => 'normal']);
        Assert::same('normal', $v->verify($fast['payload'], $fast['signature'], [])['timing'] ?? null);
        foreach (['insane', 'T5', ''] as $bad) {
            $j = $job(['timing' => $bad]);
            Assert::same('unknown scan timing', $v->verify($j['payload'], $j['signature'], []), 'refused: ' . $bad);
        }
        $j = $job(['timing' => ['-T5']]);
        Assert::same('unknown scan timing', $v->verify($j['payload'], $j['signature'], []), 'refused: not a string');
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
    'protocol checks: SNMP encoding, answer parsing and grading' => function (TestContext $ctx): void {
        $req = \Sentinel\Scanning\ProtocolProbes::snmpGet('public', 1234);
        Assert::same('302702010104067075626c6963a01a020204d2020100020100300e300c06082b060102010101000500', bin2hex($req), 'SNMPv2c GetRequest sysDescr.0');
        $resp = hex2bin('3028020101040770726976617465a21a020204d2020100020100300e300c06082b060102010101000400');
        Assert::true(\Sentinel\Scanning\ProtocolProbes::snmpAnswered($resp, 1234), 'answer accepted');
        Assert::true(!\Sentinel\Scanning\ProtocolProbes::snmpAnswered($resp, 999), 'other request id');
        Assert::true(!\Sentinel\Scanning\ProtocolProbes::snmpAnswered("\x30\x02\x02", 1234), 'garbage');
        $noSuch = hex2bin('3028020101040770726976617465a21a020204d2020102020101300e300c06082b060102010101000500');
        Assert::true(\Sentinel\Scanning\ProtocolProbes::snmpAnswered($noSuch, 1234), 'an error answer (noSuchName) still proves the community works');
        Assert::same('020100', substr(bin2hex(\Sentinel\Scanning\ProtocolProbes::snmpGet('public', 1, 0)), 4, 6), 'version 0');
        // SMB and RDP answers, parsed from bytes.
        $P = \Sentinel\Scanning\ProtocolProbes::class;
        $smb1 = static fn (string $flags, int $words, int $dialect, int $status = 0): string => "\x00\x00\x00\x30" . "\xffSMB\x72" . pack('V', $status) . $flags . "\x01\x48" . str_repeat("\x00", 12) . "\xff\xff\x00\x00\x00\x00\x00\x00" . chr($words) . pack('v', $dialect) . str_repeat("\x00", 8);
        Assert::same(true, $P::parseSmb1($smb1("\x98", 17, 0)), 'SMBv1 accepted');
        Assert::same(false, $P::parseSmb1($smb1("\x98", 1, 0xFFFF)), 'no dialect accepted');
        Assert::same(null, $P::parseSmb1($smb1("\x98", 0, 0)), 'WordCount 0: not a dialect answer');
        Assert::same(null, $P::parseSmb1($smb1("\x18", 17, 0)), 'not a reply');
        Assert::same(false, $P::parseSmb1("\x00\x00\x00\x40\xfeSMB" . str_repeat("\x00", 60)), 'answered with SMB2');
        $smb2 = static fn (int $status, int $command, int $size, int $mode): string => "\x00\x00\x00\x80" . "\xfeSMB" . pack('v', 64) . pack('v', 0) . pack('V', $status) . pack('v', $command) . str_repeat("\x00", 50) . pack('v', $size) . pack('v', $mode) . str_repeat("\x00", 60);
        Assert::same(true, $P::parseSmb2($smb2(0, 0, 65, 3)), 'signing required');
        Assert::same(false, $P::parseSmb2($smb2(0, 0, 65, 1)), 'signing optional');
        Assert::same(null, $P::parseSmb2($smb2(0xC00000BB, 0, 9, 0)), 'dialects refused: unknown, never "not required"');
        Assert::same(null, $P::parseSmb2($smb2(0, 1, 65, 1)), 'not a NEGOTIATE answer');
        $rdp = static fn (int $type, int $value): string => "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00" . chr($type) . "\x00\x08\x00" . pack('V', $value);
        Assert::same(false, $P::parseRdp($rdp(2, 1)), 'TLS without NLA');
        Assert::same(true, $P::parseRdp($rdp(3, 5)), 'NLA required');
        Assert::same(false, $P::parseRdp($rdp(3, 2)), 'Standard RDP Security only');
        Assert::same(null, $P::parseRdp($rdp(3, 6)), 'TLS with client certificates: not judged');
        Assert::same(null, $P::parseRdp(substr($rdp(2, 1), 0, 11)), 'cut short');
        Assert::same(false, $P::parseRdp("\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"), 'complete confirm without negotiation');
        $issues = static fn (array $ports, array $dev = []): array => array_column(\Sentinel\Agent\ProtocolRules::issues(['checks' => json_encode($dev)], $ports), 'severity', 'code');
        Assert::same([], $issues([['port' => 445, 'service' => 'microsoft-ds', 'checks' => '{"smb1":null,"signing_required":null}', 'web' => null]]), 'unknown is never a finding');
        Assert::same(['smb1' => 'fail', 'smb_signing' => 'warn'], $issues([['port' => 445, 'service' => 'microsoft-ds', 'checks' => '{"smb1":true,"signing_required":false}', 'web' => null], ['port' => 139, 'service' => 'netbios-ssn', 'checks' => '{"smb1":true}', 'web' => null]]), 'one finding per code');
        Assert::same([], $issues([['port' => 23, 'service' => 'tcpwrapped', 'checks' => null, 'web' => null]]), 'port 23 without Telnet is not Telnet');
        Assert::same(['telnet' => 'fail'], $issues([['port' => 2323, 'service' => 'telnet', 'checks' => null, 'web' => null]]), 'Telnet on another port');
        Assert::same(['snmp_public' => 'warn'], $issues([], ['snmp_public' => true, 'snmp_private' => false]));
    },
];
