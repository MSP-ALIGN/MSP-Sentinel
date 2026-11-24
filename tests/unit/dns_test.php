<?php

declare(strict_types=1);

/**
 * Unit tests for the DNS wire-format parser, the DNS client (against the mock
 * DNS server on 127.0.0.1) and the crt.sh response parser.
 * Hostile inputs: compression loops, truncation, mismatched IDs and questions, garbage.
 */

use Sentinel\Discovery\CrtShClient;
use Sentinel\Discovery\DnsClient;
use Sentinel\Discovery\DnsException;
use Sentinel\Discovery\DnsMessage;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

/** Header + question for "a.example" type A, as a server would echo it. */
$responseHead = static function (int $id, int $flags, int $answers): string {
    return pack('nnnnnn', $id, $flags, 1, $answers, 0, 0) . "\x01a\x07example\x00" . pack('nn', 1, 1);
};
$throws = static function (callable $fn): bool {
    try {
        $fn();
        return false;
    } catch (DnsException) {
        return true;
    }
};

return [
    'DNS query encoding' => function (TestContext $ctx): void {
        $q = DnsMessage::buildQuery(0x1234, 'www.example', DnsMessage::AAAA);
        Assert::same("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x00\x00\x1c\x00\x01", $q);
        Assert::same('10.113.0.203.in-addr.arpa', DnsMessage::reverseName('203.0.113.10'));
        Assert::same('1.' . str_repeat('0.', 23) . '8.b.d.0.1.0.0.2.ip6.arpa', DnsMessage::reverseName('2001:db8::1'));
    },
    'DNS parser reads A, MX and CNAME answers with compression' => function (TestContext $ctx) use ($responseHead): void {
        $p = $responseHead(7, 0x8180, 2)
            . "\xc0\x0c" . pack('nnNn', 5, 1, 60, 6) . "\x03cdn\xc0\x0e"      // a.example CNAME cdn.example (pointer to "example")
            . "\xc0\x0c" . pack('nnNn', 1, 1, 60, 4) . inet_pton('203.0.113.9');
        $r = DnsMessage::parseResponse($p, 7, 'a.example', DnsMessage::A);
        Assert::same(0, $r['rcode']);
        Assert::same('cdn.example', $r['answers'][0]['data']);
        Assert::same('203.0.113.9', $r['answers'][1]['data']);
    },
    'DNS parser rejects hostile and mismatched responses' => function (TestContext $ctx) use ($responseHead, $throws): void {
        $good = $responseHead(7, 0x8180, 1) . "\xc0\x0c" . pack('nnNn', 1, 1, 60, 4) . inet_pton('203.0.113.9');
        Assert::true($throws(fn () => DnsMessage::parseResponse($good, 8, 'a.example', DnsMessage::A)), 'wrong ID');
        Assert::true($throws(fn () => DnsMessage::parseResponse($good, 7, 'b.example', DnsMessage::A)), 'wrong question name');
        Assert::true($throws(fn () => DnsMessage::parseResponse($good, 7, 'a.example', DnsMessage::AAAA)), 'wrong question type');
        Assert::true($throws(fn () => DnsMessage::parseResponse(substr($good, 0, -2), 7, 'a.example', DnsMessage::A)), 'truncated rdata');
        Assert::true($throws(fn () => DnsMessage::parseResponse('short', 7, 'a.example', DnsMessage::A)), 'too short');
        $query = pack('nnnnnn', 7, 0x0100, 1, 0, 0, 0) . "\x01a\x07example\x00" . pack('nn', 1, 1);
        Assert::true($throws(fn () => DnsMessage::parseResponse($query, 7, 'a.example', DnsMessage::A)), 'a query, not a response');
        $loop = $responseHead(7, 0x8180, 1) . "\xc0\x1b";     // answer name points at itself
        Assert::true($throws(fn () => DnsMessage::parseResponse($loop, 7, 'a.example', DnsMessage::A)), 'compression loop');
        $farPointer = $responseHead(7, 0x8180, 1) . "\xff\xff";
        Assert::true($throws(fn () => DnsMessage::parseResponse($farPointer, 7, 'a.example', DnsMessage::A)), 'pointer past the end');
        $long = $responseHead(7, 0x8180, 1) . str_repeat("\x3f" . str_repeat('a', 63), 5) . "\x00" . pack('nnNn', 1, 1, 60, 4) . inet_pton('203.0.113.9');
        Assert::true($throws(fn () => DnsMessage::parseResponse($long, 7, 'a.example', DnsMessage::A)), 'name over 255 bytes');
        $weird = $responseHead(7, 0x8180, 1) . "\xc0\x0c" . pack('nnNn', 5, 1, 60, 14) . "\x04ev\xffl\x07example\x00";
        Assert::true($throws(fn () => DnsMessage::parseResponse($weird, 7, 'a.example', DnsMessage::A)), 'non-hostname bytes in a name');
        $dotted = $responseHead(7, 0x8180, 1) . "\xc0\x0c" . pack('nnNn', 5, 1, 60, 13) . "\x03a.b\x07example\x00";
        Assert::true($throws(fn () => DnsMessage::parseResponse($dotted, 7, 'a.example', DnsMessage::A)), 'dot inside a label');
        $badA = $responseHead(7, 0x8180, 1) . "\xc0\x0c" . pack('nnNn', 1, 1, 60, 3) . 'abc';
        Assert::same([], DnsMessage::parseResponse($badA, 7, 'a.example', DnsMessage::A)['answers'], 'A record with wrong length is ignored');
    },
    'DNS client against the mock server: answers, NXDOMAIN, TCP fallback, failures' => function (TestContext $ctx) use ($throws): void {
        $dns = new DnsClient('127.0.0.1', $ctx->dnsPort, 0.3);
        $a = $dns->query('mail.discovery.example', DnsMessage::A);
        Assert::same('203.0.113.20', $a[0]['data']);
        $mx = array_column($dns->query('discovery.example', DnsMessage::MX), 'data');
        Assert::same(['mail.discovery.example', 'mx1.mailhost.example'], $mx);
        Assert::same([], $dns->query('nothing-here.discovery.example', DnsMessage::A), 'NXDOMAIN gives no answers');
        Assert::same('203.0.113.61', $dns->query('big.quiet.example', DnsMessage::A)[0]['data'], 'truncated UDP answer retried over TCP');
        Assert::true($throws(fn () => $dns->query('remote.discovery.example', DnsMessage::A)), 'timeout');
        Assert::true($throws(fn () => $dns->query('ftp.discovery.example', DnsMessage::A)), 'garbage response');
        $t = microtime(true);
        Assert::true($throws(fn () => $dns->query('wrongid.quiet.example', DnsMessage::A)), 'reply with the wrong ID is never accepted');
        Assert::true(microtime(true) - $t >= 0.5, 'it kept waiting for the right reply until the timeout');
        $chain = $dns->query('www.discovery.example', DnsMessage::A);
        Assert::same([DnsMessage::CNAME, DnsMessage::A], array_column($chain, 'type'), 'CNAME chain');
    },
    'crt.sh parser keeps only valid names under the domain' => function (TestContext $ctx): void {
        $json = (string) file_get_contents($ctx->root . '/tests/fixtures/crtsh/discovery.example.json');
        Assert::same(['billing.discovery.example', 'discovery.example', 'old.discovery.example', 'shop.discovery.example', 'www.discovery.example'], CrtShClient::parse($json, 'discovery.example'));
        $threw = false;
        try {
            CrtShClient::parse('<html>', 'discovery.example');
        } catch (RuntimeException) {
            $threw = true;
        }
        Assert::true($threw, 'non-JSON refused');
        Assert::same([], CrtShClient::parse('[{"name_value":"evil-discovery.example"}]', 'discovery.example'), 'suffix without dot boundary refused');
    },
    'crt.sh client: errors are reported, oversized bodies refused' => function (TestContext $ctx): void {
        $c = new CrtShClient($ctx->crtshUrl, 5);
        Assert::same(['billing.discovery.example', 'discovery.example', 'old.discovery.example', 'shop.discovery.example', 'www.discovery.example'], $c->hostnames('discovery.example'));
        foreach (['crtsh-down.example' => 'HTTP 500', 'crtsh-huge.example' => 'too large', 'crtsh-html.example' => 'not JSON'] as $domain => $expect) {
            try {
                $c->hostnames($domain);
                Assert::true(false, "{$domain} should fail");
            } catch (RuntimeException $ex) {
                Assert::contains($expect, $ex->getMessage(), $domain);
            }
        }
    },
    'zone transfer parser: wildcard names read, hostile messages refused' => function (TestContext $ctx) use ($throws): void {
        $q = "\x01z\x07example\x00" . pack('nn', DnsMessage::AXFR, 1);
        $rr = static fn (string $owner, int $type): string => $owner . pack('nnNn', $type, 1, 300, 0);
        $msg = pack('nnnnnn', 7, 0x8400, 1, 3, 0, 0) . $q . $rr("\xc0\x0c", DnsMessage::SOA) . $rr("\x01*\xc0\x0c", DnsMessage::A) . $rr("\x03a\x01b\xc0\x0c", DnsMessage::A);
        $p = DnsMessage::parseAxfrMessage($msg, 7, 'z.example');
        Assert::same(['z.example', '*.z.example', 'a?b.z.example'], array_column($p['records'], 'name'), 'wildcard kept, odd bytes made harmless');
        Assert::true($throws(fn () => DnsMessage::parseAxfrMessage($msg, 8, 'z.example')), 'wrong id');
        Assert::true($throws(fn () => DnsMessage::parseAxfrMessage($msg, 7, 'other.example')), 'answer to another zone');
        Assert::true($throws(fn () => DnsMessage::parseAxfrMessage(pack('nnnnnn', 7, 0x8400, 2, 0, 0, 0) . $q . $q, 7, 'z.example')), 'two questions');
        Assert::true($throws(fn () => DnsMessage::parseAxfrMessage(pack('nnnnnn', 7, 0x8400, 0, 1, 0, 0) . "\xc0\x0c" . pack('nnNn', 1, 1, 300, 0), 7, 'z.example')), 'compression loop');
        Assert::true($throws(fn () => DnsMessage::parseAxfrMessage(pack('nnnnnn', 7, 0x8400, 1, 1, 0, 0) . $q . "\x01x\x00" . pack('nnNn', 1, 1, 300, 50), 7, 'z.example')), 'record longer than the message');
        // A later message without the question is fine.
        Assert::same(1, count(DnsMessage::parseAxfrMessage(pack('nnnnnn', 7, 0x8400, 0, 1, 0, 0) . $rr("\x01z\x07example\x00", DnsMessage::SOA), 7, 'z.example')['records']));
    },
];
