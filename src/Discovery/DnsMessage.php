<?php

declare(strict_types=1);

namespace Sentinel\Discovery;

/**
 * Builds DNS queries and parses DNS responses (RFC 1035 wire format) for the
 * record types discovery needs: A, NS, CNAME, PTR, MX and AAAA.
 *
 * Security assumptions:
 * - Responses are UNTRUSTED (anyone on the path, or a hostile name server,
 *   can shape them). The parser bounds-checks every read, limits compression
 *   pointer jumps (no loops), limits name and label lengths, and throws
 *   DnsException on anything malformed instead of guessing.
 * - A response is only accepted if its ID and question match the query, which
 *   stops stray or spoofed packets for other queries from being used.
 * - Names coming out of the parser contain only [a-z0-9_-] labels (anything
 *   else makes the response invalid). Callers still pass them through
 *   ScopeService::canonicalTarget() before using them.
 */
final class DnsMessage
{
    public const A = 1;
    public const NS = 2;
    public const CNAME = 5;
    public const PTR = 12;
    public const MX = 15;
    public const TXT = 16;
    public const AAAA = 28;

    private const MAX_JUMPS = 16;

    /**
     * A recursive query for one name and type.
     *
     * @param int    $id   16-bit random query ID.
     * @param string $name Hostname (already validated by the caller).
     */
    public static function buildQuery(int $id, string $name, int $type): string
    {
        $header = pack('nnnnnn', $id & 0xffff, 0x0100, 1, 0, 0, 0); // RD=1, one question
        return $header . self::encodeName($name) . pack('nn', $type, 1);
    }

    /**
     * Parse a response.
     *
     * @param string $packet Untrusted bytes.
     * @return array{rcode:int, truncated:bool, answers:list<array{name:string,type:int,ttl:int,data:string}>}
     * @throws DnsException if the packet is malformed or doesn't answer our query.
     */
    public static function parseResponse(string $packet, int $expectedId, string $expectedName, int $expectedType): array
    {
        if (strlen($packet) < 12) {
            throw new DnsException('DNS response too short.');
        }
        $h = unpack('nid/nflags/nqd/nan/nns/nar', substr($packet, 0, 12));
        if ($h['id'] !== ($expectedId & 0xffff) || ($h['flags'] & 0x8000) === 0) {
            throw new DnsException('DNS response does not match the query.');
        }
        if ($h['qd'] !== 1) {
            throw new DnsException('DNS response has an unexpected question count.');
        }
        $offset = 12;
        $qname = self::readName($packet, $offset);
        $q = self::read($packet, $offset, 4);
        $qt = unpack('ntype/nclass', $q);
        if ($qname !== strtolower(rtrim($expectedName, '.')) || $qt['type'] !== $expectedType) {
            throw new DnsException('DNS response is for a different question.');
        }
        $answers = [];
        for ($i = 0; $i < min($h['an'], 200); $i++) {
            $name = self::readName($packet, $offset);
            $fixed = unpack('ntype/nclass/Nttl/nlen', self::read($packet, $offset, 10));
            $rdataStart = $offset;
            $rdata = self::read($packet, $offset, $fixed['len']);
            if ($fixed['class'] !== 1) {
                continue;
            }
            $data = match ($fixed['type']) {
                self::A => strlen($rdata) === 4 ? (string) inet_ntop($rdata) : null,
                self::AAAA => strlen($rdata) === 16 ? (string) inet_ntop($rdata) : null,
                self::NS, self::CNAME, self::PTR => self::nameAt($packet, $rdataStart),
                self::MX => strlen($rdata) >= 3 ? self::nameAt($packet, $rdataStart + 2) : null,
                self::TXT => self::txt($rdata),
                default => null,
            };
            if ($data !== null) {
                $answers[] = ['name' => $name, 'type' => $fixed['type'], 'ttl' => $fixed['ttl'], 'data' => $data];
            }
        }
        return ['rcode' => $h['flags'] & 0x0f, 'truncated' => ($h['flags'] & 0x0200) !== 0, 'answers' => $answers];
    }

    /**
     * A TXT record's character-strings joined into one string (as SPF/DMARC/DKIM
     * expect), with anything but printable ASCII replaced by "?" and capped at 4000
     * characters. Untrusted data: only used for pattern checks and shown escaped.
     */
    private static function txt(string $rdata): ?string
    {
        $out = '';
        $pos = 0;
        $len = strlen($rdata);
        while ($pos < $len) {
            $n = ord($rdata[$pos]);
            $part = substr($rdata, $pos + 1, $n);
            if (strlen($part) !== $n) {
                return null; // malformed
            }
            $out .= $part;
            $pos += $n + 1;
            if (strlen($out) > 4000) {
                break;
            }
        }
        return substr((string) preg_replace('/[^\x20-\x7E]/', '?', $out), 0, 4000);
    }

    public const SOA = 6;
    public const AXFR = 252;

    /** A zone transfer request (AXFR) for $zone: no recursion asked. Sent over TCP by the caller. */
    public static function buildAxfr(int $id, string $zone): string
    {
        return pack('nnnnnn', $id & 0xffff, 0x0000, 1, 0, 0, 0) . self::encodeName($zone) . pack('nn', self::AXFR, 1);
    }

    /**
     * One message of a zone transfer answer: the response code, and each answer's owner name and type (at most 500).
     * Only names and types are read (enough to tell an open transfer and show a few names as evidence).
     *
     * @param string $packet Untrusted bytes.
     * @return array{rcode:int, records:list<array{name:string,type:int}>}
     * @throws DnsException if the packet is malformed or doesn't answer our request.
     */
    public static function parseAxfrMessage(string $packet, int $expectedId): array
    {
        if (strlen($packet) < 12) {
            throw new DnsException('DNS response too short.');
        }
        $h = unpack('nid/nflags/nqd/nan/nns/nar', substr($packet, 0, 12));
        if ($h['id'] !== ($expectedId & 0xffff) || ($h['flags'] & 0x8000) === 0) {
            throw new DnsException('DNS response does not match the request.');
        }
        $offset = 12;
        for ($i = 0; $i < min($h['qd'], 1); $i++) {
            self::readName($packet, $offset);
            self::read($packet, $offset, 4);
        }
        $records = [];
        for ($i = 0; $i < min($h['an'], 500); $i++) {
            $name = self::readName($packet, $offset);
            $fixed = unpack('ntype/nclass/Nttl/nlen', self::read($packet, $offset, 10));
            self::read($packet, $offset, $fixed['len']);
            $records[] = ['name' => $name, 'type' => $fixed['type']];
        }
        return ['rcode' => $h['flags'] & 0x0f, 'records' => $records];
    }

    /** The reverse-lookup name for an IP, e.g. 203.0.113.5 -> 5.113.0.203.in-addr.arpa. */
    public static function reverseName(string $ip): string
    {
        $packed = (string) inet_pton($ip);
        if (strlen($packed) === 4) {
            return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        }
        $nibbles = str_split(bin2hex($packed));
        return implode('.', array_reverse($nibbles)) . '.ip6.arpa';
    }

    /** Wire-format name: length-prefixed labels, ending with a zero byte. */
    private static function encodeName(string $name): string
    {
        $out = '';
        foreach (explode('.', rtrim($name, '.')) as $label) {
            if ($label === '' || strlen($label) > 63) {
                throw new DnsException('Invalid name for a DNS query.');
            }
            $out .= chr(strlen($label)) . $label;
        }
        return $out . "\0";
    }

    /** Read a (possibly compressed) name at a fixed position without moving a cursor. */
    private static function nameAt(string $packet, int $position): string
    {
        return self::readName($packet, $position);
    }

    /**
     * Read a name, following compression pointers safely.
     *
     * @param int $offset Moved past the name as it appears at the original position.
     */
    private static function readName(string $packet, int &$offset): string
    {
        $labels = [];
        $pos = $offset;
        $jumped = false;
        $jumps = 0;
        $total = 0;
        while (true) {
            $len = ord(self::byteAt($packet, $pos));
            if (($len & 0xc0) === 0xc0) {
                $pointer = (($len & 0x3f) << 8) | ord(self::byteAt($packet, $pos + 1));
                if (++$jumps > self::MAX_JUMPS || $pointer >= strlen($packet)) {
                    throw new DnsException('DNS name compression loop or bad pointer.');
                }
                if (!$jumped) {
                    $offset = $pos + 2;
                    $jumped = true;
                }
                $pos = $pointer;
                continue;
            }
            if (($len & 0xc0) !== 0) {
                throw new DnsException('Unsupported DNS label type.');
            }
            if ($len === 0) {
                if (!$jumped) {
                    $offset = $pos + 1;
                }
                break;
            }
            $label = substr($packet, $pos + 1, $len);
            if (strlen($label) !== $len) {
                throw new DnsException('DNS label runs past the end of the packet.');
            }
            // Only hostname-safe bytes. Anything else (dots inside labels, control or non-UTF-8 bytes)
            // has no place in the names discovery uses, and could break storage or display later.
            if (!preg_match('/^[A-Za-z0-9_-]+$/D', $label)) {
                throw new DnsException('DNS name contains characters that are not allowed in hostnames.');
            }
            $total += $len + 1;
            if ($total > 255) {
                throw new DnsException('DNS name too long.');
            }
            $labels[] = strtolower($label);
            $pos += $len + 1;
        }
        return implode('.', $labels);
    }

    /** Read $n bytes at $offset (bounds-checked) and move the offset. */
    private static function read(string $packet, int &$offset, int $n): string
    {
        $bytes = substr($packet, $offset, $n);
        if (strlen($bytes) !== $n) {
            throw new DnsException('DNS response truncated.');
        }
        $offset += $n;
        return $bytes;
    }

    /** One byte, bounds-checked. */
    private static function byteAt(string $packet, int $pos): string
    {
        if ($pos < 0 || $pos >= strlen($packet)) {
            throw new DnsException('DNS response truncated.');
        }
        return $packet[$pos];
    }
}
