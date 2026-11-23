<?php

declare(strict_types=1);

namespace Sentinel\Directory;

/**
 * The small part of BER (ASN.1 Basic Encoding Rules) that LDAP needs: single-byte tags, definite lengths, integers,
 * octet strings, booleans, enumerations and constructed values. Used by LdapClient (agent) and the test suite's mock
 * LDAP server.
 *
 * Decoding is for untrusted input: lengths are checked against what is actually there, a length takes at most 4
 * bytes, nesting depth is capped by the caller walking it, and anything malformed throws BerException (never a
 * partial value). Multi-byte tags and indefinite lengths (not used by LDAP servers' answers) are refused.
 */
final class Ber
{
    public const INTEGER = 0x02;
    public const OCTET_STRING = 0x04;
    public const BOOLEAN = 0x01;
    public const ENUMERATED = 0x0A;
    public const SEQUENCE = 0x30;
    public const SET = 0x31;

    /** A complete TLV. */
    public static function tlv(int $tag, string $value): string
    {
        return chr($tag) . self::length(strlen($value)) . $value;
    }

    public static function seq(string ...$parts): string
    {
        return self::tlv(self::SEQUENCE, implode('', $parts));
    }

    public static function str(string $s, int $tag = self::OCTET_STRING): string
    {
        return self::tlv($tag, $s);
    }

    public static function int(int $n, int $tag = self::INTEGER): string
    {
        // Only non-negative numbers are ever sent (message IDs, versions, sizes, scopes): shortest form, with a
        // leading zero byte when the top bit would otherwise make it negative.
        if ($n < 0) {
            throw new \InvalidArgumentException('Only non-negative BER integers are encoded.');
        }
        $bytes = '';
        do {
            $bytes = chr($n & 0xFF) . $bytes;
            $n >>= 8;
        } while ($n > 0);
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }
        return self::tlv($tag, $bytes);
    }

    public static function bool(bool $b): string
    {
        return self::tlv(self::BOOLEAN, $b ? "\xFF" : "\x00");
    }

    /** A definite length. */
    public static function length(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = ltrim(pack('N', $len), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Read the TLV at $offset.
     *
     * @return array{tag:int, value:string, end:int} end: the offset just after it.
     */
    public static function read(string $buf, int $offset = 0): array
    {
        $n = strlen($buf);
        if ($offset + 2 > $n) {
            throw new BerException('Truncated BER value.');
        }
        $tag = ord($buf[$offset]);
        if (($tag & 0x1F) === 0x1F) {
            throw new BerException('Multi-byte BER tags are not supported.');
        }
        [$len, $pos] = self::readLength($buf, $offset + 1);
        if ($pos + $len > $n) {
            throw new BerException('BER value longer than the data.');
        }
        return ['tag' => $tag, 'value' => substr($buf, $pos, $len), 'end' => $pos + $len];
    }

    /**
     * The length starting at $offset, and the offset of the value after it.
     *
     * @return array{0:int, 1:int}
     */
    public static function readLength(string $buf, int $offset): array
    {
        if ($offset >= strlen($buf)) {
            throw new BerException('Truncated BER length.');
        }
        $first = ord($buf[$offset]);
        if ($first < 0x80) {
            return [$first, $offset + 1];
        }
        $count = $first & 0x7F;
        if ($count === 0 || $count > 4) {
            throw new BerException('Unsupported BER length.');
        }
        if ($offset + 1 + $count > strlen($buf)) {
            throw new BerException('Truncated BER length.');
        }
        $len = 0;
        for ($i = 1; $i <= $count; $i++) {
            $len = ($len << 8) | ord($buf[$offset + $i]);
        }
        return [$len, $offset + 1 + $count];
    }

    /**
     * Every TLV inside a constructed value.
     *
     * @return list<array{tag:int, value:string, end:int}>
     */
    public static function children(string $value, int $max = 100000): array
    {
        $out = [];
        for ($o = 0, $n = strlen($value); $o < $n;) {
            $t = self::read($value, $o);
            $out[] = $t;
            $o = $t['end'];
            if (count($out) > $max) {
                throw new BerException('Too many BER values.');
            }
        }
        return $out;
    }

    /** A decoded INTEGER or ENUMERATED (at most 8 bytes). */
    public static function toInt(string $value): int
    {
        $len = strlen($value);
        if ($len === 0 || $len > 8) {
            throw new BerException('Bad BER integer.');
        }
        $n = (ord($value[0]) & 0x80) ? -1 : 0;
        for ($i = 0; $i < $len; $i++) {
            $n = ($n << 8) | ord($value[$i]);
        }
        return $n;
    }
}
