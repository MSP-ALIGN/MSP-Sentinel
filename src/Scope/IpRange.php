<?php

declare(strict_types=1);

namespace Sentinel\Scope;

/**
 * An inclusive IP address range (a single IP or a CIDR block), held as packed
 * binary start and end addresses, so ranges of the same family can be
 * compared byte-wise (and in SQL with VARBINARY(16) columns).
 *
 * Security assumptions:
 * - Input text is untrusted. parse() accepts only strict IPv4/IPv6 literals
 *   with an optional /prefix, and returns null for anything else.
 * - IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are refused by the caller's
 *   reserved-range check (::ffff:0:0/96 is in the reserved list), so a
 *   private IPv4 can't be sneaked in through IPv6 notation.
 */
final class IpRange
{
    /** Use parse(). $start and $end are packed addresses (4 or 16 bytes). */
    private function __construct(
        public readonly string $start,
        public readonly string $end,
        public readonly int $prefix,
        public readonly bool $isV6,
    ) {
    }

    /**
     * Parse "192.0.2.10", "198.51.100.0/24" or "2001:db8::/120".
     *
     * @param string $text Untrusted.
     * @return self|null Null if it isn't a valid IP or CIDR, or the address has host bits set below the prefix.
     */
    public static function parse(string $text): ?self
    {
        $parts = explode('/', $text);
        if (count($parts) > 2) {
            return null;
        }
        $ip = $parts[0];
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $packed = inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        $isV6 = strlen($packed) === 16;
        $bits = $isV6 ? 128 : 32;
        if (count($parts) === 2) {
            if (!preg_match('/^\d{1,3}$/', $parts[1]) || (int) $parts[1] > $bits) {
                return null;
            }
            $prefix = (int) $parts[1];
        } else {
            $prefix = $bits;
        }
        $mask = self::mask($prefix, strlen($packed));
        $start = $packed & $mask;
        if ($start !== $packed) {
            // "198.51.100.7/24" is almost always a typo. Ask for the network address instead of guessing.
            return null;
        }
        $end = $packed | ~$mask;
        return new self($start, $end, $prefix, $isV6);
    }

    /** Number of host bits (32/128 minus prefix): the range holds 2^n addresses. */
    public function hostBits(): int
    {
        return ($this->isV6 ? 128 : 32) - $this->prefix;
    }

    /** True if the two ranges share at least one address (same family only). */
    public function overlaps(self $other): bool
    {
        return $this->isV6 === $other->isV6
            && strcmp($this->start, $other->end) <= 0
            && strcmp($this->end, $other->start) >= 0;
    }

    /** True if this range lies completely inside $other. */
    public function within(self $other): bool
    {
        return $this->isV6 === $other->isV6
            && strcmp($this->start, $other->start) >= 0
            && strcmp($this->end, $other->end) <= 0;
    }

    /** Canonical text: "192.0.2.10" for a single address, otherwise "network/prefix". */
    public function canonical(): string
    {
        $ip = (string) inet_ntop($this->start);
        return $this->prefix === ($this->isV6 ? 128 : 32) ? $ip : $ip . '/' . $this->prefix;
    }

    /** Bitmask with $prefix leading one-bits, $bytes long. */
    private static function mask(int $prefix, int $bytes): string
    {
        $mask = str_repeat("\xff", intdiv($prefix, 8));
        if ($prefix % 8 !== 0) {
            $mask .= chr((0xff << (8 - $prefix % 8)) & 0xff);
        }
        return str_pad($mask, $bytes, "\x00");
    }
}
