<?php

declare(strict_types=1);

namespace Sentinel\Agent;

/**
 * Internal network ranges an agent may scan: single addresses or CIDR
 * networks inside private address space only (10.0.0.0/8, 172.16.0.0/12,
 * 192.168.0.0/16, 100.64.0.0/10 and IPv6 fc00::/7). Public addresses belong
 * in the external authorisation, never here.
 *
 * Size limits keep scans gentle: an IPv4 network may be at most a /16
 * (65,536 addresses), IPv6 at most a /112, and one authorisation at most
 * 262,144 IPv4 addresses in total.
 *
 * This class has no dependencies, so the agent program uses the same
 * checks to refuse any job target outside its signed authorisation.
 *
 * Untrusted: the text admins type, and job targets received by the agent.
 */
final class InternalRanges
{
    public const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7'];
    public const MAX_PREFIX_V4 = 16;
    public const MAX_PREFIX_V6 = 112;
    public const MAX_TOTAL_V4 = 262144;
    public const MAX_ENTRIES = 64;

    /**
     * Parse lines (one address or CIDR each; blank lines and # comments ignored).
     *
     * @return array{ranges:list<string>, errors:list<string>} ranges in canonical CIDR form ("10.1.0.0/16", "10.1.2.3/32").
     */
    public static function parseLines(string $text): array
    {
        $ranges = [];
        $errors = [];
        $total = 0;
        foreach (preg_split('/\R/', $text) ?: [] as $n => $line) {
            $line = trim((string) preg_replace('/#.*$/', '', $line));
            if ($line === '') {
                continue;
            }
            $r = self::parse($line);
            if (isset($r['error'])) {
                $errors[] = 'Line ' . ($n + 1) . ': ' . $r['error'];
                continue;
            }
            $r = $r['cidr'];
            if (!str_contains($r, ':')) {
                $total += 2 ** (32 - (int) explode('/', $r)[1]);
            }
            $ranges[$r] = true;
        }
        if (count($ranges) > self::MAX_ENTRIES) {
            $errors[] = 'At most ' . self::MAX_ENTRIES . ' ranges per authorisation.';
        }
        if ($total > self::MAX_TOTAL_V4) {
            $errors[] = 'Too many addresses in total (at most ' . self::MAX_TOTAL_V4 . ', for example four /16 networks).';
        }
        return ['ranges' => array_keys($ranges), 'errors' => $errors];
    }

    /**
     * One address or CIDR.
     *
     * @return array{cidr:string}|array{error:string} The canonical CIDR, or why it isn't allowed.
     */
    public static function parse(string $text): array
    {
        $text = trim($text);
        if (!preg_match('#^([0-9a-fA-F:.]{2,39})(?:/(\d{1,3}))?$#', $text, $m)) {
            return ['error' => '"' . mb_substr($text, 0, 60) . '" is not an IP address or network.'];
        }
        $bin = @inet_pton($m[1]);
        if ($bin === false) {
            return ['error' => '"' . mb_substr($text, 0, 60) . '" is not an IP address or network.'];
        }
        $bits = strlen($bin) * 8;
        $prefix = isset($m[2]) ? (int) $m[2] : $bits;
        if ($prefix > $bits) {
            return ['error' => '"' . mb_substr($text, 0, 60) . '": the prefix is too long.'];
        }
        if ($prefix < ($bits === 32 ? self::MAX_PREFIX_V4 : self::MAX_PREFIX_V6)) {
            return ['error' => '"' . mb_substr($text, 0, 60) . '" is too large: split it into networks of at most /' . ($bits === 32 ? self::MAX_PREFIX_V4 : self::MAX_PREFIX_V6) . '.'];
        }
        $network = self::mask($bin, $prefix);
        if ($network !== $bin) {
            return ['error' => '"' . mb_substr($text, 0, 60) . '" has host bits set: use ' . inet_ntop($network) . '/' . $prefix . '.'];
        }
        $cidr = inet_ntop($network) . '/' . $prefix;
        foreach (self::PRIVATE as $private) {
            if (self::within($cidr, $private)) {
                return ['cidr' => $cidr];
            }
        }
        return ['error' => '"' . mb_substr($text, 0, 60) . '" is not a private (internal) address. Internet addresses belong in the external authorisation.'];
    }

    /** True if the address or CIDR $inner lies completely inside the CIDR $outer. */
    public static function within(string $inner, string $outer): bool
    {
        [$ia, $ip] = array_pad(explode('/', $inner, 2), 2, null);
        [$oa, $op] = array_pad(explode('/', $outer, 2), 2, null);
        $ib = @inet_pton((string) $ia);
        $ob = @inet_pton((string) $oa);
        if ($ib === false || $ob === false || strlen($ib) !== strlen($ob)) {
            return false;
        }
        $bits = strlen($ib) * 8;
        $ip = $ip === null ? $bits : (int) $ip;
        $op = $op === null ? $bits : (int) $op;
        return $ip >= $op && $op <= $bits && self::mask($ib, $op) === self::mask($ob, $op);
    }

    /**
     * True if every target (address or CIDR) lies inside one of the ranges.
     *
     * @param list<string> $targets
     * @param list<string> $ranges
     */
    public static function allWithin(array $targets, array $ranges): bool
    {
        foreach ($targets as $t) {
            $ok = false;
            foreach ($ranges as $r) {
                if (self::within((string) $t, (string) $r)) {
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                return false;
            }
        }
        return true;
    }

    /** The binary address with all bits after $prefix set to zero. */
    private static function mask(string $bin, int $prefix): string
    {
        $out = '';
        for ($i = 0, $n = strlen($bin); $i < $n; $i++) {
            $bits = max(0, min(8, $prefix - $i * 8));
            $out .= chr(ord($bin[$i]) & (0xFF << (8 - $bits)) & 0xFF);
        }
        return $out;
    }
}
