<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

/**
 * CPE (Common Platform Enumeration) handling: turns nmap's CPE 2.2 URIs
 * ("cpe:/a:openbsd:openssh:8.9p1") into NVD CPE 2.3 match strings
 * ("cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*").
 *
 * Security assumptions: the input comes from a scanned host's banner, via
 * nmap, so it is UNTRUSTED. Only strictly valid components are accepted
 * (lower-case letters, digits and a few punctuation characters). Anything
 * else returns null, so nothing strange reaches the NVD URL or the database.
 */
final class Cpe
{
    /**
     * Parse an nmap CPE.
     *
     * @return array{part:string,vendor:string,product:string,version:string}|null Null if invalid or not useful.
     */
    public static function parse(string $uri): ?array
    {
        if (!str_starts_with($uri, 'cpe:/') || strlen($uri) > 200) {
            return null;
        }
        $parts = explode(':', substr($uri, 5));
        $part = $parts[0] ?? '';
        $vendor = strtolower($parts[1] ?? '');
        $product = strtolower($parts[2] ?? '');
        $version = strtolower($parts[3] ?? '');
        if (!in_array($part, ['a', 'o', 'h'], true)) {
            return null;
        }
        foreach ([$vendor, $product] as $c) {
            // "!" and "+" occur in real NVD products (joomla:joomla!, notepad-plus-plus:notepad++); esc() escapes them.
            if (!preg_match('/^[a-z0-9][a-z0-9._\-~!+]{0,99}$/D', $c)) {
                return null;
            }
        }
        if ($version !== '' && !preg_match('/^[a-z0-9][a-z0-9._\-~+]{0,49}$/D', $version)) {
            $version = ''; // a garbled version is treated as unknown, never guessed
        }
        // Operating system and hardware CPEs without a version are too vague to be useful.
        if ($part !== 'a' && $version === '') {
            return null;
        }
        return ['part' => $part, 'vendor' => $vendor, 'product' => $product, 'version' => $version];
    }

    /**
     * NVD virtualMatchString for a parsed CPE (components escaped as CPE 2.3
     * requires). With a version, NVD matches exact versions and version
     * ranges. Without one, it matches any version of the product.
     *
     * @param array{part:string,vendor:string,product:string,version:string} $cpe
     */
    public static function matchString(array $cpe): string
    {
        $base = 'cpe:2.3:' . $cpe['part'] . ':' . self::esc($cpe['vendor']) . ':' . self::esc($cpe['product']);
        return $cpe['version'] === '' ? $base : $base . ':' . self::esc($cpe['version']);
    }

    /**
     * All match strings worth asking NVD. Versions like "8.9p1" are often
     * listed by NVD as version "8.9" with update "p1", so both forms are
     * asked and the answers combined.
     *
     * @param array{part:string,vendor:string,product:string,version:string} $cpe
     * @return list<string>
     */
    public static function matchStrings(array $cpe): array
    {
        $out = [self::matchString($cpe)];
        if (preg_match('/^(\d+(?:\.\d+)*)(p\d+)$/D', $cpe['version'], $m)) {
            $out[] = 'cpe:2.3:' . $cpe['part'] . ':' . self::esc($cpe['vendor']) . ':' . self::esc($cpe['product']) . ':' . $m[1] . ':' . $m[2];
        }
        return $out;
    }

    /** vendor:product prefix of a match string ("cpe:2.3:a:openbsd:openssh:"), used to check NVD's "vulnerable" flags. */
    public static function productPrefix(string $matchString): string
    {
        $parts = explode(':', $matchString);
        return implode(':', array_slice($parts, 0, 5)) . ':';
    }

    /** Escape a component for a CPE 2.3 formatted string: anything but letters, digits, "_", "-" and "." gets a backslash. */
    private static function esc(string $component): string
    {
        return (string) preg_replace('/([^a-z0-9_.\-])/', '\\\\$1', $component);
    }

    /** True if a string looks like a CVE ID (CVE-YYYY-NNNN...). */
    public static function isCveId(string $id): bool
    {
        return preg_match('/^CVE-(19|20)\d{2}-\d{4,7}$/D', $id) === 1;
    }
}
