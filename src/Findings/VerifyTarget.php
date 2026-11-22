<?php

declare(strict_types=1);

namespace Sentinel\Findings;

/**
 * What a "verify fix" recheck must touch for one finding: one address and
 * port (exposed services, certificates, web pages, website checks and
 * vulnerabilities), or one domain (email records).
 *
 * The finding key is built by FindingsEngine from scan data; it is parsed
 * here with fixed rules (the port is a fixed number of segments from the
 * end, so IPv6 addresses with colons work) and the result is validated
 * (a real IP and port, or a plain domain name). Long keys that were hashed
 * can't be parsed and are not verifiable one by one.
 *
 * Security assumptions: this only says what the finding is about. The
 * caller must still check the client's active scope, pause and kill switch,
 * and the worker checks them again before touching anything.
 */
final class VerifyTarget
{
    /** Segments after the port, by key prefix: "tls:{ip}:{port}:{sni}:{code}" has 2. */
    private const AFTER_PORT = ['port' => 0, 'tls' => 2, 'web' => 1, 'site' => 1, 'vuln' => 1, 'webvuln' => 2];

    /**
     * Parse a finding key.
     *
     * @return array{kind:'endpoint', ip:string, port:int}|array{kind:'email', domain:string}|null
     */
    public static function fromKey(string $key): ?array
    {
        if (str_contains($key, '#')) {
            return null; // shortened long key
        }
        $parts = explode(':', $key);
        $prefix = array_shift($parts);
        if ($prefix === 'email') {
            $domain = strtolower((string) ($parts[0] ?? ''));
            return count($parts) === 2 && preg_match('/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain) === 1
                ? ['kind' => 'email', 'domain' => $domain] : null;
        }
        if (!isset(self::AFTER_PORT[$prefix])) {
            return null;
        }
        $after = self::AFTER_PORT[$prefix];
        if (count($parts) < 2 + $after) {
            return null;
        }
        $port = $parts[count($parts) - 1 - $after];
        $ip = implode(':', array_slice($parts, 0, count($parts) - 1 - $after));
        if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535 || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        return ['kind' => 'endpoint', 'ip' => $ip, 'port' => (int) $port];
    }
}
