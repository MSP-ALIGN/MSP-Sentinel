<?php

declare(strict_types=1);

namespace Sentinel\Scope;

/**
 * Parses and validates scope entries typed by an admin: one IP, CIDR block or
 * domain per line.
 *
 * Accepted:
 * - single public IPv4/IPv6 addresses
 * - public CIDR blocks no larger than /24 (IPv4) or /120 (IPv6), written as
 *   the network address
 * - domain names (ASCII or punycode), optionally with a leading "*." to cover
 *   all subdomains (the bare domain must then be listed separately)
 *
 * Refused (v1.0 scans only from outside, so only public targets make sense):
 * private, loopback, link-local, CGNAT, multicast, reserved and documentation
 * ranges, plus reserved or internal-only top-level domains.
 * IPv6 uses an allowlist: only global unicast (2000::/3) is accepted, then the
 * blocklist applies. That shuts out IPv4-compatible (::10.0.0.1), translated,
 * site-local, unallocated and other special forms in one rule.
 * Wildcards and entries on public suffixes (co.uk, github.io, ...) are refused:
 * "*.github.io" would put every site on that platform in scope.
 *
 * Security assumptions:
 * - Every line is untrusted. Only the canonical form produced here is ever
 *   stored, never the raw text.
 * - Documentation ranges (192.0.2.0/24 etc.) and example domains are only
 *   accepted when $allowDocumentation is true. That is used by the test
 *   suite, which must never use real addresses. It is off in production.
 */
final class ScopeParser
{
    public const MAX_ENTRIES = 256;
    private const MAX_HOST_BITS_V4 = 8;   // /24
    private const MAX_HOST_BITS_V6 = 8;   // /120

    /** Always refused: special-purpose ranges (IANA registries) that are never valid external targets. */
    private const RESERVED = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
        '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23',
        '2002::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8',
    ];

    /** The only IPv6 space that holds public unicast addresses. */
    private const IPV6_GLOBAL_UNICAST = '2000::/3';

    /**
     * Shared public suffixes: names under them belong to many unrelated owners.
     * A small built-in list of common ones (no external public suffix list is downloaded).
     */
    private const PUBLIC_SUFFIXES = [
        'github.io', 'gitlab.io', 'azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'azureedge.net', 'trafficmanager.net',
        'core.windows.net', 'blob.core.windows.net', 'onmicrosoft.com', 'sharepoint.com', 'herokuapp.com', 'appspot.com', 'blogspot.com',
        'amazonaws.com', 'cloudfront.net', 'elasticbeanstalk.com', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
        'web.app', 'firebaseapp.com', 'wordpress.com', 'myshopify.com', 'wixsite.com', 'squarespace.com', 'duckdns.org',
        'no-ip.com', 'ddns.net', 'dyndns.org', 'synology.me', 'myqnapcloud.com',
    ];
    /** Second-level labels used as public suffixes under country TLDs (co.uk, com.au, ...). */
    private const CC_SECOND_LEVELS = ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'ltd', 'plc', 'or', 'ne', 'go', 'mil', 'nhs', 'sch', 'gen', 'biz', 'info'];

    /** Documentation ranges: refused in production, allowed for tests. */
    private const DOCUMENTATION = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32', '3fff::/20'];

    /** Top-level domains that never point at a client's public systems. */
    private const RESERVED_TLDS = ['test', 'invalid', 'localhost', 'local', 'internal', 'lan', 'home', 'corp', 'onion', 'alt', 'localdomain', 'intranet', 'private'];
    private const DOCUMENTATION_DOMAINS = ['example', 'example.com', 'example.net', 'example.org'];

    /** @var list<IpRange>|null */
    private static ?array $reservedRanges = null;
    /** @var list<IpRange>|null */
    private static ?array $docRanges = null;

    /** @param bool $allowDocumentation Accept documentation ranges and example domains (tests only). */
    public function __construct(private readonly bool $allowDocumentation = false)
    {
    }

    /**
     * Parse a block of text, one entry per line. Blank lines and "#" comments are ignored.
     *
     * @param string $text Untrusted textarea input.
     * @return array{entries: list<array{type:string,value:string,range:?IpRange}>, errors: list<string>}
     */
    public function parseLines(string $text): array
    {
        $entries = [];
        $errors = [];
        $seen = [];
        $lines = preg_split('/\R/', $text) ?: [];
        foreach ($lines as $i => $line) {
            $line = trim((string) preg_replace('/#.*$/', '', $line));
            if ($line === '') {
                continue;
            }
            $result = $this->parse($line);
            if (is_string($result)) {
                $errors[] = __('Line {n} ("{text}"): {error}', ['n' => $i + 1, 'text' => mb_substr($line, 0, 80), 'error' => $result]);
                continue;
            }
            if (isset($seen[$result['value']])) {
                continue; // duplicates are harmless; keep one
            }
            $seen[$result['value']] = true;
            $entries[] = $result;
        }
        if ($entries === [] && $errors === []) {
            $errors[] = __('Enter at least one IP address, range or domain.');
        }
        if (count($entries) > self::MAX_ENTRIES) {
            $errors[] = __('At most {n} entries per authorisation. Split large scopes into several authorisations.', ['n' => self::MAX_ENTRIES]);
        }
        return ['entries' => $entries, 'errors' => $errors];
    }

    /**
     * Parse a single entry.
     *
     * @param string $text Untrusted, already trimmed.
     * @return array{type:string,value:string,range:?IpRange}|string The entry, or an error message.
     */
    public function parse(string $text): array|string
    {
        if (strlen($text) > 260) {
            return __('Too long.');
        }
        if (preg_match('/^[0-9.]+(\/\d+)?$/', $text) || str_contains($text, ':')) {
            return $this->parseIp($text);
        }
        return $this->parseDomain($text);
    }

    /** @return array{type:string,value:string,range:IpRange}|string */
    private function parseIp(string $text): array|string
    {
        $range = IpRange::parse($text);
        if ($range === null) {
            return str_contains($text, '/')
                ? __('Not a valid range. Use the network address, e.g. 198.51.100.0/24.')
                : __('Not a valid IP address.');
        }
        $maxBits = $range->isV6 ? self::MAX_HOST_BITS_V6 : self::MAX_HOST_BITS_V4;
        if ($range->hostBits() > $maxBits) {
            return $range->isV6 ? __('Range too large. The largest allowed is /120.') : __('Range too large. The largest allowed is /24.');
        }
        if ($range->isV6 && !$range->within(IpRange::parse(self::IPV6_GLOBAL_UNICAST))) {
            return __('Private, internal or reserved addresses cannot be scanned from outside. Approve internal networks per site on the client\'s Agents page (on-premises agent).');
        }
        foreach (self::reservedRanges() as $reserved) {
            if ($range->overlaps($reserved)) {
                return __('Private, internal or reserved addresses cannot be scanned from outside. Approve internal networks per site on the client\'s Agents page (on-premises agent).');
            }
        }
        if (!$this->allowDocumentation) {
            foreach (self::docRanges() as $doc) {
                if ($range->overlaps($doc)) {
                    return __('This is a documentation range, not a real address.');
                }
            }
        }
        return ['type' => $range->hostBits() === 0 ? 'ip' : 'cidr', 'value' => $range->canonical(), 'range' => $range];
    }

    /** @return array{type:string,value:string,range:null}|string */
    private function parseDomain(string $text): array|string
    {
        $domain = strtolower(rtrim($text, '.'));
        $wildcard = str_starts_with($domain, '*.');
        $host = $wildcard ? substr($domain, 2) : $domain;
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$/D', $host)) {
            return __('Not a valid domain name. Use letters, digits and hyphens (punycode for international names), e.g. www.client-domain.com.');
        }
        $labels = explode('.', $host);
        $tld = end($labels);
        if (in_array($tld, self::RESERVED_TLDS, true) || str_ends_with($host, '.home.arpa') || $tld === 'arpa') {
            return __('This is an internal or reserved domain, not a public one.');
        }
        if (self::isPublicSuffix($host)) {
            return __('This is a shared public suffix (like co.uk or github.io), not a single organisation\'s domain. List the client\'s own names under it instead.');
        }
        // A wildcard under a shared platform (*.s3.amazonaws.com, *.region.cloudapp.azure.com) would take in other
        // customers' names; only exact names (the client's own app.azurewebsites.net) are accepted there (1.34 audit).
        if ($wildcard && self::underPublicSuffix($host)) {
            return __('A wildcard under a shared platform domain would include other organisations\' names. List the client\'s own names under it one by one instead.');
        }
        if (!$this->allowDocumentation) {
            $lastTwo = implode('.', array_slice($labels, -2));
            if (in_array($tld, self::DOCUMENTATION_DOMAINS, true) || in_array($lastTwo, self::DOCUMENTATION_DOMAINS, true)) {
                return __('This is an example domain, not a real one.');
            }
        }
        return ['type' => 'domain', 'value' => $wildcard ? '*.' . $host : $host, 'range' => null];
    }

    /**
     * True if $host is itself a public suffix: a known shared platform domain,
     * or a "co.uk"-style second level under a 2-letter country TLD.
     */
    public static function isPublicSuffix(string $host): bool
    {
        if (in_array($host, self::PUBLIC_SUFFIXES, true)) {
            return true;
        }
        $labels = explode('.', $host);
        return count($labels) === 2 && strlen($labels[1]) === 2 && in_array($labels[0], self::CC_SECOND_LEVELS, true);
    }

    /** True if $host is below one of the shared platform suffixes (not counting country second levels). */
    public static function underPublicSuffix(string $host): bool
    {
        foreach (self::PUBLIC_SUFFIXES as $suffix) {
            if (str_ends_with($host, '.' . $suffix)) {
                return true;
            }
        }
        return false;
    }

    /** @return list<IpRange> */
    private static function reservedRanges(): array
    {
        return self::$reservedRanges ??= array_map(static fn (string $c): IpRange => IpRange::parse($c), self::RESERVED);
    }

    /** @return list<IpRange> */
    private static function docRanges(): array
    {
        return self::$docRanges ??= array_map(static fn (string $c): IpRange => IpRange::parse($c), self::DOCUMENTATION);
    }
}
