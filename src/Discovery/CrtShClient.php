<?php

declare(strict_types=1);

namespace Sentinel\Discovery;

use Sentinel\Core\Config;
use Sentinel\Scope\ScopeService;

/**
 * Looks up hostnames in public Certificate Transparency logs through crt.sh
 * (free JSON interface).
 *
 * Security assumptions:
 * - Only the configured base URL (crtsh.base_url, default https://crt.sh) is
 *   contacted, over HTTPS with certificate verification on, with a timeout
 *   and a response size cap. Redirects are not followed.
 * - The JSON is untrusted. Only the name_value field is read, and every name
 *   is normalised and validated (canonical hostname under the queried
 *   domain) before it is returned.
 * - The query only reveals the client's domain name to crt.sh, which is public
 *   information. Nothing touches the client's systems.
 */
final class CrtShClient
{
    private const MAX_BYTES = 10 * 1024 * 1024;
    private const MAX_NAMES = 2000;

    /** Use fromConfig() normally. $baseUrl has no trailing slash. */
    public function __construct(private readonly string $baseUrl, private readonly int $timeout = 30)
    {
        $scheme = parse_url($baseUrl, PHP_URL_SCHEME);
        if (!in_array($scheme, ['https', 'http'], true)) {
            throw new \InvalidArgumentException('crt.sh base URL must be http(s).');
        }
    }

    /** Build from config: crtsh.base_url, crtsh.timeout. Returns null when crtsh.enabled is false. */
    public static function fromConfig(Config $config): ?self
    {
        if ($config->get('crtsh.enabled', true) === false) {
            return null;
        }
        return new self(rtrim((string) $config->get('crtsh.base_url', 'https://crt.sh'), '/'), (int) $config->get('crtsh.timeout', 30));
    }

    /**
     * Hostnames seen in certificates for $domain and its subdomains.
     *
     * @param string   $domain    Canonical domain from the client's scope.
     * @param int|null $timeoutMs Overall time limit for this call (to fit a caller's budget). Null uses the configured timeout.
     * @return list<string> Canonical hostnames equal to or under $domain (wildcard labels removed).
     * @throws \RuntimeException on network errors, HTTP errors, oversized or invalid responses.
     */
    public function hostnames(string $domain, ?int $timeoutMs = null): array
    {
        $timeoutMs = max(1000, min($timeoutMs ?? $this->timeout * 1000, $this->timeout * 1000));
        $url = $this->baseUrl . '/?' . http_build_query(['q' => '%.' . $domain, 'output' => 'json']);
        $body = '';
        $tooBig = false;
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => min(10000, $timeoutMs),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_USERAGENT => 'MSP-Sentinel (self-hosted)',
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$tooBig): int {
                if (strlen($body) + strlen($chunk) > self::MAX_BYTES) {
                    $tooBig = true;
                    return 0; // abort the transfer
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        if ($tooBig) {
            throw new \RuntimeException('crt.sh response was too large.');
        }
        if ($ok === false) {
            throw new \RuntimeException('crt.sh could not be reached: ' . mb_substr($error, 0, 200));
        }
        if ($status !== 200) {
            throw new \RuntimeException('crt.sh returned HTTP ' . $status . '.');
        }
        return self::parse($body, $domain);
    }

    /**
     * Extract hostnames from a crt.sh JSON response (public for unit tests).
     *
     * @param string $json Untrusted.
     * @return list<string>
     */
    public static function parse(string $json, string $domain): array
    {
        $data = json_decode($json, true, 8);
        if (!is_array($data)) {
            throw new \RuntimeException('crt.sh returned something that is not JSON.');
        }
        $names = [];
        foreach ($data as $row) {
            if (!is_array($row) || !is_string($row['name_value'] ?? null)) {
                continue;
            }
            foreach (preg_split('/\s+/', $row['name_value']) ?: [] as $raw) {
                $raw = strtolower(trim($raw));
                if (str_starts_with($raw, '*.')) {
                    $raw = substr($raw, 2);
                }
                $host = ScopeService::canonicalTarget($raw);
                if ($host === null || filter_var($host, FILTER_VALIDATE_IP) !== false) {
                    continue;
                }
                if ($host !== $domain && !str_ends_with($host, '.' . $domain)) {
                    continue; // certificates often list unrelated names too
                }
                $names[$host] = true;
                if (count($names) >= self::MAX_NAMES) {
                    break 2;
                }
            }
        }
        ksort($names);
        return array_keys($names);
    }
}
