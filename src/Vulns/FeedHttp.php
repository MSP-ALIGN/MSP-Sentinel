<?php

declare(strict_types=1);

namespace Sentinel\Vulns;

/**
 * Minimal HTTPS GET for public threat feeds (NVD, CISA KEV, FIRST EPSS).
 *
 * Security assumptions:
 * - Only URLs built from configured base URLs are fetched. TLS is verified,
 *   redirects are not followed, there is a timeout, and the body size is capped.
 * - Responses are untrusted. Callers parse JSON with a depth limit and
 *   validate every field.
 * - The optional NVD API key is sent only as a header, never in the URL,
 *   and never logged. The caller only adds it for https or loopback URLs.
 * - HTTP 403/429/503 raise RateLimited, so callers back off (Retry-After honoured).
 */
final class FeedHttp
{
    /** @param int $maxBytes Body size cap. */
    public function __construct(private readonly int $timeout = 60, private readonly int $maxBytes = 50_000_000)
    {
    }

    /**
     * GET a URL and decode its JSON.
     *
     * @param list<string> $headers Extra request headers.
     * @return array<mixed>
     * @throws \RuntimeException on network, HTTP, size or JSON errors (messages never include headers).
     */
    public function getJson(string $url, array $headers = []): array
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!in_array($scheme, ['https', 'http'], true)) {
            throw new \RuntimeException('Feed URL must be http(s).');
        }
        $body = '';
        $tooBig = false;
        $max = $this->maxBytes;
        $retryAfter = null;
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_USERAGENT => 'MSP-Sentinel (self-hosted)',
            CURLOPT_HTTPHEADER => array_merge(['Accept: application/json'], $headers),
            CURLOPT_ENCODING => '', // accept gzip
            CURLOPT_NOPROXY => 'localhost,127.0.0.1,::1', // a configured proxy is used for the public feeds, never for local addresses
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$retryAfter): int {
                if (preg_match('/^retry-after:\s*(\d{1,6})\s*$/i', $line, $m)) {
                    $retryAfter = (int) $m[1];
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$tooBig, $max): int {
                if (strlen($body) + strlen($chunk) > $max) {
                    $tooBig = true;
                    return 0;
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
            throw new \RuntimeException('Feed response was too large.');
        }
        if ($ok === false) {
            throw new \RuntimeException('Feed could not be reached: ' . mb_substr($error, 0, 200));
        }
        if (in_array($status, [403, 429, 503], true)) {
            // Rate limited or temporarily unavailable: callers back off instead of retrying.
            throw new RateLimited('Feed returned HTTP ' . $status . ' (rate limit or maintenance).', min(max($retryAfter ?? 60, 30), 3600));
        }
        if ($status !== 200) {
            throw new \RuntimeException('Feed returned HTTP ' . $status . '.');
        }
        $data = json_decode($body, true, 64);
        if (!is_array($data)) {
            throw new \RuntimeException('Feed returned something that is not JSON.');
        }
        return $data;
    }
}
