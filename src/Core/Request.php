<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * The current HTTP request.
 *
 * Untrusted: everything here (path, query, form fields, headers) comes from
 * the client. Controllers must validate every value they use.
 *
 * Security assumptions:
 * - The client IP is REMOTE_ADDR. X-Forwarded-For is only honoured when the
 *   direct peer is listed in app.trusted_proxies, because otherwise anyone
 *   could fake their IP and get around login throttling.
 */
final class Request
{
    /**
     * @param array<string,mixed> $query
     * @param array<string,mixed> $post
     * @param array<string,mixed> $server
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        private readonly array $query,
        private readonly array $post,
        private readonly array $server,
        private readonly string $clientIp,
    ) {
    }

    /**
     * Build from PHP superglobals.
     *
     * @param string   $basePath       Configured base path, stripped from the URL path.
     * @param string[] $trustedProxies IPs whose X-Forwarded-For header is believed.
     */
    public static function fromGlobals(string $basePath, array $trustedProxies): self
    {
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $path = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?? '/');
        $path = rawurldecode($path);
        if ($basePath !== '' && str_starts_with($path, $basePath)) {
            $path = substr($path, strlen($basePath));
        }
        if ($path === '' || $path[0] !== '/') {
            $path = '/' . $path;
        }
        // Treat "/users/" the same as "/users".
        if ($path !== '/') {
            $path = rtrim($path, '/');
        }

        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        if (in_array($ip, $trustedProxies, true) && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // The proxy appends the address it saw, so the right-most entry is
            // the one it vouches for.
            $parts = array_map('trim', explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']));
            $candidate = end($parts);
            if (is_string($candidate) && filter_var($candidate, FILTER_VALIDATE_IP)) {
                $ip = $candidate;
            }
        }

        return new self($method, $path, $_GET, $_POST, $_SERVER, $ip);
    }

    /** A form field as a trimmed string ('' if missing or not a string). Untrusted. */
    public function input(string $key): string
    {
        $value = $this->post[$key] ?? '';
        return is_string($value) ? trim($value) : '';
    }

    /** A form field exactly as sent (for passwords: no trimming). Untrusted. */
    public function raw(string $key): string
    {
        $value = $this->post[$key] ?? '';
        return is_string($value) ? $value : '';
    }

    /** A query-string value as a string ('' if missing). Untrusted. */
    public function query(string $key): string
    {
        $value = $this->query[$key] ?? '';
        return is_string($value) ? trim($value) : '';
    }

    /** A request header, e.g. header('X-CSRF-Token'). Untrusted. */
    public function header(string $name): string
    {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        return (string) ($this->server[$key] ?? '');
    }

    /** Client IP (see the class notes on trusted proxies). */
    public function ip(): string
    {
        return $this->clientIp;
    }

    /** True when the request came over HTTPS (directly or through a trusted proxy). */
    public function isSecure(bool $behindTrustedProxy): bool
    {
        if (!empty($this->server['HTTPS']) && $this->server['HTTPS'] !== 'off') {
            return true;
        }
        return $behindTrustedProxy && strtolower((string) ($this->server['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    }

    /** User-Agent header, cut to 255 characters. Untrusted. */
    public function userAgent(): string
    {
        return mb_substr((string) ($this->server['HTTP_USER_AGENT'] ?? ''), 0, 255);
    }
}
