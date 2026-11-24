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
        private readonly array $files = [],
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

        return new self($method, $path, $_GET, $_POST, $_SERVER, $ip, $_FILES);
    }

    /**
     * An uploaded file's temporary path, or null if none was uploaded without
     * error. Only files PHP itself received (is_uploaded_file) are returned.
     * The content is untrusted.
     */
    public function uploadedFile(string $key): ?string
    {
        $f = $this->files[$key] ?? null;
        if (!is_array($f) || !is_string($f['tmp_name'] ?? null) || ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'])) {
            return null;
        }
        return $f['tmp_name'];
    }

    /** The name the browser gave an uploaded file ('' if none). Untrusted: sanitise before storing or showing. */
    public function uploadedName(string $key): string
    {
        $f = $this->files[$key] ?? null;
        return is_array($f) && is_string($f['name'] ?? null) ? $f['name'] : '';
    }

    /** The upload error code for a file field (UPLOAD_ERR_NO_FILE if none was sent). */
    public function uploadError(string $key): int
    {
        $f = $this->files[$key] ?? null;
        return is_array($f) && is_int($f['error'] ?? null) ? $f['error'] : UPLOAD_ERR_NO_FILE;
    }

    /**
     * The request body parsed as a JSON object (API), or null if it is missing,
     * larger than 64 KB, or not a JSON object. Untrusted.
     *
     * @return array<string,mixed>|null
     */
    public function jsonBody(): ?array
    {
        $raw = (string) file_get_contents('php://input', false, null, 0, 65537);
        if ($raw === '' || strlen($raw) > 65536) {
            return null;
        }
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        return is_array($data) && !array_is_list($data) ? $data : null;
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

    /**
     * A form field sent as a list (name="clients[]"): its string values, trimmed. Untrusted.
     *
     * @return list<string>
     */
    public function postList(string $key): array
    {
        $value = $this->post[$key] ?? [];
        if (!is_array($value)) {
            return [];
        }
        return array_values(array_map('trim', array_filter($value, 'is_string')));
    }

    /**
     * A repeated query parameter (?id[]=1&id[]=2) as a list of strings. Non-string items are dropped. Untrusted.
     *
     * @return list<string>
     */
    public function queryList(string $key): array
    {
        $value = $this->query[$key] ?? [];
        if (!is_array($value)) {
            return [];
        }
        return array_values(array_map('trim', array_filter($value, 'is_string')));
    }

    /** A request header, e.g. header('X-CSRF-Token'). Untrusted. */
    public function header(string $name): string
    {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        // Apache with CGI/FastCGI can pass Authorization only as REDIRECT_HTTP_AUTHORIZATION.
        return (string) ($this->server[$key] ?? ($key === 'HTTP_AUTHORIZATION' ? ($this->server['REDIRECT_HTTP_AUTHORIZATION'] ?? '') : ''));
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
