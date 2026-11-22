<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * Adds browser security headers to every response.
 *
 * Security assumptions:
 * - The Content Security Policy allows scripts, styles, fonts and images
 *   from this server only. There are no inline scripts or styles, so
 *   injected markup can't run code.
 * - Pages may not be framed (blocks clickjacking).
 * - Pages are never cached, because they contain client security data.
 *   Static assets are served by the web server, not through here.
 * - HSTS is sent only over HTTPS.
 * - A response may set its OWN, stricter policy (stored reports: no scripts at
 *   all, sandboxed, inline styles only); it is then kept as is.
 */
final class SecurityHeaders
{
    /** Add the headers to a response. HSTS only when $secure. */
    public static function apply(Response $response, bool $secure): Response
    {
        if ($response->getHeader('Content-Security-Policy') === null) {
            $response->header('Content-Security-Policy', implode('; ', [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "object-src 'none'",
                "base-uri 'none'",
                "form-action 'self'",
                "frame-ancestors 'none'",
            ]));
        }
        $response
            ->header('X-Content-Type-Options', 'nosniff')
            ->header('X-Frame-Options', 'DENY')
            ->header('Referrer-Policy', 'same-origin')
            ->header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
            ->header('Cross-Origin-Opener-Policy', 'same-origin')
            ->header('Cache-Control', 'no-store')
            ->header('Pragma', 'no-cache');
        if ($secure) {
            $response->header('Strict-Transport-Security', 'max-age=31536000');
        }
        return $response;
    }
}
