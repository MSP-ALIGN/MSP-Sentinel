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
 *   all, sandboxed, inline styles only). It is kept only if it has
 *   default-src 'none', sandbox and no script-src; otherwise the app policy
 *   replaces it, so a handler can never weaken the policy by accident.
 */
final class SecurityHeaders
{
    /**
     * Microsoft's sign-in origin for form-action (1.63.1): the real one, or in the test suite its mock's (a plain
     * 127.0.0.1 address, so the browser tests can follow the same redirect).
     */
    private static function microsoftOrigin(): string
    {
        if (App::webhookTestMode()) {
            $p = parse_url((string) App::config()->get('testing.entra_authority', ''));
            if (is_array($p) && ($p['host'] ?? '') === '127.0.0.1' && isset($p['port'])) {
                return 'http://127.0.0.1:' . (int) $p['port'];
            }
        }
        return \Sentinel\Auth\EntraSso::DEFAULT_AUTHORITY;
    }

    /** Add the headers to a response. HSTS only when $secure. */
    public static function apply(Response $response, bool $secure): Response
    {
        $own = $response->getHeader('Content-Security-Policy');
        // Only a locked-down document policy may replace the app's (no default sources, sandboxed). Anything else is overwritten.
        if ($own === null || !str_contains($own, "default-src 'none'") || !preg_match('/(^|;)\s*sandbox\s*(;|$)/', $own) || str_contains($own, 'script-src')) {
            $response->header('Content-Security-Policy', implode('; ', [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "object-src 'none'",
                "base-uri 'none'",
                // 1.63.1: forms may also lead to Microsoft's sign-in. "Link my Microsoft account" is a form (it asks for the
                // password) that ends in a redirect to Microsoft, and browsers apply form-action to that redirect too.
                "form-action 'self' " . self::microsoftOrigin(),
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
