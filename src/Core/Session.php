<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * Wrapper around PHP's native session, with hardened cookie settings.
 *
 * Security assumptions:
 * - The cookie is HttpOnly and SameSite=Lax. It is Secure when the request is
 *   HTTPS, or always when app.force_secure_cookies is on (recommended in production).
 * - Strict mode is on, so PHP refuses session IDs it didn't create (this
 *   blocks session fixation).
 * - The session ID is regenerated at every privilege change (login steps,
 *   logout) by the Auth class.
 * - Session data is server-side. The client only holds a random ID.
 */
final class Session
{
    private const COOKIE_NAME = 'sentinel_session';

    /**
     * Start the session.
     *
     * @param bool   $secure   Send the cookie only over HTTPS.
     * @param string $basePath Cookie path, so several installs on one host don't clash.
     */
    public static function start(bool $secure, string $basePath): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        // Session ID length uses PHP's default (128 bits of randomness). The
        // sid_length/sid_bits ini settings are deprecated in PHP 8.4.
        // Server-side lifetime. Idle and absolute timeouts are also enforced in Auth.
        ini_set('session.gc_maxlifetime', '43200');
        session_name(self::COOKIE_NAME);
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => $basePath === '' ? '/' : $basePath . '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }

    /** Read a session value (server-side data, set only by this app). */
    public static function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    /** Store a session value. Never store secrets that must not live on disk. */
    public static function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
    }

    /** Delete a session value. */
    public static function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    /** New session ID, keeping the data (call at every privilege change). */
    public static function regenerate(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
    }

    /** Wipe all session data and start a clean session with a new ID. */
    public static function reset(): void
    {
        $_SESSION = [];
        self::regenerate();
    }

    /** Store a one-time message shown on the next page. */
    public static function flash(string $type, string $message): void
    {
        $_SESSION['_flash'][] = ['type' => $type, 'message' => $message];
    }

    /**
     * Take all flash messages (and clear them).
     *
     * @return list<array{type:string,message:string}>
     */
    public static function takeFlashes(): array
    {
        $flashes = $_SESSION['_flash'] ?? [];
        unset($_SESSION['_flash']);
        return is_array($flashes) ? $flashes : [];
    }
}
