<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * CSRF protection using a synchroniser token per session.
 *
 * The kernel checks EVERY state-changing request (POST, PUT, PATCH, DELETE)
 * before routing reaches a controller, so no route can forget the check.
 *
 * Security assumptions:
 * - The token is 32 random bytes, kept in the server-side session.
 * - It is compared in constant time.
 * - A new token is issued whenever the session ID changes (login and logout),
 *   so a token seen before login is useless after it.
 */
final class Csrf
{
    public const FIELD = '_csrf';
    private const SESSION_KEY = '_csrf_token';

    /** The current token, created if missing. Safe to print in a hidden field. */
    public static function token(): string
    {
        $token = Session::get(self::SESSION_KEY);
        if (!is_string($token) || strlen($token) !== 64) {
            $token = bin2hex(random_bytes(32));
            Session::set(self::SESSION_KEY, $token);
        }
        return $token;
    }

    /** Replace the token (after login or logout). */
    public static function rotate(): void
    {
        Session::set(self::SESSION_KEY, bin2hex(random_bytes(32)));
    }

    /**
     * Check a submitted token.
     *
     * @param string $submitted Untrusted value from the form field or the X-CSRF-Token header.
     */
    public static function isValid(string $submitted): bool
    {
        $expected = Session::get(self::SESSION_KEY);
        return is_string($expected) && $submitted !== '' && hash_equals($expected, $submitted);
    }

    /** Hidden input for forms, already escaped. */
    public static function field(): string
    {
        return '<input type="hidden" name="' . self::FIELD . '" value="' . e(self::token()) . '">';
    }
}
