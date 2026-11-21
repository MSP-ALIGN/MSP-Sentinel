<?php

declare(strict_types=1);

namespace Sentinel\Auth;

/**
 * Password hashing and the password policy.
 *
 * Security assumptions:
 * - Argon2id is used when PHP supports it, otherwise bcrypt. Hashes carry
 *   their algorithm, so needsRehash() upgrades old hashes at login.
 * - The policy follows current guidance: a long minimum length, no
 *   composition rules, and no password equal to the username. An upper
 *   limit stops very long inputs from wasting CPU.
 */
final class Passwords
{
    public const MIN_LENGTH = 12;
    public const MAX_LENGTH = 256;

    /** Hash a password for storage. $password is untrusted and already policy-checked. */
    public static function hash(string $password): string
    {
        return password_hash($password, self::algorithm());
    }

    /** Constant-time check of an untrusted password against a stored hash. */
    public static function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /** True if the hash uses an older algorithm or cost and should be upgraded at login. */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, self::algorithm());
    }

    /**
     * Burn the same time as a real check when the user doesn't exist, so
     * response timing doesn't reveal which usernames are valid.
     */
    public static function verifyDummy(string $password): void
    {
        // Fixed hashes (of a public, meaningless string) with the same cost settings as
        // real hashes. A hash created at runtime would add a second, slower hashing step
        // for unknown users and give them away by timing.
        password_verify($password, self::algorithm() === PASSWORD_BCRYPT ? self::DUMMY_BCRYPT : self::DUMMY_ARGON2ID);
    }

    private const DUMMY_ARGON2ID = '$argon2id$v=19$m=65536,t=4,p=1$S1lUbGM3VzlUL251MVNFaA$ez78oh9dxCD0+a7L4TNvHLUkzoXK9yB+Ti1aNQHoH68';
    private const DUMMY_BCRYPT = '$2y$10$coOlju6Bhroyg.jWvQPrUubdLj2QLws0nH3sSZE1xkGm8Jp7b1H0a';

    /**
     * Check a new password against the policy.
     *
     * @param string $password Untrusted.
     * @param string $username Used to reject "password = username".
     * @return string|null Error message for the user, or null if acceptable.
     */
    public static function policyError(string $password, string $username): ?string
    {
        $length = mb_strlen($password);
        if ($length < self::MIN_LENGTH) {
            return __('Password must be at least {n} characters.', ['n' => self::MIN_LENGTH]);
        }
        if ($length > self::MAX_LENGTH) {
            return __('Password must be at most {n} characters.', ['n' => self::MAX_LENGTH]);
        }
        // bcrypt (only used when PHP lacks Argon2id) silently ignores bytes after 72.
        if (self::algorithm() === PASSWORD_BCRYPT && strlen($password) > 72) {
            return __('Password must be at most 72 bytes on this server.');
        }
        if (strcasecmp($password, $username) === 0) {
            return __('Password must not be the same as the username.');
        }
        return null;
    }

    /** Argon2id when available, otherwise bcrypt. */
    private static function algorithm(): string
    {
        return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    }
}
