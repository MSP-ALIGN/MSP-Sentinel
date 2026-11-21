<?php

declare(strict_types=1);

namespace Sentinel\Auth;

/**
 * User roles and their ranking.
 *
 * - viewer:     read-only access.
 * - technician: viewer, plus running scans and triaging findings (later releases).
 * - admin:      everything, including users, settings, API tokens and approving scan scope.
 *
 * Security assumptions: the role is always read fresh from the database on
 * each request (see Auth::user()), never trusted from the session, so a
 * demotion takes effect straight away.
 */
final class Role
{
    public const VIEWER = 'viewer';
    public const TECHNICIAN = 'technician';
    public const ADMIN = 'admin';

    private const RANK = [self::VIEWER => 1, self::TECHNICIAN => 2, self::ADMIN => 3];

    /** True for the three known role names. $role may be untrusted. */
    public static function isValid(string $role): bool
    {
        return isset(self::RANK[$role]);
    }

    /** True when $role is at least as powerful as $required. Unknown roles get nothing. */
    public static function atLeast(string $role, string $required): bool
    {
        return isset(self::RANK[$role], self::RANK[$required]) && self::RANK[$role] >= self::RANK[$required];
    }

    /** @return array<string,string> role => human label, for forms. */
    public static function labels(): array
    {
        return [
            self::ADMIN => __('Admin'),
            self::TECHNICIAN => __('Technician'),
            self::VIEWER => __('Viewer'),
        ];
    }
}
