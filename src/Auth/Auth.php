<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use Sentinel\Core\Audit;
use Sentinel\Core\Csrf;
use Sentinel\Core\RateLimiter;
use Sentinel\Core\Request;
use Sentinel\Core\Session;

/**
 * Sign-in state machine: password, then a second factor, then signed in.
 *
 *   anonymous --password ok--> pending (5 min) --TOTP or recovery code--> signed in
 *                                  |
 *                                  +--no 2FA yet--> forced 2FA enrolment --> signed in
 *
 * Security assumptions:
 * - 2FA is mandatory for every account. A user who passed only the password
 *   step can reach nothing except the 2FA pages (Router 'pending' level).
 * - The session ID is regenerated, and the CSRF token rotated, at each step.
 * - On every request the user row is reloaded. The session is dropped if the
 *   user was disabled, or if session_version changed (password change, role
 *   change, 2FA reset), or if the idle (30 min) or absolute (12 h) timeout passed.
 * - Login is throttled per account (5 failures in 15 minutes, keyed on the
 *   user ID so look-alike spellings share one allowance) and per IP (30
 *   failures in 15 minutes; IPv6 by /64). The second factor is throttled per user.
 *   Error messages and timing never reveal whether the username exists.
 * - Known trade-off: anyone can lock an account out of sign-in for 15
 *   minutes with 5 wrong passwords. Being locked out for a while is
 *   preferable to unlimited guessing. Admins can see it in the audit log.
 * - The throttle check and the failure record are separate queries, so a
 *   burst of parallel requests can slightly exceed a limit. With 2FA
 *   mandatory, the effect on security is negligible.
 */
final class Auth
{
    public const IDLE_TIMEOUT = 1800;
    public const ABSOLUTE_TIMEOUT = 43200;
    public const PENDING_TIMEOUT = 300;

    private const USER_MAX_FAILS = 5;
    private const IP_MAX_FAILS = 30;
    private const SECOND_FACTOR_MAX_FAILS = 5;
    private const WINDOW = 900;

    /** @var array<string,mixed>|null|false Cached user for this request (false = not looked up yet). */
    private array|null|false $current = false;

    /** True for background requests (dashboard refresh) that must not count as user activity. */
    private bool $passive = false;

    /** Wire up the services the sign-in flow needs. */
    public function __construct(
        private readonly UserRepository $users,
        private readonly RateLimiter $limiter,
        private readonly Audit $audit,
    ) {
    }

    /**
     * Step 1: check username and password.
     *
     * @param string $username Untrusted.
     * @param string $password Untrusted.
     * @return array<string,mixed>|string The user row on success, or an error message safe to show.
     */
    public function attemptPassword(Request $request, string $username, string $password): array|string
    {
        $ipBucket = 'login-ip:' . self::ipBucketKey($request->ip());
        $generic = __('Incorrect username or password.');
        $tooMany = __('Too many failed attempts. Please wait 15 minutes and try again.');

        // Only usernames that could exist (same pattern as account creation) reach the
        // database. This stops look-alike spellings (accents, full-width letters, invisible
        // characters) that the database collation would match to a real account from each
        // getting their own throttling allowance.
        $wellFormed = self::isValidUsername($username) && $password !== '' && strlen($password) <= 1024;
        // The audit log stores the typed username only when it is well formed. Anything else
        // might be a password typed into the wrong field.
        $auditName = self::isValidUsername($username) ? $username : '(invalid username)';

        if ($this->limiter->tooMany($ipBucket, self::IP_MAX_FAILS, self::WINDOW)) {
            $this->audit->log('auth.login_throttled', null, $auditName, null, null, ['scope' => 'ip'], $request->ip());
            return $tooMany;
        }
        $user = $wellFormed ? $this->users->findByUsername($username) : null;
        // Throttle per account ID when the account exists, so every spelling counts against one allowance.
        $userBucket = $user !== null ? 'login-uid:' . (int) $user['id'] : 'login-user:' . strtolower($username);
        if ($wellFormed && $this->limiter->tooMany($userBucket, self::USER_MAX_FAILS, self::WINDOW)) {
            $this->audit->log('auth.login_throttled', $user !== null ? (int) $user['id'] : null, $auditName, null, null, ['scope' => 'user'], $request->ip());
            return $tooMany;
        }

        if ($user === null) {
            // Same cost as a real check, so timing doesn't reveal whether the username exists.
            Passwords::verifyDummy($password);
        }
        $ok = $user !== null && Passwords::verify($password, (string) $user['password_hash']);
        if (!$ok || (int) $user['is_active'] !== 1) {
            if ($wellFormed) {
                $this->limiter->hit($userBucket);
            }
            $this->limiter->hit($ipBucket);
            $this->audit->log('auth.login_failed', $user !== null ? (int) $user['id'] : null, $auditName, null, null,
                $user !== null && $ok ? ['reason' => 'disabled'] : [], $request->ip());
            return $generic;
        }

        if (Passwords::needsRehash((string) $user['password_hash'])) {
            $this->users->rehashPassword((int) $user['id'], Passwords::hash($password));
        }
        $this->limiter->clear($userBucket);
        return $user;
    }

    /** True if the username matches the account-creation pattern (ASCII letters, digits, . _ -; 3 to 50). */
    public static function isValidUsername(string $username): bool
    {
        return preg_match('/^[A-Za-z0-9._-]{3,50}$/D', $username) === 1;
    }

    /**
     * Throttling key for an IP: IPv4 as is, IPv6 by its /64 network. One
     * IPv6 customer usually controls a whole /64, so per-address buckets
     * would be trivial to rotate around.
     */
    public static function ipBucketKey(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $packed = inet_pton($ip);
            if ($packed !== false) {
                return bin2hex(substr($packed, 0, 8)) . '::/64';
            }
        }
        return $ip;
    }

    /**
     * Move to the "pending second factor" state after a correct password.
     *
     * @param array<string,mixed> $user
     */
    public function beginPending(array $user): void
    {
        Session::reset();
        Csrf::rotate();
        Session::set('pending_uid', (int) $user['id']);
        Session::set('pending_sv', (int) $user['session_version']);
        Session::set('pending_at', time());
    }

    /**
     * The user who passed the password step and hasn't finished 2FA.
     *
     * @return array<string,mixed>|null
     */
    public function pendingUser(): ?array
    {
        $id = Session::get('pending_uid');
        $at = Session::get('pending_at');
        if (!is_int($id) || !is_int($at) || time() - $at > self::PENDING_TIMEOUT) {
            return null;
        }
        $user = $this->users->find($id);
        if ($user === null || (int) $user['is_active'] !== 1 || (int) $user['session_version'] !== Session::get('pending_sv')) {
            return null;
        }
        return $user;
    }

    /** True if this pending user has had too many second-factor failures. */
    public function secondFactorLocked(int $userId): bool
    {
        return $this->limiter->tooMany('2fa-user:' . $userId, self::SECOND_FACTOR_MAX_FAILS, self::WINDOW);
    }

    /** Record a failed second-factor attempt. */
    public function secondFactorFailed(int $userId, string $username, Request $request): void
    {
        $this->limiter->hit('2fa-user:' . $userId);
        $this->audit->log('auth.2fa_failed', $userId, $username, null, null, [], $request->ip());
    }

    /**
     * Step 2 done: the user is fully signed in.
     *
     * @param array<string,mixed> $user
     */
    public function completeLogin(array $user, Request $request, string $method): void
    {
        $id = (int) $user['id'];
        $fresh = $this->users->find($id) ?? $user;
        Session::reset();
        Csrf::rotate();
        Session::set('uid', $id);
        Session::set('sv', (int) $fresh['session_version']);
        Session::set('auth_at', time());
        Session::set('seen_at', time());
        $this->limiter->clear('2fa-user:' . $id);
        $this->users->touchLastLogin($id);
        $this->audit->log('auth.login', $id, (string) $user['username'], null, null, ['method' => $method], $request->ip());
        $this->current = false;
    }

    /**
     * Mark this request as background (e.g. the dashboard's 60-second refresh): the
     * idle and absolute timeouts are still checked, but the request doesn't reset the
     * idle timer, so an unattended screen still signs out after 30 minutes.
     */
    public function markPassive(): void
    {
        $this->passive = true;
    }

    /**
     * The signed-in user, or null. Checks timeouts and revocation on every call
     * (once per request, then cached).
     *
     * @return array<string,mixed>|null Full row. Never pass it to a view unfiltered.
     */
    public function user(): ?array
    {
        if ($this->current !== false) {
            return $this->current;
        }
        $this->current = null;
        $id = Session::get('uid');
        if (!is_int($id)) {
            return null;
        }
        $now = time();
        $authAt = (int) Session::get('auth_at', 0);
        $seenAt = (int) Session::get('seen_at', 0);
        if ($now - $seenAt > self::IDLE_TIMEOUT || $now - $authAt > self::ABSOLUTE_TIMEOUT) {
            Session::reset();
            Session::flash('warning', __('Your session expired. Please sign in again.'));
            return null;
        }
        $user = $this->users->find($id);
        if ($user === null || (int) $user['is_active'] !== 1 || (int) $user['session_version'] !== Session::get('sv')) {
            Session::reset();
            return null;
        }
        if (!$this->passive) {
            Session::set('seen_at', $now);
        }
        // What the user may do (1.40): read fresh with the role on every request, like the role itself, so a change
        // to the user or their role applies at once (it also ends their sessions).
        $user['permissions'] = $this->users->permissions($user);
        // Which clients they see (1.41): null for every client. Read fresh like the permissions.
        $user['client_ids'] = $this->users->clientIds($user);
        return $this->current = $user;
    }

    /**
     * Call after the signed-in user changes their own password: their
     * session_version moved, so keep this session valid while other sessions end.
     */
    /** True when the signed-in user holds a permission (Sentinel\Auth\Permissions). Nobody signed in holds nothing. */
    public function can(string $permission): bool
    {
        $user = $this->user();
        return $user !== null && in_array($permission, (array) ($user['permissions'] ?? []), true);
    }

    /** True when the signed-in user sees this client (1.41). Nobody signed in sees nothing. */
    public function canSeeClient(int $clientId): bool
    {
        $user = $this->user();
        return $user !== null && ClientAccess::allows($user['client_ids'] ?? null, $clientId);
    }

    /**
     * The signed-in user's client list for filtering lists: null for every client (also for background work with
     * nobody signed in, which isn't limited), else the IDs.
     *
     * @return list<int>|null
     */
    public function clientIds(): ?array
    {
        $user = $this->user();
        return $user === null ? null : ($user['client_ids'] ?? null);
    }

    public function refreshSessionVersion(): void
    {
        $id = Session::get('uid');
        if (is_int($id) && ($user = $this->users->find($id)) !== null) {
            Session::regenerate();
            Csrf::rotate();
            Session::set('sv', (int) $user['session_version']);
            $this->current = false;
        }
    }

    /** Sign out: audit, wipe the session, new session ID and CSRF token. */
    public function logout(Request $request): void
    {
        $user = $this->user();
        if ($user !== null) {
            $this->audit->log('auth.logout', (int) $user['id'], (string) $user['username'], null, null, [], $request->ip());
        }
        Session::reset();
        Csrf::rotate();
        $this->current = false;
    }
}
