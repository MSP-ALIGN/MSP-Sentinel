<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use PDO;

/**
 * Database access for user accounts.
 *
 * Security assumptions:
 * - Every query uses bound parameters.
 * - Rows returned include password_hash and totp_secret_enc. Callers must
 *   never pass these to views or logs. Use publicFields() for display.
 * - session_version is bumped whenever a user's access changes (password,
 *   role, disable, 2FA reset). That signs out their other sessions.
 */
final class UserRepository
{
    /** Works on the given connection. Callers validate input first. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * A user by ID (full row, including secret columns).
     *
     * @return array<string,mixed>|null
     */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * @param string $username Untrusted. Compared case-insensitively (the column collation).
     * @return array<string,mixed>|null
     */
    public function findByUsername(string $username): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE username = :u');
        $stmt->execute(['u' => $username]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** @return list<array<string,mixed>> All users, safe fields only. */
    public function all(): array
    {
        $stmt = $this->db->query(
            'SELECT id, username, display_name, email, role, is_active, must_change_password,
                    totp_enabled_at, last_login_at, created_at
             FROM users ORDER BY username'
        );
        return $stmt->fetchAll();
    }

    /**
     * Create a user. Input has already been validated by the caller.
     *
     * @return int New user ID.
     */
    public function create(string $username, string $displayName, string $email, string $role, string $passwordHash, bool $mustChange): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO users (username, display_name, email, role, password_hash, must_change_password, is_active, session_version, created_at, updated_at)
             VALUES (:u, :d, :e, :r, :p, :m, 1, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())'
        );
        $stmt->execute(['u' => $username, 'd' => $displayName, 'e' => $email, 'r' => $role, 'p' => $passwordHash, 'm' => $mustChange ? 1 : 0]);
        return (int) $this->db->lastInsertId();
    }

    /**
     * Update profile fields, role and active flag.
     *
     * @param bool $accessChanged True when role or active flag changed. Bumps session_version,
     *                            so the user's sessions end and the change takes effect at once.
     *                            A name or email fix alone doesn't sign anyone out.
     */
    public function updateAccount(int $id, string $displayName, string $email, string $role, bool $active, bool $accessChanged): void
    {
        $stmt = $this->db->prepare(
            'UPDATE users SET display_name = :d, email = :e, role = :r, is_active = :a,
                    session_version = session_version + :bump, updated_at = UTC_TIMESTAMP()
             WHERE id = :id'
        );
        $stmt->execute(['d' => $displayName, 'e' => $email, 'r' => $role, 'a' => $active ? 1 : 0, 'bump' => $accessChanged ? 1 : 0, 'id' => $id]);
    }

    /**
     * Count active admins while locking their rows (call inside a transaction).
     * Two admins demoting each other at the same moment are serialised, so
     * the "last admin" rule can't be raced.
     */
    public function countActiveAdminsForUpdate(): int
    {
        return count($this->db->query("SELECT id FROM users WHERE role = 'admin' AND is_active = 1 FOR UPDATE")->fetchAll());
    }

    /** Set a new password hash and sign out other sessions. */
    public function setPassword(int $id, string $hash, bool $mustChange): void
    {
        $stmt = $this->db->prepare(
            'UPDATE users SET password_hash = :p, must_change_password = :m,
                    session_version = session_version + 1, updated_at = UTC_TIMESTAMP()
             WHERE id = :id'
        );
        $stmt->execute(['p' => $hash, 'm' => $mustChange ? 1 : 0, 'id' => $id]);
    }

    /** Quietly upgrade a hash at login (same password, so no sign-out). */
    public function rehashPassword(int $id, string $hash): void
    {
        $stmt = $this->db->prepare('UPDATE users SET password_hash = :p WHERE id = :id');
        $stmt->execute(['p' => $hash, 'id' => $id]);
    }

    /**
     * Save a confirmed (encrypted) TOTP secret and the step just used, but only
     * if the user has no 2FA yet. Two parallel enrolments can't overwrite each other.
     *
     * @return bool False if 2FA was already enabled (by a parallel request).
     */
    public function enableTotp(int $id, string $encryptedSecret, int $step): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE users SET totp_secret_enc = :s, totp_enabled_at = UTC_TIMESTAMP(), totp_last_step = :st, updated_at = UTC_TIMESTAMP()
             WHERE id = :id AND totp_enabled_at IS NULL'
        );
        $stmt->execute(['s' => $encryptedSecret, 'st' => $step, 'id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Remove 2FA (admin reset) and set a new temporary password at the same time.
     *
     * The password is replaced too: otherwise anyone who knew the old (maybe leaked)
     * password could enrol their own authenticator before the real user does.
     * Signs out the user's sessions. Runs in one transaction.
     */
    public function resetTotp(int $id, string $temporaryPasswordHash): void
    {
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare(
                'UPDATE users SET totp_secret_enc = NULL, totp_enabled_at = NULL, totp_last_step = NULL,
                        password_hash = :p, must_change_password = 1,
                        session_version = session_version + 1, updated_at = UTC_TIMESTAMP()
                 WHERE id = :id'
            );
            $stmt->execute(['p' => $temporaryPasswordHash, 'id' => $id]);
            $this->db->prepare('DELETE FROM user_recovery_codes WHERE user_id = :id')->execute(['id' => $id]);
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Record a used TOTP step, but only if it is newer than the stored one.
     * Done in one UPDATE, so two parallel requests can't both use the same code.
     *
     * @return bool False if the step was already used (replay).
     */
    public function claimTotpStep(int $id, int $step): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE users SET totp_last_step = :s WHERE id = :id AND (totp_last_step IS NULL OR totp_last_step < :s2)'
        );
        $stmt->execute(['s' => $step, 's2' => $step, 'id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /** Record the time of a completed sign-in. */
    public function touchLastLogin(int $id): void
    {
        $this->db->prepare('UPDATE users SET last_login_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['id' => $id]);
    }


    /**
     * Strip secret columns before a row goes anywhere near a view.
     *
     * @param array<string,mixed> $user
     * @return array<string,mixed>
     */
    public static function publicFields(array $user): array
    {
        unset($user['password_hash'], $user['totp_secret_enc'], $user['totp_last_step'], $user['session_version']);
        return $user;
    }
}
