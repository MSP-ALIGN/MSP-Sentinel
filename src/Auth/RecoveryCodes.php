<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use PDO;
use Sentinel\Core\Crypto;

/**
 * One-time recovery codes, for signing in when the authenticator app is lost.
 *
 * Security assumptions:
 * - 10 codes, each 10 characters from a 31-character alphabet (about 49 bits),
 *   shown to the user once and never again.
 * - Only an HMAC (keyed with the app key) is stored. A database dump alone
 *   can't be used to recover or check codes.
 * - Each code works once. Using it is a single conditional UPDATE, so it
 *   can't be raced.
 * - Recovery codes are rate-limited together with TOTP codes (same bucket).
 */
final class RecoveryCodes
{
    private const COUNT = 10;
    // No 0/O/1/I/L, so codes are easy to read and type.
    private const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

    /** Uses the database for storage and Crypto for the HMAC key. */
    public function __construct(private readonly PDO $db, private readonly Crypto $crypto)
    {
    }

    /**
     * Replace all of a user's codes with new ones.
     *
     * @return list<string> Plain codes, to show to the user once.
     */
    public function regenerate(int $userId): array
    {
        // One transaction (joining the caller's if one is open), so the user never
        // ends up with fewer stored codes than were shown on screen.
        $own = !$this->db->inTransaction();
        if ($own) {
            $this->db->beginTransaction();
        }
        try {
            $this->db->prepare('DELETE FROM user_recovery_codes WHERE user_id = :u')->execute(['u' => $userId]);
            $insert = $this->db->prepare('INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (:u, :h, UTC_TIMESTAMP())');
            $codes = [];
            for ($i = 0; $i < self::COUNT; $i++) {
                $raw = '';
                for ($j = 0; $j < 10; $j++) {
                    $raw .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
                }
                $codes[] = substr($raw, 0, 5) . '-' . substr($raw, 5);
                $insert->execute(['u' => $userId, 'h' => $this->crypto->hmac($raw)]);
            }
            if ($own) {
                $this->db->commit();
            }
            return $codes;
        } catch (\Throwable $ex) {
            if ($own) {
                $this->db->rollBack();
            }
            throw $ex;
        }
    }

    /**
     * Use a code.
     *
     * @param string $code Untrusted input. Case, spaces and dashes are ignored.
     * @return bool True if the code was valid and unused (it is now used up).
     */
    public function consume(int $userId, string $code): bool
    {
        $normalised = strtoupper(preg_replace('/[\s-]+/', '', $code) ?? '');
        if (!preg_match('/^[' . self::ALPHABET . ']{10}$/', $normalised)) {
            return false;
        }
        $stmt = $this->db->prepare(
            'UPDATE user_recovery_codes SET used_at = UTC_TIMESTAMP()
             WHERE user_id = :u AND code_hash = :h AND used_at IS NULL'
        );
        $stmt->execute(['u' => $userId, 'h' => $this->crypto->hmac($normalised)]);
        return $stmt->rowCount() === 1;
    }

    /** Number of unused codes left. */
    public function remaining(int $userId): int
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = :u AND used_at IS NULL');
        $stmt->execute(['u' => $userId]);
        return (int) $stmt->fetchColumn();
    }
}
