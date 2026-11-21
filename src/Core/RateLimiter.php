<?php

declare(strict_types=1);

namespace Sentinel\Core;

use PDO;

/**
 * Counts failed attempts in a sliding time window (used for login and 2FA).
 *
 * Buckets are keyed by a SHA-256 of a label such as "login-user:alice" or
 * "login-ip:192.0.2.10". The raw username isn't stored, so it doesn't leak
 * through this table.
 *
 * Security assumptions:
 * - Throttling by both username and IP limits password guessing against one
 *   account and spraying from one address.
 * - It doesn't stop a distributed attack on its own. Strong passwords and
 *   mandatory 2FA are the main defence.
 */
final class RateLimiter
{
    /** Uses the auth_throttle table on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /** True when the bucket has reached $max failures in the last $windowSeconds. */
    public function tooMany(string $bucket, int $max, int $windowSeconds): bool
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM auth_throttle WHERE bucket = :b AND attempted_at > UTC_TIMESTAMP() - INTERVAL :w SECOND'
        );
        $stmt->execute(['b' => hash('sha256', $bucket), 'w' => $windowSeconds]);
        return (int) $stmt->fetchColumn() >= $max;
    }

    /** Record one failure. */
    public function hit(string $bucket): void
    {
        $stmt = $this->db->prepare('INSERT INTO auth_throttle (bucket, attempted_at) VALUES (:b, UTC_TIMESTAMP())');
        $stmt->execute(['b' => hash('sha256', $bucket)]);
        // Housekeeping: drop rows older than a day (now and then, not on every hit).
        if (random_int(1, 50) === 1) {
            $this->db->exec('DELETE FROM auth_throttle WHERE attempted_at < UTC_TIMESTAMP() - INTERVAL 1 DAY');
        }
    }

    /** Forget failures (after a successful login). */
    public function clear(string $bucket): void
    {
        $stmt = $this->db->prepare('DELETE FROM auth_throttle WHERE bucket = :b');
        $stmt->execute(['b' => hash('sha256', $bucket)]);
    }
}
