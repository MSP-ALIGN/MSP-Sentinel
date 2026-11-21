<?php

declare(strict_types=1);

namespace Sentinel\Core;

use PDO;

/**
 * Append-only audit log of security-relevant actions (logins, user changes,
 * settings changes and, later, scope approvals and scans).
 *
 * Security assumptions:
 * - The app only ever INSERTs into audit_log. There is no edit or delete in the UI.
 * - Details must never include secrets (passwords, TOTP seeds, tokens).
 *   Callers pass only IDs and changed field names or values that are safe to show.
 * - The username is copied into each row, so history survives a renamed user.
 */
final class Audit
{
    /** Writes to the audit_log table on the given connection. */
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Record an action.
     *
     * @param string               $action     Short dotted code, e.g. "auth.login_failed".
     * @param int|null             $userId     Who did it (null for anonymous / system).
     * @param string|null          $username   Username at the time (or the username tried, for failed logins).
     * @param string|null          $targetType What was acted on, e.g. "user".
     * @param int|null             $targetId   ID of the target.
     * @param array<string,mixed>  $details    Extra safe context (no secrets).
     * @param string|null          $ip         Client IP, if a web request.
     */
    public function log(
        string $action,
        ?int $userId,
        ?string $username,
        ?string $targetType = null,
        ?int $targetId = null,
        array $details = [],
        ?string $ip = null,
    ): void {
        $stmt = $this->db->prepare(
            'INSERT INTO audit_log (created_at, user_id, username, action, target_type, target_id, ip, details)
             VALUES (UTC_TIMESTAMP(), :uid, :uname, :action, :ttype, :tid, :ip, :details)'
        );
        $stmt->execute([
            'uid' => $userId,
            'uname' => $username === null ? null : mb_substr($username, 0, 100),
            'action' => $action,
            'ttype' => $targetType,
            'tid' => $targetId,
            'ip' => $ip,
            'details' => $details === [] ? null : json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
        ]);
    }
}
