<?php

declare(strict_types=1);

namespace Sentinel\Api;

use PDO;
use Sentinel\Auth\Role;
use Sentinel\Core\Crypto;
use Sentinel\Core\RateLimiter;
use Sentinel\Scope\IpRange;

/**
 * API tokens: create, authenticate, limit to clients, revoke.
 *
 * Token format: "snt_" + 12-character public prefix + "_" + 43-character
 * secret (32 random bytes, base64url). Only the prefix and an HMAC of the
 * whole token (keyed with the app key) are stored.
 *
 * Security assumptions:
 * - The bearer token is untrusted input. It is checked with hash_equals.
 * - A token works only while: not revoked, not expired, its creator is still
 *   an active admin, and (if set) the caller's IP is in its allowlist.
 * - Failed attempts are rate-limited per IP; successful calls per token.
 * - Tokens are shown once at creation and can't be recovered.
 */
final class TokenService
{
    public const MAX_DAYS = 365;
    public const RATE_PER_MINUTE = 120;
    private const FAIL_LIMIT = 20;

    /** Needs the database, the app key (for HMACs) and the rate limiter. */
    public function __construct(private readonly PDO $db, private readonly Crypto $crypto, private readonly RateLimiter $limiter)
    {
    }

    /**
     * Create a token. Returns [id, plaintext token]. Input was validated by the controller.
     *
     * @param list<int>    $clientIds Ignored when $allClients.
     * @param list<string> $ips       Canonical IPs/CIDRs ('' = any).
     * @return array{0:int, 1:string}
     */
    public function create(string $name, bool $allClients, array $clientIds, bool $canTriage, bool $canScan, array $ips, int $days, int $userId): array
    {
        $prefix = substr(strtr(base64_encode(random_bytes(9)), '+/', 'AB'), 0, 12);
        $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $token = 'snt_' . $prefix . '_' . $secret;
        $this->db->beginTransaction();
        try {
            $this->db->prepare(
                'INSERT INTO api_tokens (name, token_prefix, token_hash, all_clients, can_triage, can_scan, ip_allowlist, expires_at, created_by, created_at)
                 VALUES (:n, :p, :h, :a, :t, :s, :ip, UTC_TIMESTAMP() + INTERVAL :d DAY, :u, UTC_TIMESTAMP())'
            )->execute(['n' => $name, 'p' => $prefix, 'h' => $this->crypto->hmac($token), 'a' => $allClients ? 1 : 0, 't' => $canTriage ? 1 : 0,
                        's' => $canScan ? 1 : 0, 'ip' => implode(',', $ips), 'd' => max(1, min(self::MAX_DAYS, $days)), 'u' => $userId]);
            $id = (int) $this->db->lastInsertId();
            if (!$allClients) {
                $stmt = $this->db->prepare('INSERT INTO api_token_clients (token_id, client_id) VALUES (:t, :c)');
                foreach (array_unique($clientIds) as $cid) {
                    $stmt->execute(['t' => $id, 'c' => $cid]);
                }
            }
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
        return [$id, $token];
    }

    /**
     * Check an Authorization header. Returns the token row (with creator details
     * and 'client_ids' = null for all clients), or an error: [HTTP status, message].
     */
    public function authenticate(string $authorization, string $ip): array
    {
        if ($this->limiter->tooMany('api-fail:' . $ip, self::FAIL_LIMIT, 600)) {
            return ['error' => [429, 'Too many failed attempts. Try again later.']];
        }
        if (!preg_match('/^Bearer (snt_([A-Za-z0-9]{12})_[A-Za-z0-9_-]{43})$/', $authorization, $m)) {
            return $this->fail($ip, 401, 'Missing or malformed bearer token.');
        }
        $stmt = $this->db->prepare(
            "SELECT t.*, u.username AS creator_username, u.role AS creator_role, u.is_active AS creator_active
             FROM api_tokens t JOIN users u ON u.id = t.created_by WHERE t.token_prefix = :p"
        );
        $stmt->execute(['p' => $m[2]]);
        $t = $stmt->fetch();
        if ($t === false || !hash_equals((string) $t['token_hash'], $this->crypto->hmac($m[1]))) {
            return $this->fail($ip, 401, 'Invalid token.');
        }
        if ($t['revoked_at'] !== null || strtotime($t['expires_at'] . ' UTC') <= time()) {
            return $this->fail($ip, 401, 'This token has expired or was revoked.');
        }
        if ((int) $t['creator_active'] !== 1 || !Role::atLeast((string) $t['creator_role'], Role::ADMIN)) {
            return $this->fail($ip, 401, 'The admin who created this token is no longer active.');
        }
        if (!self::ipAllowed((string) $t['ip_allowlist'], $ip)) {
            return $this->fail($ip, 403, 'Requests from this address are not allowed for this token.');
        }
        if ($this->limiter->tooMany('api:' . $t['id'], self::RATE_PER_MINUTE, 60)) {
            return ['error' => [429, 'Rate limit reached (' . self::RATE_PER_MINUTE . ' requests per minute).']];
        }
        $this->limiter->hit('api:' . $t['id']);
        // Record use (at most once a minute, to keep writes low).
        if ($t['last_used_at'] === null || strtotime($t['last_used_at'] . ' UTC') < time() - 60 || $t['last_used_ip'] !== $ip) {
            $this->db->prepare('UPDATE api_tokens SET last_used_at = UTC_TIMESTAMP(), last_used_ip = :ip WHERE id = :id')->execute(['ip' => $ip, 'id' => $t['id']]);
        }
        $t['client_ids'] = (int) $t['all_clients'] === 1 ? null : $this->clientIds((int) $t['id']);
        unset($t['token_hash']);
        return $t;
    }

    /** True if the IP is allowed by the (comma-separated) allowlist; an empty list allows any address. */
    public static function ipAllowed(string $allowlist, string $ip): bool
    {
        if (trim($allowlist) === '') {
            return true;
        }
        $addr = IpRange::parse($ip);
        if ($addr === null) {
            return false;
        }
        foreach (explode(',', $allowlist) as $entry) {
            $range = IpRange::parse(trim($entry));
            if ($range !== null && $addr->within($range)) {
                return true;
            }
        }
        return false;
    }

    /** @return list<int> Client IDs a limited token may see. */
    public function clientIds(int $tokenId): array
    {
        $stmt = $this->db->prepare('SELECT client_id FROM api_token_clients WHERE token_id = :t ORDER BY client_id');
        $stmt->execute(['t' => $tokenId]);
        return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    }

    /**
     * All tokens for the admin page (never the hash).
     *
     * @return list<array<string,mixed>>
     */
    public function all(): array
    {
        $rows = $this->db->query(
            "SELECT t.id, t.name, t.token_prefix, t.all_clients, t.can_triage, t.can_scan, t.ip_allowlist, t.expires_at, t.created_at, t.last_used_at,
                    t.last_used_ip, t.revoked_at, u.display_name AS creator
             FROM api_tokens t JOIN users u ON u.id = t.created_by ORDER BY t.revoked_at IS NULL DESC, t.id DESC"
        )->fetchAll();
        foreach ($rows as &$r) {
            $r['clients'] = (int) $r['all_clients'] === 1 ? [] : $this->db->query('SELECT c.name FROM api_token_clients tc JOIN clients c ON c.id = tc.client_id WHERE tc.token_id = ' . (int) $r['id'] . ' ORDER BY c.name')->fetchAll(PDO::FETCH_COLUMN);
        }
        return $rows;
    }

    /** Revoke a token. Returns false if it was unknown or already revoked. */
    public function revoke(int $id, int $userId): bool
    {
        $stmt = $this->db->prepare('UPDATE api_tokens SET revoked_at = UTC_TIMESTAMP(), revoked_by = :u WHERE id = :id AND revoked_at IS NULL');
        $stmt->execute(['u' => $userId, 'id' => $id]);
        return $stmt->rowCount() === 1;
    }

    /** Record a failed attempt and build the error. */
    private function fail(string $ip, int $status, string $message): array
    {
        $this->limiter->hit('api-fail:' . $ip);
        return ['error' => [$status, $message]];
    }
}
