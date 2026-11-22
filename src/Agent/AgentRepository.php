<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use PDO;
use Sentinel\Core\Crypto;

/**
 * Storage for on-premises agents: internal authorisations (signed), one-time
 * enrolment codes, agents with their tokens, and agent jobs.
 *
 * Tokens ("sna_" + 12-character prefix + "_" + 43-character secret) and
 * enrolment codes are stored only as HMACs (app key), compared in constant
 * time. An enrolment code works once, for 24 hours, for one site.
 *
 * An internal authorisation is signed when it is recorded (Signer); a row
 * whose signature doesn't verify is never used, so changing the database
 * alone can't widen what an agent may scan.
 *
 * Untrusted: form values (validated by the controller), the bearer token and
 * enrolment code from agents, and agent-reported hostnames and versions.
 */
final class AgentRepository
{
    public const CODE_HOURS = 24;

    /** Works on the given connection with the app's HMAC and signing keys. */
    public function __construct(private readonly PDO $db, private readonly Crypto $crypto, private readonly Signer $signer)
    {
    }

    /**
     * Record and sign an internal authorisation.
     *
     * @param array{approved_by_name:string,approved_by_role:string,approved_on:string,valid_from:string,valid_until:string,document_ref:string,notes:string} $f
     * @param list<string> $ranges Canonical CIDRs (InternalRanges::parseLines).
     */
    public function createAuthorisation(int $clientId, int $siteId, string $timezone, array $f, array $ranges, int $userId): int
    {
        $this->db->beginTransaction();
        try {
            $this->db->prepare(
                "INSERT INTO internal_authorisations (client_id, site_id, approved_by_name, approved_by_role, approved_on, valid_from, valid_until, document_ref, notes,
                                                      ranges, signed_payload, signature, recorded_by, created_at)
                 VALUES (:c, :s, :n, :r, :on, :from, :until, :doc, :notes, :ranges, '', '', :u, UTC_TIMESTAMP())"
            )->execute(['c' => $clientId, 's' => $siteId, 'n' => $f['approved_by_name'], 'r' => $f['approved_by_role'], 'on' => $f['approved_on'],
                        'from' => $f['valid_from'], 'until' => $f['valid_until'], 'doc' => $f['document_ref'], 'notes' => $f['notes'] === '' ? null : $f['notes'],
                        'ranges' => implode("\n", $ranges), 'u' => $userId]);
            $id = (int) $this->db->lastInsertId();
            $signed = $this->signer->sign(['v' => 1, 'type' => 'internal_authorisation', 'id' => $id, 'client_id' => $clientId, 'site_id' => $siteId,
                'ranges' => array_values($ranges), 'valid_from' => $f['valid_from'], 'valid_until' => $f['valid_until'], 'timezone' => $timezone]);
            $this->db->prepare('UPDATE internal_authorisations SET signed_payload = :p, signature = :s WHERE id = :id')
                ->execute(['p' => $signed['payload'], 's' => $signed['signature'], 'id' => $id]);
            $this->db->commit();
            return $id;
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Internal authorisations of a site, newest first.
     *
     * @return list<array<string,mixed>>
     */
    public function authorisations(int $siteId): array
    {
        $stmt = $this->db->prepare('SELECT a.*, u.username AS recorded_by_username FROM internal_authorisations a LEFT JOIN users u ON u.id = a.recorded_by WHERE a.site_id = :s ORDER BY a.id DESC');
        $stmt->execute(['s' => $siteId]);
        return $stmt->fetchAll();
    }

    /**
     * The newest valid, unrevoked authorisation of a site on $today whose signature verifies, or null.
     *
     * @return array<string,mixed>|null With 'ranges_list'.
     */
    public function activeAuthorisation(int $siteId, string $today): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM internal_authorisations WHERE site_id = :s AND revoked_at IS NULL AND valid_from <= :t AND valid_until >= :t2 ORDER BY id DESC');
        $stmt->execute(['s' => $siteId, 't' => $today, 't2' => $today]);
        foreach ($stmt->fetchAll() as $a) {
            $data = json_decode((string) $a['signed_payload'], true);
            // The signed payload, not the row, is the truth: it must verify and agree with the row.
            if (is_array($data) && Signer::verify((string) $a['signed_payload'], (string) $a['signature'], $this->signer->publicKey())
                && (int) $data['id'] === (int) $a['id'] && (int) $data['site_id'] === $siteId && $data['valid_until'] >= $today && $data['valid_from'] <= $today) {
                $a['ranges_list'] = array_values(array_map('strval', (array) $data['ranges']));
                return $a;
            }
        }
        return null;
    }

    /** Revoke an authorisation (no new jobs use it; queued jobs for it are cancelled). */
    public function revokeAuthorisation(int $id, int $userId, string $reason): void
    {
        $this->db->prepare('UPDATE internal_authorisations SET revoked_at = UTC_TIMESTAMP(), revoked_by = :u, revoke_reason = :r WHERE id = :id AND revoked_at IS NULL')
            ->execute(['u' => $userId, 'r' => $reason, 'id' => $id]);
        $this->db->prepare("UPDATE agent_jobs SET cancel_requested = 1, status = IF(status = 'queued', 'cancelled', status), finished_at = IF(status = 'cancelled', UTC_TIMESTAMP(), finished_at)
                            WHERE authorisation_id = :id AND status IN ('queued','sent')")->execute(['id' => $id]);
    }

    /** Create a one-time enrolment code for a site; returns the code (shown once). */
    public function createEnrolment(int $clientId, int $siteId, int $userId): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $raw = '';
        for ($i = 0; $i < 20; $i++) {
            $raw .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        $code = 'SNE-' . implode('-', str_split($raw, 5));
        $this->db->prepare('INSERT INTO agent_enrolments (client_id, site_id, code_hash, created_by, created_at, expires_at)
                            VALUES (:c, :s, :h, :u, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL ' . self::CODE_HOURS . ' HOUR)')
            ->execute(['c' => $clientId, 's' => $siteId, 'h' => $this->crypto->hmac('enrol|' . $code), 'u' => $userId]);
        return $code;
    }

    /**
     * Use an enrolment code (once) to create an agent.
     *
     * @return array{agent_id:int, token:string, site_id:int, client_id:int}|null null if the code is unknown, used or expired.
     */
    public function enrol(string $code, string $hostname, string $version, string $ip): ?array
    {
        $code = strtoupper(trim($code));
        if (!preg_match('/^SNE(-[A-Z2-9]{5}){4}$/', $code)) {
            return null;
        }
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare('SELECT * FROM agent_enrolments WHERE code_hash = :h AND used_at IS NULL AND expires_at > UTC_TIMESTAMP() FOR UPDATE');
            $stmt->execute(['h' => $this->crypto->hmac('enrol|' . $code)]);
            $e = $stmt->fetch();
            if ($e === false) {
                $this->db->rollBack();
                return null;
            }
            $prefix = bin2hex(random_bytes(6));
            $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $token = 'sna_' . $prefix . '_' . $secret;
            $name = $hostname !== '' ? $hostname : 'agent-' . $prefix;
            $this->db->prepare("INSERT INTO agents (client_id, site_id, name, token_prefix, token_hash, hostname, version, status, enrolled_at, enrolled_by, last_seen_at, last_ip)
                                VALUES (:c, :s, :n, :p, :h, :host, :v, 'active', UTC_TIMESTAMP(), :u, UTC_TIMESTAMP(), :ip)")
                ->execute(['c' => (int) $e['client_id'], 's' => (int) $e['site_id'], 'n' => mb_substr($name, 0, 100), 'p' => $prefix, 'h' => $this->crypto->hmac('agent|' . $token),
                           'host' => mb_substr($hostname, 0, 255), 'v' => mb_substr($version, 0, 20), 'u' => (int) $e['created_by'], 'ip' => mb_substr($ip, 0, 45)]);
            $agentId = (int) $this->db->lastInsertId();
            $this->db->prepare('UPDATE agent_enrolments SET used_at = UTC_TIMESTAMP(), agent_id = :a WHERE id = :id')->execute(['a' => $agentId, 'id' => (int) $e['id']]);
            $this->db->commit();
            return ['agent_id' => $agentId, 'token' => $token, 'site_id' => (int) $e['site_id'], 'client_id' => (int) $e['client_id']];
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * The active agent for a bearer token, or null.
     *
     * @return array<string,mixed>|null
     */
    public function authenticate(string $authorization): ?array
    {
        if (!preg_match('/^Bearer (sna_([0-9a-f]{12})_[A-Za-z0-9_-]{43})$/', trim($authorization), $m)) {
            return null;
        }
        $stmt = $this->db->prepare("SELECT a.*, c.is_archived, c.scanning_paused AS client_paused, c.timezone, s.scanning_paused AS site_paused, s.name AS site_name
                                    FROM agents a JOIN clients c ON c.id = a.client_id JOIN sites s ON s.id = a.site_id WHERE a.token_prefix = :p AND a.status = 'active'");
        $stmt->execute(['p' => $m[2]]);
        $agent = $stmt->fetch();
        if ($agent === false || !hash_equals((string) $agent['token_hash'], $this->crypto->hmac('agent|' . $m[1]))) {
            return null;
        }
        return $agent;
    }

    /** Record that an agent checked in. */
    public function touch(int $agentId, string $ip, string $hostname, string $version): void
    {
        $this->db->prepare('UPDATE agents SET last_seen_at = UTC_TIMESTAMP(), last_ip = :ip, hostname = :h, version = :v WHERE id = :id')
            ->execute(['ip' => mb_substr($ip, 0, 45), 'h' => mb_substr($hostname, 0, 255), 'v' => mb_substr($version, 0, 20), 'id' => $agentId]);
    }

    /**
     * Agents of a site (active first).
     *
     * @return list<array<string,mixed>>
     */
    public function agents(int $siteId): array
    {
        $stmt = $this->db->prepare("SELECT * FROM agents WHERE site_id = :s ORDER BY status = 'active' DESC, id DESC");
        $stmt->execute(['s' => $siteId]);
        return $stmt->fetchAll();
    }

    /** Revoke an agent: its token stops working and its open jobs are cancelled. */
    public function revokeAgent(int $agentId, int $userId): void
    {
        $this->db->prepare("UPDATE agents SET status = 'revoked', revoked_at = UTC_TIMESTAMP(), revoked_by = :u WHERE id = :id AND status = 'active'")->execute(['u' => $userId, 'id' => $agentId]);
        $this->db->prepare("UPDATE agent_jobs SET status = 'cancelled', finished_at = UTC_TIMESTAMP() WHERE agent_id = :id AND status IN ('queued','sent')")->execute(['id' => $agentId]);
    }

    /**
     * Queue a job for an agent.
     *
     * @param list<int> $ports
     */
    public function queueJob(int $agentId, int $clientId, int $siteId, int $authorisationId, string $kind, string $trigger, ?int $userId, array $ports, int $hours): int
    {
        $this->db->prepare("INSERT INTO agent_jobs (agent_id, client_id, site_id, authorisation_id, kind, trigger_type, requested_by, status, ports, created_at, expires_at)
                            VALUES (:a, :c, :s, :auth, :k, :t, :u, 'queued', :p, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL :h HOUR)")
            ->execute(['a' => $agentId, 'c' => $clientId, 's' => $siteId, 'auth' => $authorisationId, 'k' => $kind === 'light' ? 'light' : 'full',
                       't' => $trigger === 'manual' ? 'manual' : 'scheduled', 'u' => $userId, 'p' => implode(',', array_map('intval', $ports)), 'h' => $hours]);
        return (int) $this->db->lastInsertId();
    }

    /**
     * Jobs an agent should run now: queued, or sent but not finished (the agent may have restarted), not expired.
     *
     * @return list<array<string,mixed>>
     */
    public function jobsFor(int $agentId): array
    {
        $this->db->exec("UPDATE agent_jobs SET status = 'expired', finished_at = UTC_TIMESTAMP() WHERE status IN ('queued','sent') AND expires_at < UTC_TIMESTAMP()");
        $stmt = $this->db->prepare("SELECT * FROM agent_jobs WHERE agent_id = :a AND status IN ('queued','sent') AND cancel_requested = 0 ORDER BY id LIMIT 3");
        $stmt->execute(['a' => $agentId]);
        return $stmt->fetchAll();
    }

    /**
     * IDs of this agent's jobs that must stop now (cancelled, or scanning paused).
     *
     * @return list<int>
     */
    public function jobsToStop(int $agentId): array
    {
        $stmt = $this->db->prepare("SELECT id FROM agent_jobs WHERE agent_id = :a AND (cancel_requested = 1 OR status IN ('cancelled','expired')) AND (finished_at IS NULL OR finished_at > UTC_TIMESTAMP() - INTERVAL 1 DAY)");
        $stmt->execute(['a' => $agentId]);
        return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    }

    /** Mark a job as handed to its agent. */
    public function markSent(int $jobId): void
    {
        $this->db->prepare("UPDATE agent_jobs SET status = 'sent', sent_at = COALESCE(sent_at, UTC_TIMESTAMP()) WHERE id = :id AND status IN ('queued','sent')")->execute(['id' => $jobId]);
    }

    /**
     * A job of this agent, or null.
     *
     * @return array<string,mixed>|null
     */
    public function job(int $agentId, int $jobId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM agent_jobs WHERE id = :id AND agent_id = :a');
        $stmt->execute(['id' => $jobId, 'a' => $agentId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Finish a job (only once).
     *
     * @param array<string,mixed> $summary
     */
    public function finishJob(int $jobId, string $status, array $summary): bool
    {
        $stmt = $this->db->prepare("UPDATE agent_jobs SET status = :st, finished_at = UTC_TIMESTAMP(), summary = :sum WHERE id = :id AND status IN ('queued','sent')");
        $stmt->execute(['st' => $status, 'sum' => json_encode($summary, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), 'id' => $jobId]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Recent jobs of a site.
     *
     * @return list<array<string,mixed>>
     */
    public function recentJobs(int $siteId, int $limit = 10): array
    {
        $stmt = $this->db->prepare('SELECT j.*, a.name AS agent_name FROM agent_jobs j JOIN agents a ON a.id = j.agent_id WHERE j.site_id = :s ORDER BY j.id DESC LIMIT :l');
        $stmt->bindValue('s', $siteId, PDO::PARAM_INT);
        $stmt->bindValue('l', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }
}
