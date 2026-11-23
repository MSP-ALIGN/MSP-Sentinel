<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use PDO;

/**
 * Active Directory settings per site, and the relay of sealed directory passwords to agents.
 *
 * The password is never readable here. An admin's browser seals it to the site agent's public key
 * (agent-seal.js); this class stores that sealed box as a "drop" for that one agent, hands it out (signed) at the
 * agent's check-in, and deletes it when the agent confirms it opened and kept it, or after DROP_HOURS. The site row
 * then only says where the password is: waiting for the agent, held by agent #n (since when), or failed (why).
 *
 * Untrusted: everything an agent reports (it is checked and shortened by the callers and here); the sealed box (only
 * its size and shape are checked: it can't be read here). Settings come from admins, validated by the controller.
 */
final class DirectoryRepository
{
    /** Hours a sealed password waits for its agent before it is deleted. */
    public const DROP_HOURS = 24;
    /** Largest sealed box accepted (a password of a few hundred characters fits many times over). */
    public const MAX_SEALED = 4096;

    public function __construct(private readonly PDO $db)
    {
    }

    /** A site's directory settings and state, or null when it has none. @return array<string,mixed>|null */
    public function find(int $siteId): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM site_directory WHERE site_id = :s');
        $stmt->execute(['s' => $siteId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Save the domain, domain controller and user name. A different domain controller means a different certificate
     * (trust is asked again); a different user name means the agent's password is for someone else (it must be set
     * again). Returns what changed, for the audit log.
     *
     * @return list<string>
     */
    public function saveSettings(int $siteId, int $clientId, string $domain, string $dcIp, string $username): array
    {
        $old = $this->find($siteId);
        if ($old === null) {
            $this->db->prepare("INSERT INTO site_directory (site_id, client_id, domain, dc_ip, username, updated_at) VALUES (:s, :c, :d, :ip, :u, UTC_TIMESTAMP())")
                ->execute(['s' => $siteId, 'c' => $clientId, 'd' => $domain, 'ip' => $dcIp, 'u' => $username]);
            return ['domain', 'dc_ip', 'username'];
        }
        $changed = array_keys(array_filter(['domain' => $old['domain'] !== $domain, 'dc_ip' => $old['dc_ip'] !== $dcIp, 'username' => $old['username'] !== $username]));
        if ($changed === []) {
            return [];
        }
        $sets = ['domain = :d', 'dc_ip = :ip', 'username = :u', 'updated_at = UTC_TIMESTAMP()'];
        if (in_array('dc_ip', $changed, true) || in_array('domain', $changed, true)) {
            $sets[] = "cert_seen = '', cert_seen_subject = '', cert_seen_at = NULL, cert_trusted = '', cert_trusted_by = NULL";
        }
        if (in_array('username', $changed, true)) {
            $sets[] = "cred_state = 'none', cred_agent_id = NULL, cred_confirmed_at = NULL, cred_error = ''";
            $this->db->prepare('DELETE FROM agent_secret_drops WHERE site_id = :s')->execute(['s' => $siteId]);
        }
        $this->db->prepare('UPDATE site_directory SET ' . implode(', ', $sets) . ' WHERE site_id = :s')->execute(['d' => $domain, 'ip' => $dcIp, 'u' => $username, 's' => $siteId]);
        return $changed;
    }

    /** Turn the directory checks off for a site: settings, results and any password on its way are deleted. */
    public function remove(int $siteId): void
    {
        $this->db->prepare('DELETE FROM agent_secret_drops WHERE site_id = :s')->execute(['s' => $siteId]);
        $this->db->prepare('DELETE FROM site_directory WHERE site_id = :s')->execute(['s' => $siteId]);
    }

    /** An admin trusts the certificate the agent saw on the domain controller (it must still be the one shown). */
    public function trustCertificate(int $siteId, string $fingerprint, int $userId): bool
    {
        $stmt = $this->db->prepare("UPDATE site_directory SET cert_trusted = cert_seen, cert_trusted_by = :u, updated_at = UTC_TIMESTAMP()
                                    WHERE site_id = :s AND cert_seen = :f AND cert_seen <> ''");
        $stmt->execute(['u' => $userId, 's' => $siteId, 'f' => $fingerprint]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Queue a sealed password for an agent (replacing any not yet collected). The box was sealed in the browser to
     * that agent's key and bound to its ID, $nonce and $username (AgentKey::directoryAad).
     */
    public function createDrop(int $agentId, int $siteId, string $nonce, string $username, string $sealed, int $userId): int
    {
        $this->db->beginTransaction();
        try {
            $this->db->prepare('DELETE FROM agent_secret_drops WHERE site_id = :s')->execute(['s' => $siteId]);
            $this->db->prepare('INSERT INTO agent_secret_drops (agent_id, site_id, nonce, username, sealed, created_by, created_at, expires_at)
                                VALUES (:a, :s, :n, :u, :b, :by, UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL ' . self::DROP_HOURS . ' HOUR)')
                ->execute(['a' => $agentId, 's' => $siteId, 'n' => $nonce, 'u' => $username, 'b' => $sealed, 'by' => $userId]);
            $id = (int) $this->db->lastInsertId();
            $this->db->prepare("UPDATE site_directory SET cred_state = 'waiting', cred_set_at = UTC_TIMESTAMP(), cred_error = '', updated_at = UTC_TIMESTAMP() WHERE site_id = :s")
                ->execute(['s' => $siteId]);
            $this->db->commit();
            return $id;
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Sealed passwords waiting for this agent (expired ones are deleted first, and their sites told so).
     *
     * @return list<array<string,mixed>>
     */
    public function dropsFor(int $agentId): array
    {
        $this->expire();
        $stmt = $this->db->prepare('SELECT * FROM agent_secret_drops WHERE agent_id = :a ORDER BY id');
        $stmt->execute(['a' => $agentId]);
        return $stmt->fetchAll();
    }

    /**
     * The agent's answer about a drop. The drop is deleted either way: opened and kept (the site's password is now
     * held by this agent), or refused (why, shortened). Returns false when it's not this agent's drop.
     */
    public function acknowledge(int $agentId, int $dropId, bool $ok, string $error): bool
    {
        $stmt = $this->db->prepare('SELECT site_id FROM agent_secret_drops WHERE id = :d AND agent_id = :a');
        $stmt->execute(['d' => $dropId, 'a' => $agentId]);
        $siteId = $stmt->fetchColumn();
        if ($siteId === false) {
            return false;
        }
        $this->db->prepare('DELETE FROM agent_secret_drops WHERE id = :d')->execute(['d' => $dropId]);
        if ($ok) {
            $this->db->prepare("UPDATE site_directory SET cred_state = 'held', cred_agent_id = :a, cred_confirmed_at = UTC_TIMESTAMP(), cred_error = '', updated_at = UTC_TIMESTAMP() WHERE site_id = :s")
                ->execute(['a' => $agentId, 's' => $siteId]);
        } else {
            $this->db->prepare("UPDATE site_directory SET cred_state = 'failed', cred_error = :e, updated_at = UTC_TIMESTAMP() WHERE site_id = :s")
                ->execute(['e' => mb_substr($error !== '' ? $error : 'The agent could not open it.', 0, 255), 's' => $siteId]);
        }
        return true;
    }

    /**
     * Whether this agent should delete a directory password it holds: its site has no directory settings any more, the
     * password is for another account than the site's (it was changed, and the new one never arrived), or it is held
     * by another agent. $heldUser: the account the agent says its password is for (null from older agents).
     */
    public function shouldForget(int $agentId, int $siteId, ?string $heldUser = null): bool
    {
        $row = $this->find($siteId);
        if ($row === null || $row['cred_state'] === 'none') {
            return true;
        }
        if ($heldUser !== null && $heldUser !== (string) $row['username']) {
            return true;
        }
        return $row['cred_state'] === 'held' && (int) $row['cred_agent_id'] !== $agentId;
    }

    /** The agent's public key changed (reinstalled, or its key file lost): a password it held can't be opened any more. */
    public function agentKeyChanged(int $agentId): void
    {
        $this->db->prepare("UPDATE site_directory SET cred_state = 'failed', cred_error = 'The agent has a new key (reinstalled?): set the password again.', updated_at = UTC_TIMESTAMP()
                            WHERE cred_agent_id = :a AND cred_state = 'held'")->execute(['a' => $agentId]);
        $this->db->prepare('DELETE FROM agent_secret_drops WHERE agent_id = :a')->execute(['a' => $agentId]);
    }

    /** Delete drops nobody collected in time, and say so on their sites. */
    public function expire(): void
    {
        $this->db->exec("UPDATE site_directory d JOIN agent_secret_drops x ON x.site_id = d.site_id AND x.expires_at < UTC_TIMESTAMP()
                         SET d.cred_state = 'failed', d.cred_error = 'Not delivered: the agent did not check in within " . self::DROP_HOURS . " hours. Set the password again.'
                         WHERE d.cred_state = 'waiting'");
        $this->db->exec('DELETE FROM agent_secret_drops WHERE expires_at < UTC_TIMESTAMP()');
    }

    /**
     * Save what a full agent scan found in the directory (results already validated and shortened by the caller).
     * A read that failed keeps the earlier results: no answer is not evidence of a fix.
     *
     * @param array<string,mixed>|null $results
     */
    public function saveResults(int $siteId, ?array $results, string $error, string $certSeen, string $certSubject): void
    {
        $sets = ['last_error = :e', 'last_attempt_at = UTC_TIMESTAMP()'];
        $params = ['e' => mb_substr($error, 0, 500), 's' => $siteId];
        if ($results !== null) {
            $sets[] = 'results = :r';
            $sets[] = 'checked_at = UTC_TIMESTAMP()';
            $params['r'] = json_encode($results, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        }
        if ($certSeen !== '') {
            $sets[] = 'cert_seen = :cs';
            $sets[] = 'cert_seen_subject = :csub';
            $sets[] = 'cert_seen_at = UTC_TIMESTAMP()';
            $params['cs'] = $certSeen;
            $params['csub'] = mb_substr($certSubject, 0, 255);
        }
        $this->db->prepare('UPDATE site_directory SET ' . implode(', ', $sets) . ' WHERE site_id = :s')->execute($params);
    }
}
