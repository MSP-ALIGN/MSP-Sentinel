<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

use Sentinel\Agent\Signer;

/**
 * The directory password this agent holds for its site, received sealed through Sentinel.
 *
 * accept() takes a drop from a check-in answer only when it is signed by the pinned server key, is for this agent,
 * site and client, hasn't expired or been seen before, and opens with this agent's key under the exact binding
 * (agent ID, the drop's nonce, its user name). The file keeps the SEALED box, not the password (0600, the agent's
 * user only): password() opens it in memory when a check needs it.
 *
 * Untrusted: every drop and instruction (they arrive over the network); only the signature, the IDs pinned at
 * enrolment and the agent's own key decide.
 */
final class Credentials
{
    private const MAX_SEEN = 200;
    /** A "forget it" instruction older than this is ignored (it is signed, but shouldn't live for ever). */
    private const FORGET_MAX_AGE = 86400;

    public function __construct(private readonly string $file, private readonly AgentKey $key, private readonly string $serverKey,
        private readonly int $agentId, private readonly int $siteId, private readonly int $clientId)
    {
    }

    /** Whether a directory password is held. */
    public function holds(): bool
    {
        return is_string($this->read()['sealed'] ?? null);
    }

    /** The user name the held password is for ('' when none). */
    public function username(): string
    {
        return (string) ($this->read()['username'] ?? '');
    }

    /** The held password, opened now (null when none or it no longer opens). */
    public function password(): ?string
    {
        $d = $this->read();
        if (!is_string($d['sealed'] ?? null)) {
            return null;
        }
        return $this->key->open($d['sealed'], AgentKey::directoryAad($this->agentId, (string) $d['nonce'], (string) $d['username']));
    }

    /**
     * Take a signed drop from a check-in answer.
     *
     * @return array{drop_id:int, ok:bool, error:string}|null null when it isn't a drop for this agent at all (no answer
     *         is sent: the server's own ID can't be trusted then).
     */
    public function accept(string $payload, string $signature, ?int $now = null): ?array
    {
        $now ??= time();
        if (!Signer::verify($payload, $signature, $this->serverKey)) {
            return null;
        }
        $d = json_decode($payload, true);
        if (!is_array($d) || ($d['v'] ?? null) !== 1 || ($d['type'] ?? null) !== 'agent_secret' || ($d['purpose'] ?? null) !== 'directory_password'
            || ($d['agent_id'] ?? null) !== $this->agentId || ($d['site_id'] ?? null) !== $this->siteId || ($d['client_id'] ?? null) !== $this->clientId
            || !is_int($d['drop_id'] ?? null) || $d['drop_id'] < 1) {
            return null;
        }
        $state = $this->read();
        $fail = static fn (string $why): array => ['drop_id' => (int) $d['drop_id'], 'ok' => false, 'error' => $why];
        // The drop we already hold, sent again because our confirmation was lost: confirm again, change nothing.
        if (($state['drop_id'] ?? null) === $d['drop_id'] && is_string($state['sealed'] ?? null) && hash_equals($state['sealed'], (string) ($d['sealed'] ?? ''))) {
            return ['drop_id' => (int) $d['drop_id'], 'ok' => true, 'error' => ''];
        }
        if (in_array($d['drop_id'], (array) ($state['seen'] ?? []), true)) {
            return $fail('Already received (replay).');
        }
        $expires = strtotime((string) ($d['expires_at'] ?? ''));
        if ($expires === false || $expires < $now) {
            return $fail('Expired before it arrived.');
        }
        $nonce = $d['nonce'] ?? null;
        $user = $d['username'] ?? null;
        if (!is_string($nonce) || preg_match('/^[0-9a-f]{32}$/', $nonce) !== 1 || !is_string($user) || $user === '' || strlen($user) > 256 || preg_match('/[\x00-\x1F\x7F]/', $user)) {
            return $fail('Malformed.');
        }
        // Each box carries a one-off number: an old box re-sent under a new drop ID (e.g. restored from a backup to
        // roll back to an older password or account) is refused.
        if (in_array($nonce, (array) ($state['nonces'] ?? []), true)) {
            return $fail('This sealed password was already used once (replay).');
        }
        $sealed = is_string($d['sealed'] ?? null) ? $d['sealed'] : '';
        $password = $this->key->open($sealed, AgentKey::directoryAad($this->agentId, $nonce, $user));
        if ($password === null || $password === '') {
            $this->write(['seen' => array_slice([...(array) ($state['seen'] ?? []), $d['drop_id']], -self::MAX_SEEN)] + $state);
            return $fail('It does not open with this agent\'s key (sealed for another agent, or changed on the way).');
        }
        // Keep the box, not the password.
        $this->write(['sealed' => $sealed, 'nonce' => $nonce, 'username' => $user, 'drop_id' => $d['drop_id'], 'received_at' => gmdate('Y-m-d H:i:s', $now),
                      'seen' => array_slice([...(array) ($state['seen'] ?? []), $d['drop_id']], -self::MAX_SEEN),
                      'nonces' => array_slice([...(array) ($state['nonces'] ?? []), $nonce], -self::MAX_SEEN)]);
        return ['drop_id' => (int) $d['drop_id'], 'ok' => true, 'error' => ''];
    }

    /**
     * Delete the held password when Sentinel says so (signed, for this agent, issued within FORGET_MAX_AGE). Returns
     * true when it was deleted.
     */
    public function forget(string $payload, string $signature, ?int $now = null): bool
    {
        $now ??= time();
        if (!Signer::verify($payload, $signature, $this->serverKey)) {
            return false;
        }
        $d = json_decode($payload, true);
        if (!is_array($d) || ($d['type'] ?? null) !== 'agent_forget' || ($d['purpose'] ?? null) !== 'directory_password'
            || ($d['agent_id'] ?? null) !== $this->agentId || ($d['site_id'] ?? null) !== $this->siteId || ($d['client_id'] ?? null) !== $this->clientId) {
            return false;
        }
        $issued = strtotime((string) ($d['issued_at'] ?? ''));
        if ($issued === false || $issued < $now - self::FORGET_MAX_AGE || $issued > $now + 300) {
            return false;
        }
        $this->wipe();
        return true;
    }

    /**
     * Delete the held password (keeping the replay lists). Also used when Sentinel revokes this agent: the sealed box
     * and the agent's private key sit side by side on the appliance, so they must not outlive the agent.
     */
    public function wipe(): void
    {
        $state = $this->read();
        $this->write(['seen' => (array) ($state['seen'] ?? []), 'nonces' => (array) ($state['nonces'] ?? [])]);
    }

    /** @return array<string,mixed> */
    private function read(): array
    {
        $data = is_file($this->file) ? json_decode((string) file_get_contents($this->file), true) : null;
        return is_array($data) ? $data : [];
    }

    /** @param array<string,mixed> $data */
    private function write(array $data): void
    {
        $old = umask(0077);
        file_put_contents($this->file . '.tmp', json_encode($data, JSON_UNESCAPED_SLASHES));
        umask($old);
        chmod($this->file . '.tmp', 0600);
        rename($this->file . '.tmp', $this->file);
    }
}
