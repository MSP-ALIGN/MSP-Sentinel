<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

use Sentinel\Agent\Signer;

/**
 * Moving the agent to a new Sentinel address (and CA), as an admin set on Administration, System.
 *
 * The agent's config (/etc/sentinel-agent/agent.json) is root-owned and read-only for the service, so the new address
 * is kept as an override in the agent's state folder (server-override.json, with its CA as ca-override.pem), which the
 * agent program reads at start-up instead of the configured address. Nothing about what the agent TRUSTS changes: the
 * pinned server key, site and client stay as they were enrolled.
 *
 * Before switching (tryMove):
 * - the instruction must be signed with the pinned server key, for this agent, site and client, and recent;
 * - the new address must prove it is the same Sentinel: asked WITHOUT the agent's token (nothing secret goes to an
 *   unproven address), it returns a signature over a random nonce, this agent and ITS OWN address, made with the server
 *   key, checked against the PINNED key. Sentinel only signs for the address an admin set (with their password; the
 *   setting is encrypted with the app key), so relaying the proof from another address doesn't work.
 * After switching:
 * - probation: during the first PROBATION_HOURS, until PROBATION_CHECKINS good check-ins, MAX_FAILURES failed
 *   check-ins in a row (or a refusal of its token) send the agent back to its configured address, and it says so;
 * - recall: every RECALL_HOURS the agent asks its configured (original, read-only) address what it should use. A
 *   signed answer naming another address, or none, ends the override: Sentinel can always bring its agents back.
 * The override names this agent and the pinned server key: one from another enrolment is ignored.
 *
 * Untrusted: the instruction and everything the new address answers. The CA certificate is only used for the TLS
 * connection to that address, and checked to be PEM certificates.
 */
final class Mover
{
    public const MAX_FAILURES = 10;
    public const PROBATION_HOURS = 24;
    public const PROBATION_CHECKINS = 20;
    public const RECALL_HOURS = 6;
    private const MAX_CA = 32768;

    /**
     * @param callable(string):void $log
     * @param string  $configuredServer the address in the (read-only) config: fallback and recall go there
     * @param ?string $configuredCa     its CA file, if any
     */
    public function __construct(private readonly string $stateDir, private readonly string $serverKey, private readonly int $agentId, private readonly int $siteId,
        private readonly int $clientId, private readonly string $token, private readonly bool $testMode, private $log,
        private readonly string $configuredServer = '', private readonly ?string $configuredCa = null)
    {
    }

    /**
     * The address to use instead of the configured one, if the agent moved.
     *
     * @return array{server:string, ca_file:?string}|null
     */
    public function override(): ?array
    {
        $o = $this->read();
        if ($o !== null && !isset($o['agent_id']) && !isset($o['key']) && is_string($o['server'] ?? null) && self::validServer($o['server'], $this->testMode)) {
            // A move made by a 1.23.0 agent (its file has no enrolment binding): adopt it once, as past probation, so the
            // upgrade never sends agents back to an address that may be gone.
            $o += ['agent_id' => $this->agentId, 'key' => $this->keyId(), 'good' => self::PROBATION_CHECKINS, 'recall_checked_at' => gmdate('Y-m-d\TH:i:s\Z')];
            $o['moved_at'] = gmdate('Y-m-d\TH:i:s\Z', time() - (self::PROBATION_HOURS + 1) * 3600);
            $this->write($o);
        }
        if ($o === null || !is_string($o['server'] ?? null) || !self::validServer($o['server'], $this->testMode)
            || ($o['agent_id'] ?? null) !== $this->agentId || ($o['key'] ?? null) !== $this->keyId()) {
            return null; // none, or written for another enrolment
        }
        $ca = ($o['ca_file'] ?? null) === $this->stateDir . '/ca-override.pem' && is_file($o['ca_file']) ? $o['ca_file'] : null;
        return ['server' => $o['server'], 'ca_file' => $ca];
    }

    /** Whether an address is acceptable: https://host[:port] only (http://127.0.0.1 in the test suite). */
    public static function validServer(string $url, bool $testMode): bool
    {
        return preg_match('#^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$#', $url) === 1
            || ($testMode && preg_match('#^http://127\.0\.0\.1(:[0-9]{1,5})?/?$#', $url) === 1);
    }

    /**
     * The new address and CA a signed move instruction asks for, or null when it isn't one for this agent.
     *
     * @param array<string,mixed> $signed
     * @return array{server:string, ca_pem:string, move_id:string}|null
     */
    public function requested(array $signed): ?array
    {
        if (!is_string($signed['payload'] ?? null) || !is_string($signed['signature'] ?? null) || !Signer::verify($signed['payload'], $signed['signature'], $this->serverKey)) {
            return null;
        }
        $d = json_decode($signed['payload'], true);
        $issued = is_array($d) ? strtotime((string) ($d['issued_at'] ?? '')) : false;
        if (!is_array($d) || ($d['type'] ?? null) !== 'agent_move' || ($d['agent_id'] ?? null) !== $this->agentId || ($d['site_id'] ?? null) !== $this->siteId
            || ($d['client_id'] ?? null) !== $this->clientId || $issued === false || abs(time() - $issued) > 3600
            || !is_string($d['server'] ?? null) || !self::validServer($d['server'], $this->testMode) || !is_string($d['ca_pem'] ?? null)) {
            return null;
        }
        return ['server' => rtrim($d['server'], '/'), 'ca_pem' => $d['ca_pem'], 'move_id' => is_string($d['move_id'] ?? null) ? mb_substr($d['move_id'], 0, 32) : ''];
    }

    /**
     * Prove and switch. Returns '' when the agent moved (restart it to use the new address), else why not. The result
     * is reported to Sentinel (at the new address when it worked, else at the current one).
     */
    public function tryMove(string $server, string $caPem, Http $current, string $moveId = ''): string
    {
        $why = $this->prove($server, $caPem, $moveId);
        if ($why === '') {
            $this->report($this->http($server, $this->stateDir . '/ca-override.pem'), $server, true, 'Moved to ' . $server . '.');
            ($this->log)('Moved to ' . $server . ' (it proved it holds this Sentinel\'s key). Restarting to use it.');
            return '';
        }
        ($this->log)('Not moved to ' . $server . ': ' . $why);
        $this->report($current, $server, false, $why);
        return $why;
    }

    /**
     * A check-in at the moved-to address failed; true when the agent should go back to its configured address
     * (restart). Only during probation: afterwards the move is permanent (an outage at the new address mustn't strand
     * agents at an old address that may be gone; recall still works).
     */
    public function checkInFailed(): bool
    {
        $o = $this->read();
        if ($o === null || !$this->inProbation($o)) {
            return false;
        }
        $o['failures'] = (int) ($o['failures'] ?? 0) + 1;
        if ($o['failures'] >= self::MAX_FAILURES) {
            $this->fallBack('The new address failed ' . self::MAX_FAILURES . ' check-ins in a row right after the move.');
            return true;
        }
        $this->write($o);
        return false;
    }

    /** A check-in at the moved-to address worked. */
    public function checkInWorked(): void
    {
        $o = $this->read();
        if ($o !== null) {
            $o['failures'] = 0;
            $o['good'] = (int) ($o['good'] ?? 0) + 1;
            $this->write($o);
        }
    }

    /**
     * A token refusal (401) at the moved-to address: during probation the agent goes back (true: restart). After
     * probation it stays (a misrouted proxy shouldn't undo a finished move; recall still works). Never wiped either way.
     */
    public function refusedAtNewAddress(): bool
    {
        $o = $this->read();
        if ($o === null || !$this->inProbation($o)) {
            ($this->log)('The new address refused the agent\'s token; staying (the move is past its trial period). Sentinel can recall the agent.');
            return false;
        }
        $this->fallBack('The new address refused the agent\'s token.');
        return true;
    }

    /**
     * Go back to the configured address, and tell Sentinel there (so it doesn't hand out the same move again at once).
     */
    public function fallBack(string $why): void
    {
        $o = $this->read();
        @unlink($this->stateDir . '/server-override.json');
        @unlink($this->stateDir . '/ca-override.pem');
        ($this->log)($why . ' Going back to the configured address ' . $this->configuredServer . '.');
        if ($this->configuredServer !== '' && is_string($o['server'] ?? null)) {
            $this->report($this->http($this->configuredServer, $this->configuredCa), (string) $o['server'], false, $why . ' The agent went back to its configured address.');
        }
    }

    /** Whether it is time to ask the configured address about the move (while moved). */
    public function recallDue(): bool
    {
        $o = $this->read();
        return $o !== null && strtotime((string) ($o['recall_checked_at'] ?? $o['moved_at'] ?? '')) < time() - self::RECALL_HOURS * 3600;
    }

    /**
     * Ask the configured (original) address which address to use (signed answer). True when the override ended (restart
     * onto the configured address; a new move there is proven again). An unreachable configured address changes nothing.
     */
    public function recall(): bool
    {
        $o = $this->read();
        if ($o === null || $this->configuredServer === '') {
            return false;
        }
        $o['recall_checked_at'] = gmdate('Y-m-d\TH:i:s\Z');
        $this->write($o);
        try {
            $res = $this->http($this->configuredServer, $this->configuredCa)->post('/agent/v1/move/check', [], 20);
        } catch (\Throwable) {
            return false;
        }
        $ok = $res['status'] === 200 && is_string($res['data']['payload'] ?? null) && is_string($res['data']['signature'] ?? null)
            && Signer::verify($res['data']['payload'], $res['data']['signature'], $this->serverKey);
        $d = $ok ? json_decode($res['data']['payload'], true) : null;
        $issued = is_array($d) ? strtotime((string) ($d['issued_at'] ?? '')) : false;
        if (!is_array($d) || ($d['type'] ?? null) !== 'agent_move_status' || ($d['agent_id'] ?? null) !== $this->agentId || !is_string($d['server'] ?? null)
            || $issued === false || abs(time() - $issued) > 3600) {
            return false;
        }
        $sameMove = rtrim($d['server'], '/') === rtrim((string) $o['server'], '/')
            && (!is_string($d['move_id'] ?? null) || $d['move_id'] === '' || (string) ($o['move_id'] ?? '') === '' || $d['move_id'] === $o['move_id']);
        if ($sameMove) {
            return false; // still the move Sentinel wants
        }
        @unlink($this->stateDir . '/server-override.json');
        @unlink($this->stateDir . '/ca-override.pem');
        ($this->log)('Sentinel (at the configured address) no longer wants this agent at ' . $o['server'] . ': going back.');
        return true;
    }

    /** @param array<string,mixed> $o */
    private function inProbation(array $o): bool
    {
        return strtotime((string) ($o['moved_at'] ?? '')) > time() - self::PROBATION_HOURS * 3600 && (int) ($o['good'] ?? 0) < self::PROBATION_CHECKINS;
    }

    /** @return array<string,mixed>|null */
    private function read(): ?array
    {
        $o = json_decode((string) @file_get_contents($this->stateDir . '/server-override.json'), true);
        return is_array($o) ? $o : null;
    }

    private function keyId(): string
    {
        return substr(hash('sha256', $this->serverKey), 0, 16);
    }

    private function prove(string $server, string $caPem, string $moveId = ''): string
    {
        $caFile = null;
        if (trim($caPem) !== '') {
            if (strlen($caPem) > self::MAX_CA || preg_match_all('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $caPem, $m) < 1) {
                return 'The CA given is not a PEM certificate.';
            }
            foreach ($m[0] as $pem) {
                if (@openssl_x509_read($pem) === false) {
                    return 'The CA given is not a valid certificate.';
                }
            }
            $caFile = $this->stateDir . '/ca-candidate.pem';
            if (!$this->writeFile($caFile, implode("\n", $m[0]) . "\n")) {
                return 'Could not save the CA in the agent\'s folder.';
            }
        }
        $nonce = bin2hex(random_bytes(16));
        // No token: nothing secret goes to an address before it proved itself. Without a CA given, the system CAs are
        // tried first and then the configured private CA (the same CA under a new name).
        $attempts = $caFile !== null ? [$caFile] : array_values(array_unique([null, $this->configuredCa]));
        $res = null;
        $error = '';
        foreach ($attempts as $ca) {
            try {
                $res = (new Http($server, null, $ca, $this->testMode))->post('/agent/v1/prove', ['agent_id' => $this->agentId, 'nonce' => $nonce, 'server' => $server], 20);
                $usedCa = $ca;
                break;
            } catch (\Throwable $ex) {
                $error = mb_substr($ex->getMessage(), 0, 150);
            }
        }
        if ($res === null) {
            @unlink((string) $caFile);
            return 'The new address could not be reached: ' . $error;
        }
        $ok = $res['status'] === 200 && is_string($res['data']['payload'] ?? null) && is_string($res['data']['signature'] ?? null)
            && Signer::verify($res['data']['payload'], $res['data']['signature'], $this->serverKey);
        $p = $ok ? json_decode($res['data']['payload'], true) : null;
        if (!is_array($p) || ($p['type'] ?? null) !== 'agent_prove' || ($p['agent_id'] ?? null) !== $this->agentId || ($p['nonce'] ?? null) !== $nonce
            || ($p['server'] ?? null) !== $server) {
            @unlink((string) $caFile);
            return 'The new address did not prove it is this Sentinel (no valid signature for that address).';
        }
        $caTarget = $this->stateDir . '/ca-override.pem';
        $caInUse = $usedCa ?? null;
        if ($caFile !== null) {
            if (!rename($caFile, $caTarget)) {
                return 'Could not save the CA in the agent\'s folder.';
            }
            $caInUse = $caTarget;
        } elseif ($caInUse !== null) {
            if (!copy($caInUse, $caTarget)) {
                return 'Could not save the CA in the agent\'s folder.';
            }
            $caInUse = $caTarget;
        } else {
            @unlink($caTarget);
        }
        if (!$this->write(['server' => $server, 'ca_file' => $caInUse, 'moved_at' => gmdate('Y-m-d\TH:i:s\Z'), 'failures' => 0, 'good' => 0,
                           'agent_id' => $this->agentId, 'key' => $this->keyId(), 'move_id' => $moveId])) {
            return 'Could not save the new address in the agent\'s folder.';
        }
        return '';
    }

    private function http(string $server, ?string $caFile): Http
    {
        return new Http($server, $this->token, $caFile !== null && is_file($caFile) ? $caFile : null, $this->testMode);
    }

    private function report(Http $http, string $server, bool $ok, string $message): void
    {
        try {
            $http->post('/agent/v1/move/result', ['server' => $server, 'ok' => $ok, 'message' => mb_substr($message, 0, 300)]);
        } catch (\Throwable) {
            // shown on the next try
        }
    }

    /** @param array<string,mixed> $o */
    private function write(array $o): bool
    {
        return $this->writeFile($this->stateDir . '/server-override.json', (string) json_encode($o, JSON_UNESCAPED_SLASHES));
    }

    private function writeFile(string $path, string $content): bool
    {
        $old = umask(0077);
        $ok = file_put_contents($path . '.tmp', $content) === strlen($content);
        umask($old);
        return $ok && chmod($path . '.tmp', 0600) && rename($path . '.tmp', $path);
    }
}
