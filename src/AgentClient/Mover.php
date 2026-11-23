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
 * - the new address must prove it is the same Sentinel: it signs a random nonce with the server key (POST
 *   /agent/v1/prove), checked against the PINNED key. A wrong or impostor address gets nothing: no results, no
 *   diagnostics, nothing sealed.
 * After switching, the new address must keep answering: after MAX_FAILURES failed check-ins in a row the override is
 * removed and the agent goes back to its configured address on its own.
 *
 * Untrusted: the instruction and everything the new address answers. The CA certificate is only used for the TLS
 * connection to that address, and checked to be PEM certificates.
 */
final class Mover
{
    public const MAX_FAILURES = 10;
    private const MAX_CA = 32768;

    /** @param callable(string):void $log */
    public function __construct(private readonly string $stateDir, private readonly string $serverKey, private readonly int $agentId, private readonly int $siteId,
        private readonly int $clientId, private readonly string $token, private readonly bool $testMode, private $log)
    {
    }

    /**
     * The address to use instead of the configured one, if the agent moved.
     *
     * @return array{server:string, ca_file:?string}|null
     */
    public function override(): ?array
    {
        $o = json_decode((string) @file_get_contents($this->stateDir . '/server-override.json'), true);
        if (!is_array($o) || !is_string($o['server'] ?? null) || !self::validServer($o['server'], $this->testMode)) {
            return null;
        }
        $ca = is_string($o['ca_file'] ?? null) && is_file($o['ca_file']) ? $o['ca_file'] : null;
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
     * @return array{server:string, ca_pem:string}|null
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
        return ['server' => rtrim($d['server'], '/'), 'ca_pem' => $d['ca_pem']];
    }

    /**
     * Prove and switch. Returns '' when the agent moved (restart it to use the new address), else why not. The result
     * is reported to Sentinel (at the new address when it worked, else at the current one).
     */
    public function tryMove(string $server, string $caPem, Http $current): string
    {
        $why = $this->prove($server, $caPem);
        if ($why === '') {
            $this->report($this->http($server, $this->stateDir . '/ca-override.pem'), $server, true, 'Moved to ' . $server . '.');
            ($this->log)('Moved to ' . $server . ' (it proved it holds this Sentinel\'s key). Restarting to use it.');
            return '';
        }
        ($this->log)('Not moved to ' . $server . ': ' . $why);
        $this->report($current, $server, false, $why);
        return $why;
    }

    /** A check-in failed; true when the agent should go back to its configured address (restart). */
    public function checkInFailed(): bool
    {
        $o = json_decode((string) @file_get_contents($this->stateDir . '/server-override.json'), true);
        if (!is_array($o)) {
            return false;
        }
        $o['failures'] = (int) ($o['failures'] ?? 0) + 1;
        if ($o['failures'] >= self::MAX_FAILURES) {
            @unlink($this->stateDir . '/server-override.json');
            @unlink($this->stateDir . '/ca-override.pem');
            ($this->log)('The new Sentinel address failed ' . self::MAX_FAILURES . ' check-ins in a row: going back to the configured address.');
            return true;
        }
        $this->write($o);
        return false;
    }

    /** A check-in worked: reset the failure count. */
    public function checkInWorked(): void
    {
        $o = json_decode((string) @file_get_contents($this->stateDir . '/server-override.json'), true);
        if (is_array($o) && (int) ($o['failures'] ?? 0) !== 0) {
            $o['failures'] = 0;
            $this->write($o);
        }
    }

    private function prove(string $server, string $caPem): string
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
            $this->writeFile($caFile, implode("\n", $m[0]) . "\n");
        }
        $nonce = bin2hex(random_bytes(16));
        try {
            $res = $this->http($server, $caFile)->post('/agent/v1/prove', ['nonce' => $nonce], 20);
        } catch (\Throwable $ex) {
            @unlink((string) $caFile);
            return 'The new address could not be reached: ' . mb_substr($ex->getMessage(), 0, 150);
        }
        $ok = $res['status'] === 200 && is_string($res['data']['payload'] ?? null) && is_string($res['data']['signature'] ?? null)
            && Signer::verify($res['data']['payload'], $res['data']['signature'], $this->serverKey);
        $p = $ok ? json_decode($res['data']['payload'], true) : null;
        if (!is_array($p) || ($p['type'] ?? null) !== 'agent_prove' || ($p['agent_id'] ?? null) !== $this->agentId || ($p['nonce'] ?? null) !== $nonce) {
            @unlink((string) $caFile);
            return 'The new address did not prove it is this Sentinel (no valid signature with its key).';
        }
        if ($caFile !== null) {
            rename($caFile, $this->stateDir . '/ca-override.pem');
        } else {
            @unlink($this->stateDir . '/ca-override.pem');
        }
        $this->write(['server' => $server, 'ca_file' => $caFile !== null ? $this->stateDir . '/ca-override.pem' : null, 'moved_at' => gmdate('Y-m-d\TH:i:s\Z'), 'failures' => 0]);
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
    private function write(array $o): void
    {
        $this->writeFile($this->stateDir . '/server-override.json', (string) json_encode($o, JSON_UNESCAPED_SLASHES));
    }

    private function writeFile(string $path, string $content): void
    {
        $old = umask(0077);
        file_put_contents($path . '.tmp', $content);
        umask($old);
        chmod($path . '.tmp', 0600);
        rename($path . '.tmp', $path);
    }
}
