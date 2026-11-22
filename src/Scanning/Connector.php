<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use Sentinel\Core\Config;

/**
 * Decides where a TLS or HTTP check actually connects to.
 *
 * In production this is always the target IP and port, unchanged.
 *
 * TEST SUITE ONLY: the tests must never contact real or documentation
 * addresses, so `testing.redirect_connections` (a map of "ip:port" to a
 * 127.0.0.1 port) sends those connections to local mock servers. It is only
 * honoured when `testing.allow_documentation_ranges` is also on, and it can
 * only redirect to 127.0.0.1, so a config mistake can't redirect a scan to
 * some other host. In test mode, a target WITHOUT a mapping is refused
 * (endpoint() throws), so a test can never reach the network by accident.
 *
 * Security assumptions: the target IP has been checked against the scope by
 * the caller. This class never widens where Sentinel connects.
 */
final class Connector
{
    /**
     * @param array<string,int> $redirects "ip:port" => local port (tests only).
     * @param bool              $testMode  True: unmapped targets are refused instead of contacted.
     */
    private function __construct(private readonly array $redirects, private readonly bool $testMode = false)
    {
    }

    /** Build from config. In production the redirect map is always empty. */
    public static function fromConfig(Config $config): self
    {
        $map = [];
        $testMode = $config->get('testing.allow_documentation_ranges', false) === true;
        if ($testMode) {
            foreach ((array) $config->get('testing.redirect_connections', []) as $from => $toPort) {
                if (is_string($from) && is_int($toPort) && $toPort > 0 && $toPort < 65536) {
                    $map[$from] = $toPort;
                }
            }
        }
        return new self($map, $testMode);
    }

    /** Production instance (no redirects), for unit tests and defaults. */
    public static function direct(): self
    {
        return new self([]);
    }

    /**
     * Address and port to really connect to for this target.
     *
     * @return array{0:string,1:int}
     * @throws \RuntimeException in test mode when the target has no mock server mapped.
     */
    public function endpoint(string $ip, int $port): array
    {
        $key = (str_contains($ip, ':') ? '[' . $ip . ']' : $ip) . ':' . $port;
        if (isset($this->redirects[$key])) {
            return ['127.0.0.1', $this->redirects[$key]];
        }
        if ($this->testMode) {
            throw new \RuntimeException('Test mode: no mock server for ' . $key . ', connection refused.');
        }
        return [$ip, $port];
    }

    /** "host:port" string for stream_socket_client, with brackets for IPv6. */
    public static function hostPort(string $ip, int $port): string
    {
        return (str_contains($ip, ':') ? '[' . $ip . ']' : $ip) . ':' . $port;
    }
}
