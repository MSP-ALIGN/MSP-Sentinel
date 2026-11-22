<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

/**
 * The agent's connection to Sentinel: JSON POSTs over HTTPS with certificate
 * checks, the agent token as a bearer token. Only outbound connections.
 *
 * Security assumptions: the server URL is https:// (plain http only to
 * 127.0.0.1 in the test suite); TLS certificates are always verified (an
 * optional CA file for private CAs); the token is never logged or put in a
 * URL. Responses are untrusted JSON.
 */
final class Http
{
    /** @param bool $testMode Allows http://127.0.0.1 (test suite only). */
    public function __construct(private readonly string $server, private readonly ?string $token, private readonly ?string $caFile = null, private readonly bool $testMode = false)
    {
        $scheme = strtolower((string) parse_url($server, PHP_URL_SCHEME));
        $host = (string) parse_url($server, PHP_URL_HOST);
        if ($scheme !== 'https' && !($testMode && $scheme === 'http' && $host === '127.0.0.1')) {
            throw new \InvalidArgumentException('The Sentinel address must start with https://');
        }
    }

    /**
     * POST JSON and decode the JSON answer.
     *
     * @param array<string,mixed> $body
     * @return array{status:int, data:array<string,mixed>}
     * @throws \RuntimeException When Sentinel can't be reached.
     */
    public function post(string $path, array $body, int $timeout = 30): array
    {
        $ch = curl_init(rtrim($this->server, '/') . $path);
        $headers = ['Content-Type: application/json', 'Accept: application/json'];
        if ($this->token !== null) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }
        curl_setopt_array($ch, [
            CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($body, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | ($this->testMode ? CURLPROTO_HTTP : 0),
            CURLOPT_USERAGENT => 'MSP-Sentinel-Agent', CURLOPT_MAXFILESIZE => 16 * 1024 * 1024,
        ]);
        if ($this->caFile !== null && $this->caFile !== '') {
            curl_setopt($ch, CURLOPT_CAINFO, $this->caFile);
        }
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        if (!is_string($raw)) {
            throw new \RuntimeException('Sentinel could not be reached: ' . $error);
        }
        $data = json_decode($raw, true);
        return ['status' => $status, 'data' => is_array($data) ? $data : []];
    }
}
