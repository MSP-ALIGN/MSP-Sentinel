<?php

declare(strict_types=1);

namespace Sentinel\Discovery;

use Sentinel\Core\Config;

/**
 * A minimal DNS stub resolver: sends recursive queries to ONE configured
 * resolver over UDP (falling back to TCP for truncated answers).
 *
 * Why not dns_get_record()? It gives no control over the server, timeouts or
 * errors, and it can't be pointed at a fake server in tests.
 *
 * Security assumptions:
 * - Only the configured resolver (dns.resolver, default: the first
 *   nameserver in /etc/resolv.conf) is ever contacted, on dns.port.
 * - Each query has a random 16-bit ID and an OS-chosen random source port,
 *   and responses must match both ID and question (DnsMessage checks this).
 * - Timeouts are short (dns.timeout, default 2 s) and responses are size-capped.
 * - Discovery only sends lookups (passive). Nothing here connects to client systems.
 */
final class DnsClient
{
    private const MAX_UDP = 4096;
    private const MAX_TCP = 65535;

    /** Use fromConfig() normally. */
    public function __construct(private readonly string $server, private readonly int $port = 53, private readonly float $timeout = 2.0)
    {
        if (filter_var($server, FILTER_VALIDATE_IP) === false) {
            throw new \InvalidArgumentException('DNS resolver must be an IP address.');
        }
    }

    /**
     * Build from config: dns.resolver, dns.port, dns.timeout.
     *
     * @throws DnsException if no resolver is configured and none is found in /etc/resolv.conf.
     */
    public static function fromConfig(Config $config): self
    {
        $server = (string) $config->get('dns.resolver', '');
        if ($server === '') {
            $server = self::systemResolver() ?? throw new DnsException('No DNS resolver configured. Set dns.resolver in config/config.php.');
        }
        return new self($server, (int) $config->get('dns.port', 53), (float) $config->get('dns.timeout', 2.0));
    }

    /** First IP nameserver in /etc/resolv.conf, or null. */
    public static function systemResolver(): ?string
    {
        $conf = @file_get_contents('/etc/resolv.conf');
        if ($conf !== false && preg_match_all('/^\s*nameserver\s+(\S+)/m', $conf, $m)) {
            foreach ($m[1] as $candidate) {
                if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                    return $candidate;
                }
            }
        }
        return null;
    }

    /**
     * Look up one name and type.
     *
     * @param string $name Hostname or reverse name (validated by the caller).
     * @return list<array{name:string,type:int,ttl:int,data:string}> Answers (may include CNAMEs). Empty for "no such name".
     * @throws DnsException on timeout, server failure or malformed responses.
     */
    public function query(string $name, int $type): array
    {
        $id = random_int(0, 0xffff);
        $packet = DnsMessage::buildQuery($id, $name, $type);
        $response = $this->sendUdp($packet, $id);
        $parsed = DnsMessage::parseResponse($response, $id, $name, $type);
        if ($parsed['truncated']) {
            $parsed = DnsMessage::parseResponse($this->sendTcp($packet), $id, $name, $type);
        }
        if ($parsed['rcode'] === 3) {
            return []; // NXDOMAIN
        }
        if ($parsed['rcode'] !== 0) {
            throw new DnsException('DNS server returned error code ' . $parsed['rcode'] . '.');
        }
        return $parsed['answers'];
    }

    /**
     * Send over UDP, with one retry on timeout. Packets whose ID doesn't match
     * (late replies, spoofing attempts) are ignored while we keep waiting.
     */
    private function sendUdp(string $packet, int $id): string
    {
        $expected = pack('n', $id & 0xffff);
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $sock = @stream_socket_client('udp://' . $this->address(), $errno, $errstr, $this->timeout);
            if ($sock === false) {
                throw new DnsException('Could not reach the DNS resolver.');
            }
            fwrite($sock, $packet);
            $deadline = microtime(true) + $this->timeout;
            while (($left = $deadline - microtime(true)) > 0) {
                stream_set_timeout($sock, (int) $left, (int) (fmod($left, 1) * 1e6));
                $data = fread($sock, self::MAX_UDP);
                if ($data === false || $data === '' || stream_get_meta_data($sock)['timed_out']) {
                    break;
                }
                if (strlen($data) >= 2 && substr($data, 0, 2) === $expected) {
                    fclose($sock);
                    return $data;
                }
            }
            fclose($sock);
        }
        throw new DnsException('DNS query timed out.');
    }

    /** Send over TCP (2-byte length prefix), for answers too big for UDP. */
    private function sendTcp(string $packet): string
    {
        $sock = @stream_socket_client('tcp://' . $this->address(), $errno, $errstr, $this->timeout);
        if ($sock === false) {
            throw new DnsException('Could not reach the DNS resolver over TCP.');
        }
        stream_set_timeout($sock, (int) $this->timeout, (int) (fmod($this->timeout, 1) * 1e6));
        fwrite($sock, pack('n', strlen($packet)) . $packet);
        $lenBytes = (string) fread($sock, 2);
        if (strlen($lenBytes) !== 2) {
            fclose($sock);
            throw new DnsException('DNS TCP response truncated.');
        }
        $len = min(unpack('n', $lenBytes)[1], self::MAX_TCP);
        $data = '';
        while (strlen($data) < $len && !feof($sock)) {
            $chunk = fread($sock, $len - strlen($data));
            if ($chunk === false || $chunk === '' || stream_get_meta_data($sock)['timed_out']) {
                break;
            }
            $data .= $chunk;
        }
        fclose($sock);
        return $data;
    }

    /** "ip:port", with brackets for IPv6. */
    private function address(): string
    {
        return (str_contains($this->server, ':') ? '[' . $this->server . ']' : $this->server) . ':' . $this->port;
    }
}
