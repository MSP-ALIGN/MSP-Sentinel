<?php

declare(strict_types=1);

namespace Sentinel\Directory;

/**
 * A minimal, read-only LDAP client for the agent's Active Directory checks: LDAPS (TLS from the first byte), one
 * simple bind, paged subtree/base searches, unbind. Nothing that writes is implemented.
 *
 * Why not php-ldap: the appliance has no LDAP library, and this lets the agent check the domain controller's
 * certificate itself before anything is sent: connectTls() completes the TLS handshake and exposes the certificate's
 * SHA-256 fingerprint; the caller compares it with the fingerprint an admin trusted and only then calls bind() with the
 * password. (Certificate chains of internal CAs are not checked: the trusted fingerprint is the check.)
 *
 * signingRequired() asks the plain LDAP port whether it requires signing, by attempting a simple bind with a made-up
 * account and password: a domain controller that requires signing answers "stronger authentication required" before it
 * looks at the credentials, one that doesn't answers "invalid credentials". No real credential is ever sent there.
 *
 * Untrusted: everything the server sends (Ber checks every length; messages and entries are capped; only text
 * attributes are read, shortened by the caller). The password is only ever written to the TLS stream, never logged or
 * put in an exception message.
 */
final class LdapClient
{
    public const SCOPE_BASE = 0;
    public const SCOPE_SUBTREE = 2;
    public const SUCCESS = 0;
    public const STRONGER_AUTH_REQUIRED = 8;
    public const INVALID_CREDENTIALS = 49;
    private const PAGED_OID = '1.2.840.113556.1.4.319';
    private const MAX_MESSAGE = 4194304;
    /** Bytes of entries one search keeps at most (memory stays bounded whatever the server sends). */
    private const MAX_SEARCH_BYTES = 67108864;

    private int $messageId = 0;

    /** @param resource $stream */
    private function __construct(private $stream, private readonly float $deadline, private readonly array $cert)
    {
    }

    /**
     * Open LDAPS to $ip:$port (the caller has checked the address is in the signed scope, and maps it through the test
     * suite's Connector). TLS 1.2 or later. Throws LdapException when it can't connect or hand-shake.
     */
    public static function connectTls(string $ip, int $port, float $timeout = 60.0): self
    {
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true, // the pinned fingerprint is the check
            'capture_peer_cert' => true, 'SNI_enabled' => false,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
        ]]);
        $host = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $s = @stream_socket_client('ssl://' . $host . ':' . $port, $errno, $errstr, min(15.0, $timeout), STREAM_CLIENT_CONNECT, $ctx);
        if ($s === false) {
            throw new LdapException('Could not connect to LDAPS on ' . $ip . ':' . $port . ($errstr !== '' ? ' (' . mb_substr($errstr, 0, 120) . ')' : '') . '.');
        }
        $peer = stream_context_get_params($s)['options']['ssl']['peer_certificate'] ?? null;
        if (!$peer instanceof \OpenSSLCertificate) {
            fclose($s);
            throw new LdapException('The domain controller sent no certificate.');
        }
        $info = openssl_x509_parse($peer) ?: [];
        $cert = [
            'sha256' => (string) openssl_x509_fingerprint($peer, 'sha256'),
            'subject' => mb_substr(self::dnText($info['subject'] ?? []), 0, 255),
            'issuer' => mb_substr(self::dnText($info['issuer'] ?? []), 0, 255),
            'not_after' => isset($info['validTo_time_t']) ? gmdate('Y-m-d', (int) $info['validTo_time_t']) : '',
        ];
        return new self($s, microtime(true) + $timeout, $cert);
    }

    /** The domain controller's certificate: sha256 (hex, lower case), subject, issuer, not_after. @return array<string,string> */
    public function certificate(): array
    {
        return $this->cert;
    }

    /**
     * Simple bind. Returns the LDAP result code (0: signed in). Only call this after the certificate was checked.
     */
    public function bind(string $name, string $password): int
    {
        $id = ++$this->messageId;
        $this->send($id, Ber::tlv(0x60, Ber::int(3) . Ber::str($name) . Ber::str($password, 0x80)));
        $msg = $this->receive($id);
        if ($msg['op'] !== 0x61) {
            throw new LdapException('Unexpected answer to the sign-in.');
        }
        return self::resultCode($msg['body']);
    }

    /**
     * A search, following the paged-results control until done or $max entries. Returns entries with their text
     * attributes (attribute names in lower case).
     *
     * @param array<int,mixed> $filter ['and', [filters]] | ['eq', attr, value] | ['present', attr]
     * @param list<string> $attributes
     * @return list<array{dn:string, attrs:array<string,list<string>>}>
     */
    public function search(string $base, int $scope, array $filter, array $attributes, int $max = 50000, int $pageSize = 500): array
    {
        $out = [];
        $cookie = '';
        $cookies = [];
        $bytes = 0;
        do {
            $id = ++$this->messageId;
            $req = Ber::tlv(0x63, Ber::str($base) . Ber::int($scope, Ber::ENUMERATED) . Ber::int(0, Ber::ENUMERATED) . Ber::int(0) . Ber::int(0)
                . Ber::bool(false) . self::filter($filter) . Ber::seq(...array_map(static fn (string $a): string => Ber::str($a), $attributes)));
            $control = Ber::seq(Ber::str(self::PAGED_OID), Ber::bool(false), Ber::str(Ber::seq(Ber::int($pageSize), Ber::str($cookie))));
            $this->send($id, $req, Ber::tlv(0xA0, $control));
            $cookie = '';
            while (true) {
                $msg = $this->receive($id);
                if ($msg['op'] === 0x64) {
                    if (count($out) < $max) {
                        $bytes += strlen($msg['body']);
                        if ($bytes > self::MAX_SEARCH_BYTES) {
                            throw new LdapException('The directory answer is too large to read.');
                        }
                        $out[] = self::entry($msg['body']);
                    }
                    continue;
                }
                if ($msg['op'] === 0x73) {
                    continue; // a referral to another domain: not followed
                }
                if ($msg['op'] !== 0x65) {
                    throw new LdapException('Unexpected answer to a search.');
                }
                $code = self::resultCode($msg['body']);
                if ($code !== self::SUCCESS) {
                    throw new LdapException('The directory refused a search (LDAP result ' . $code . ').');
                }
                $cookie = self::pagedCookie($msg['controls']);
                if ($cookie !== '' && isset($cookies[$cookie])) {
                    throw new LdapException('The directory repeated a page; the search was stopped.');
                }
                $cookies[$cookie] = true;
                break;
            }
        } while ($cookie !== '' && count($out) < $max);
        return $out;
    }

    /** Unbind and close. */
    public function close(): void
    {
        if (is_resource($this->stream)) {
            @fwrite($this->stream, Ber::seq(Ber::int(++$this->messageId), Ber::tlv(0x42, '')));
            fclose($this->stream);
        }
    }

    /**
     * Whether the plain LDAP port requires signing: true (required), false (not required), null (couldn't tell). Sends a
     * simple bind with a made-up account and random password only (see the class notes).
     */
    public static function signingRequired(string $ip, int $port, float $timeout = 15.0): ?bool
    {
        $host = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $s = @stream_socket_client('tcp://' . $host . ':' . $port, $errno, $errstr, min(10.0, $timeout));
        if ($s === false) {
            return null;
        }
        $c = new self($s, microtime(true) + $timeout, []);
        try {
            $code = $c->bind('CN=msp-sentinel-signing-check,DC=invalid', bin2hex(random_bytes(16)));
        } catch (LdapException | BerException) {
            return null;
        } finally {
            $c->close();
        }
        return match ($code) {
            self::STRONGER_AUTH_REQUIRED => true,
            self::INVALID_CREDENTIALS => false,
            default => null,
        };
    }

    /** Encode a filter (only what the checks use). @param array<int,mixed> $f */
    private static function filter(array $f): string
    {
        return match ($f[0] ?? null) {
            'and' => Ber::tlv(0xA0, implode('', array_map([self::class, 'filter'], (array) $f[1]))),
            'eq' => Ber::tlv(0xA3, Ber::str((string) $f[1]) . Ber::str((string) $f[2])),
            'present' => Ber::tlv(0x87, (string) $f[1]),
            default => throw new \InvalidArgumentException('Unknown filter.'),
        };
    }

    private function send(int $id, string $op, string $controls = ''): void
    {
        $msg = Ber::seq(Ber::int($id), $op . $controls);
        for ($done = 0, $n = strlen($msg); $done < $n;) {
            $w = @fwrite($this->stream, substr($msg, $done));
            if ($w === false || $w === 0) {
                throw new LdapException('The connection to the domain controller was lost.');
            }
            $done += $w;
        }
    }

    /**
     * The next message for $id (others are skipped).
     *
     * @return array{op:int, body:string, controls:string}
     */
    private function receive(int $id): array
    {
        while (true) {
            $raw = $this->readMessage();
            $parts = Ber::children(Ber::read($raw)['value'], 3);
            if (count($parts) < 2 || $parts[0]['tag'] !== Ber::INTEGER) {
                throw new BerException('Malformed LDAP message.');
            }
            if (Ber::toInt($parts[0]['value']) !== $id) {
                continue; // e.g. a notice of disconnection (ID 0) is handled as a lost connection below
            }
            $controls = isset($parts[2]) && $parts[2]['tag'] === 0xA0 ? $parts[2]['value'] : '';
            return ['op' => $parts[1]['tag'], 'body' => $parts[1]['value'], 'controls' => $controls];
        }
    }

    /** One whole LDAP message from the stream (tag, length, value), within the deadline and size cap. */
    private function readMessage(): string
    {
        $head = $this->readBytes(2);
        $extra = ord($head[1]) & 0x80 ? ord($head[1]) & 0x7F : 0;
        if ($extra > 4) {
            throw new BerException('Unsupported BER length.');
        }
        $head .= $extra > 0 ? $this->readBytes($extra) : '';
        [$len] = Ber::readLength($head, 1);
        if ($len > self::MAX_MESSAGE) {
            throw new LdapException('An answer from the domain controller is too large.');
        }
        return $head . ($len > 0 ? $this->readBytes($len) : '');
    }

    private function readBytes(int $n): string
    {
        $buf = '';
        while (strlen($buf) < $n) {
            $left = $this->deadline - microtime(true);
            if ($left <= 0) {
                throw new LdapException('The domain controller took too long to answer.');
            }
            stream_set_timeout($this->stream, (int) max(1, ceil(min($left, 30))));
            $chunk = @fread($this->stream, min(65536, $n - strlen($buf)));
            if ($chunk === false || ($chunk === '' && (feof($this->stream) || (stream_get_meta_data($this->stream)['timed_out'] ?? false)))) {
                throw new LdapException('The connection to the domain controller was lost.');
            }
            $buf .= $chunk;
        }
        return $buf;
    }

    /** The resultCode of an LDAPResult body. */
    private static function resultCode(string $body): int
    {
        $parts = Ber::children($body, 10);
        if ($parts === [] || $parts[0]['tag'] !== Ber::ENUMERATED) {
            throw new BerException('Malformed LDAP result.');
        }
        return Ber::toInt($parts[0]['value']);
    }

    /** @return array{dn:string, attrs:array<string,list<string>>} */
    private static function entry(string $body): array
    {
        $parts = Ber::children($body, 2);
        if (count($parts) !== 2 || $parts[0]['tag'] !== Ber::OCTET_STRING || $parts[1]['tag'] !== Ber::SEQUENCE) {
            throw new BerException('Malformed directory entry.');
        }
        $attrs = [];
        foreach (Ber::children($parts[1]['value'], 200) as $a) {
            $pair = Ber::children($a['value'], 2);
            if (count($pair) !== 2 || $pair[0]['tag'] !== Ber::OCTET_STRING || $pair[1]['tag'] !== Ber::SET) {
                throw new BerException('Malformed directory attribute.');
            }
            // Range retrieval names (member;range=0-1499) count as the attribute itself.
            $name = strtolower((string) preg_replace('/;.*$/', '', $pair[0]['value']));
            foreach (Ber::children($pair[1]['value'], 5000) as $v) {
                $attrs[$name][] = $v['value'];
            }
        }
        return ['dn' => $parts[0]['value'], 'attrs' => $attrs];
    }

    /** The cookie of the paged-results response control ('' when none: the last page). */
    private static function pagedCookie(string $controls): string
    {
        foreach ($controls === '' ? [] : Ber::children($controls, 20) as $c) {
            $parts = Ber::children($c['value'], 3);
            if (($parts[0]['value'] ?? '') !== self::PAGED_OID) {
                continue;
            }
            $value = end($parts);
            if ($value === false || $value['tag'] !== Ber::OCTET_STRING) {
                return '';
            }
            $inner = Ber::children(Ber::read($value['value'])['value'], 2);
            return isset($inner[1]) && $inner[1]['tag'] === Ber::OCTET_STRING ? $inner[1]['value'] : '';
        }
        return '';
    }

    /** "CN=dc01.corp.example, O=..." from openssl_x509_parse's subject/issuer array. @param array<string,mixed> $dn */
    private static function dnText(array $dn): string
    {
        $out = [];
        foreach ($dn as $k => $v) {
            foreach ((array) $v as $one) {
                $out[] = $k . '=' . (string) preg_replace('/[\x00-\x1F\x7F]/', '', (string) $one);
            }
        }
        return implode(', ', $out);
    }
}
