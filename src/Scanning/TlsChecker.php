<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use Sentinel\Scope\ScopeParser;

/**
 * Checks the TLS certificate and old protocol support of one endpoint.
 *
 * Handshakes per call: one verified handshake (chain trust), plus one
 * unverified handshake if the first fails. With probeProtocols() there are
 * up to two more (TLS 1.0, TLS 1.1). Each has a short timeout, and no data
 * is sent apart from the handshake.
 *
 * Security assumptions:
 * - The caller has checked the IP against the scope (and the window and
 *   kill switches) right before calling. Connector only redirects in the
 *   test suite.
 * - Everything read from the certificate is UNTRUSTED: strings are cleaned
 *   and length-limited, and dates are parsed as integers.
 * - Old protocols are only offered in the dedicated probe handshakes, to
 *   find out whether the server still accepts them. They are never used to
 *   send data.
 */
final class TlsChecker
{
    /**
     * @param string|null $caFile Extra CA bundle (config tls.ca_file). Null uses the system trust store.
     */
    public function __construct(private readonly Connector $connector, private readonly ?string $caFile = null, private readonly float $timeout = 10.0)
    {
    }

    /**
     * Read and judge the certificate.
     *
     * @param string|null        $sni        Hostname to send as SNI and to match the certificate against (null: none).
     * @param callable():bool|null $shouldStop Asked before the fallback handshake. True means stop now.
     * @return array<string,mixed> Columns for tls_endpoints, plus 'ok' (bool) and 'error' (string).
     */
    public function check(string $ip, int $port, ?string $sni, ?callable $shouldStop = null): array
    {
        $trusted = true;
        [$stream, $error] = $this->handshake($ip, $port, $sni, true, STREAM_CRYPTO_METHOD_ANY_CLIENT);
        if ($stream === null && $shouldStop !== null && $shouldStop()) {
            return ['ok' => false, 'error' => __('Stopped.'), 'stopped' => true];
        }
        if ($stream === null) {
            $trusted = false;
            // Unverified, at security level 0, so weak certificates (e.g. 1024-bit keys, which the
            // system OpenSSL refuses outright) can still be read and reported. Read only, no data sent.
            [$stream, $error] = $this->handshake($ip, $port, $sni, false, STREAM_CRYPTO_METHOD_ANY_CLIENT, true);
        }
        if ($stream === null) {
            return ['ok' => false, 'error' => $error];
        }
        $params = stream_context_get_params($stream);
        $meta = stream_get_meta_data($stream);
        fclose($stream);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if ($cert === null) {
            return ['ok' => false, 'error' => __('The server sent no certificate.')];
        }
        $info = openssl_x509_parse($cert) ?: [];
        $sans = self::sans((string) ($info['extensions']['subjectAltName'] ?? ''));
        $subjectCn = self::clean((string) ($info['subject']['CN'] ?? ''), 260);
        $issuer = self::clean(trim(($info['issuer']['O'] ?? '') . ' ' . ($info['issuer']['CN'] ?? '')), 300);
        $key = openssl_pkey_get_public($cert);
        $details = $key !== false ? (openssl_pkey_get_details($key) ?: []) : [];
        $keyType = match ($details['type'] ?? null) {
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_EC => 'EC',
            OPENSSL_KEYTYPE_DSA => 'DSA',
            default => '',
        };
        $selfSigned = ($info['subject'] ?? null) === ($info['issuer'] ?? null) && $key !== false && openssl_x509_verify($cert, $key) === 1;
        return [
            'ok' => true,
            'error' => '',
            'subject_cn' => $subjectCn,
            'sans' => implode(',', array_slice($sans, 0, 100)),
            'issuer' => $issuer,
            'not_before' => isset($info['validFrom_time_t']) ? gmdate('Y-m-d H:i:s', (int) $info['validFrom_time_t']) : null,
            'not_after' => isset($info['validTo_time_t']) ? gmdate('Y-m-d H:i:s', (int) $info['validTo_time_t']) : null,
            'self_signed' => $selfSigned ? 1 : 0,
            'chain_trusted' => $trusted ? 1 : 0,
            'hostname_match' => $sni === null ? null : (self::hostnameMatches($sni, $sans, $subjectCn) ? 1 : 0),
            'key_type' => $keyType,
            'key_bits' => isset($details['bits']) ? (int) $details['bits'] : null,
            'signature_alg' => self::clean((string) ($info['signatureTypeSN'] ?? ''), 80),
            'protocol' => self::clean((string) ($meta['crypto']['protocol'] ?? ''), 20),
        ];
    }

    /**
     * Does the server still accept TLS 1.0 and TLS 1.1?
     *
     * @return array{accepts_tls10:?int, accepts_tls11:?int}
     */
    public function probeProtocols(string $ip, int $port, ?string $sni): array
    {
        $out = [];
        foreach (['accepts_tls10' => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT, 'accepts_tls11' => STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT] as $field => $method) {
            [$stream] = $this->handshake($ip, $port, $sni, false, $method, true);
            $out[$field] = $stream === null ? 0 : 1;
            if ($stream !== null) {
                fclose($stream);
            }
        }
        return $out;
    }

    /**
     * One TLS handshake.
     *
     * @param bool $legacy Allow old protocols and ciphers (probe handshakes only).
     * @return array{0: resource|null, 1: string} [stream or null, error message]
     */
    private function handshake(string $ip, int $port, ?string $sni, bool $verify, int $method, bool $legacy = false): array
    {
        try {
            [$host, $realPort] = $this->connector->endpoint($ip, $port);
        } catch (\RuntimeException $ex) {
            return [null, self::clean($ex->getMessage(), 300)];
        }
        $ssl = [
            'verify_peer' => $verify,
            'verify_peer_name' => false, // the hostname is judged separately, so a mismatch is reported, not fatal
            'allow_self_signed' => !$verify,
            'capture_peer_cert' => true,
            'SNI_enabled' => $sni !== null,
            'crypto_method' => $method,
            'disable_compression' => true,
        ];
        if ($sni !== null) {
            $ssl['peer_name'] = $sni;
        }
        if ($legacy) {
            $ssl['ciphers'] = 'DEFAULT@SECLEVEL=0';
        }
        if ($verify && ($bundle = $this->caBundle()) !== null) {
            $ssl['cafile'] = $bundle;
        }
        $context = stream_context_create(['ssl' => $ssl]);
        $stream = @stream_socket_client('tls://' . Connector::hostPort($host, $realPort), $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context);
        if ($stream === false) {
            $last = error_get_last()['message'] ?? $errstr;
            return [null, self::clean(__('TLS handshake failed: {e}', ['e' => $errstr !== '' ? $errstr : (string) $last]), 300)];
        }
        stream_set_timeout($stream, (int) $this->timeout);
        return [$stream, ''];
    }

    /**
     * The CA bundle to verify against: PHP's "cafile" REPLACES the system
     * trust store, so an extra CA file is combined with the system bundle
     * (written once to a temporary file named after its contents' hash).
     * Returns null to use the system store unchanged.
     */
    private function caBundle(): ?string
    {
        if ($this->caFile === null || !is_file($this->caFile)) {
            return null;
        }
        static $cache = [];
        if (isset($cache[$this->caFile])) {
            return $cache[$this->caFile];
        }
        $system = '';
        $locations = openssl_get_cert_locations();
        foreach ([$locations['default_cert_file'] ?? '', '/etc/ssl/certs/ca-certificates.crt'] as $file) {
            if ($file !== '' && is_readable($file)) {
                $system = (string) file_get_contents($file);
                break;
            }
        }
        $extra = (string) file_get_contents($this->caFile);
        $path = sys_get_temp_dir() . '/msp-sentinel-ca-' . hash('sha256', $system . $extra) . '.pem';
        if (!is_file($path)) {
            file_put_contents($path . '.tmp', $system . "\n" . $extra);
            rename($path . '.tmp', $path);
        }
        return $cache[$this->caFile] = $path;
    }

    /**
     * DNS names from a subjectAltName extension string ("DNS:a, DNS:b, IP Address:...").
     *
     * @return list<string>
     */
    public static function sans(string $ext): array
    {
        $names = [];
        foreach (explode(',', $ext) as $part) {
            $part = trim($part);
            if (str_starts_with($part, 'DNS:')) {
                $name = strtolower(self::clean(substr($part, 4), 260));
                if ($name !== '' && preg_match('/^[a-z0-9*._-]+$/', $name)) {
                    $names[] = $name;
                }
            }
        }
        return array_values(array_unique($names));
    }

    /**
     * RFC 6125-style match: an exact name, or a wildcard in the left-most label only ("*.example.com"
     * matches "www.example.com", not "example.com" or "a.b.example.com"). The CN is used only when there are no SANs.
     *
     * @param list<string> $sans
     */
    public static function hostnameMatches(string $host, array $sans, string $cn): bool
    {
        $host = strtolower(rtrim($host, '.'));
        $candidates = $sans !== [] ? $sans : ($cn !== '' ? [strtolower($cn)] : []);
        foreach ($candidates as $name) {
            if ($name === $host) {
                return true;
            }
            if (str_starts_with($name, '*.') && substr_count($name, '.') >= 2 && !ScopeParser::isPublicSuffix(substr($name, 2))) {
                $suffix = substr($name, 1);
                $label = substr($host, 0, -strlen($suffix));
                if (str_ends_with($host, $suffix) && $label !== '' && !str_contains($label, '.')) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Remove control characters and invalid UTF-8, then cut to $max characters. */
    private static function clean(string $value, int $max): string
    {
        $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        return mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]/u', ' ', $value)), 0, $max);
    }
}
