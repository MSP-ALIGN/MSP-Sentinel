<?php

declare(strict_types=1);

namespace Sentinel\Tests;

/**
 * Generates throwaway certificates for the mock TLS servers: a test CA, and
 * server certificates with made-up *.example names. They are written to the
 * run's output folder and deleted with it. Nothing here is a real secret.
 */
final class TlsFixtures
{
    /**
     * Create the CA and server certificates.
     *
     * @return array<string,string> name => path of a PEM file (certificate + key), plus 'ca' => CA certificate path.
     */
    public static function create(string $dir): array
    {
        $cnf = $dir . '/openssl-test.cnf';
        $write = static function (array $sans) use ($cnf): void {
            $alt = implode(',', array_map(static fn (string $n): string => 'DNS:' . $n, $sans));
            file_put_contents($cnf, "[req]\ndistinguished_name = dn\n[dn]\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = keyCertSign,cRLSign\n"
                . "[v3_srv]\nbasicConstraints = CA:FALSE\n" . ($alt !== '' ? "subjectAltName = {$alt}\n" : ''));
        };
        $out = [];

        // Test CA
        $write([]);
        $caKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $caCsr = openssl_csr_new(['commonName' => 'Sentinel Test CA', 'organizationName' => 'Example Test CA'], $caKey, ['config' => $cnf, 'digest_alg' => 'sha256']);
        $caCert = openssl_csr_sign($caCsr, null, $caKey, 365, ['config' => $cnf, 'x509_extensions' => 'v3_ca', 'digest_alg' => 'sha256'], 1);
        openssl_x509_export($caCert, $caPem);
        file_put_contents($dir . '/ca.pem', $caPem);
        $out['ca'] = $dir . '/ca.pem';

        // Good: CA-signed, 200 days, vpn.tlscheck.example
        $out['good'] = self::server($dir, 'good', $write, ['vpn.tlscheck.example'], 2048, 200, $caCert, $caKey);
        // Weak: self-signed, 1024-bit, expires in 5 days
        $out['weak'] = self::server($dir, 'weak', $write, ['old.tlscheck.example'], 1024, 5, null, null);
        // Mail server for STARTTLS tests: CA-signed for "localhost"
        $out['smtp'] = self::server($dir, 'smtp', $write, ['localhost'], 2048, 30, $caCert, $caKey);
        // Wrong name: CA-signed but for another name
        $out['wrongname'] = self::server($dir, 'wrongname', $write, ['other-name.example'], 2048, 300, $caCert, $caKey);
        return $out;
    }

    /**
     * One server certificate (+ key) in a PEM file.
     *
     * @param list<string> $sans
     */
    private static function server(string $dir, string $name, callable $write, array $sans, int $bits, int $days, mixed $caCert, mixed $caKey): string
    {
        $cnf = $dir . '/openssl-test.cnf';
        $write($sans);
        $key = openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'config' => $cnf]);
        $csr = openssl_csr_new(['commonName' => $sans[0]], $key, ['config' => $cnf, 'digest_alg' => 'sha256']);
        $cert = openssl_csr_sign($csr, $caCert, $caKey ?? $key, $days, ['config' => $cnf, 'x509_extensions' => 'v3_srv', 'digest_alg' => 'sha256'], random_int(2, 1_000_000));
        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($key, $keyPem, null, ['config' => $cnf]);
        $path = $dir . '/' . $name . '.pem';
        file_put_contents($path, $certPem . $keyPem);
        chmod($path, 0600);
        return $path;
    }
}
