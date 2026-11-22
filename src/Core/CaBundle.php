<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * The CA bundle used to verify TLS connections Sentinel makes (certificate
 * checks, SMTP). PHP's "cafile" REPLACES the system trust store, so an extra
 * CA file (config tls.ca_file) is combined with the system bundle and written
 * once to a temporary file named after its contents' hash.
 *
 * Security assumptions: the extra CA file is trusted admin config. The combined
 * file only contains public CA certificates.
 */
final class CaBundle
{
    /** Path to use as "cafile", or null to use the system store unchanged. */
    public static function path(?string $extraCaFile): ?string
    {
        if ($extraCaFile === null || $extraCaFile === '' || !is_file($extraCaFile)) {
            return null;
        }
        static $cache = [];
        if (isset($cache[$extraCaFile])) {
            return $cache[$extraCaFile];
        }
        $system = '';
        $locations = openssl_get_cert_locations();
        foreach ([$locations['default_cert_file'] ?? '', '/etc/ssl/certs/ca-certificates.crt'] as $file) {
            if ($file !== '' && is_readable($file)) {
                $system = (string) file_get_contents($file);
                break;
            }
        }
        $extra = (string) file_get_contents($extraCaFile);
        $path = sys_get_temp_dir() . '/msp-sentinel-ca-' . hash('sha256', $system . $extra) . '.pem';
        if (!is_file($path)) {
            file_put_contents($path . '.tmp', $system . "\n" . $extra);
            rename($path . '.tmp', $path);
        }
        return $cache[$extraCaFile] = $path;
    }
}
