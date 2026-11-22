<?php

declare(strict_types=1);

namespace Sentinel\Core;

/**
 * The CA bundle used to verify TLS connections Sentinel makes (certificate
 * checks, SMTP). PHP's "cafile" REPLACES the system trust store, so an extra
 * CA file (config tls.ca_file) is combined with the system bundle and written
 * once to a file named after its contents' hash, in the app's own storage/
 * directory (not the shared /tmp, where another local user could plant a file).
 *
 * Security assumptions: the extra CA file is trusted admin config. An existing
 * combined file is only reused if its contents match exactly what we would
 * write; it is created group-readable (0640, public CA certificates only)
 * through a random temporary name.
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
        $content = $system . "\n" . $extra;
        $dir = dirname(__DIR__, 2) . '/storage/ca';
        // 2770: the web server and the worker share the "sentinel" group and both need this cache.
        if (!is_dir($dir) && !@mkdir($dir, 02770, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create ' . $dir . ' for the CA bundle.');
        }
        $path = $dir . '/ca-' . hash('sha256', $content) . '.pem';
        if (!is_file($path) || is_link($path) || (string) @file_get_contents($path) !== $content) {
            $tmp = $dir . '/.ca-' . bin2hex(random_bytes(8)) . '.tmp';
            $old = umask(0027);
            try {
                if (@file_put_contents($tmp, $content, LOCK_EX) === false || !@rename($tmp, $path)) {
                    @unlink($tmp);
                    throw new \RuntimeException('Cannot write the CA bundle in ' . $dir . '.');
                }
            } finally {
                umask($old);
            }
        }
        return $cache[$extraCaFile] = $path;
    }
}
