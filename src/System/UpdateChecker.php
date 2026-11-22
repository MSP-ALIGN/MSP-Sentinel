<?php

declare(strict_types=1);

namespace Sentinel\System;

use Sentinel\Core\Settings;

/**
 * Checks once a day whether a newer release exists (one HTTPS GET to the
 * releases feed, config updates.url). Admins can turn it off.
 *
 * Security assumptions:
 * - Nothing is sent but the request itself (no client data, no version in
 *   the User-Agent). TLS is verified; only https (plain http only in the
 *   test suite). Redirects are not followed; the answer is capped at 256 KB.
 * - The response is untrusted: only a version number matching x.y.z is kept.
 *   No URL from the response is stored or shown.
 */
final class UpdateChecker
{
    public const DEFAULT_URL = 'https://api.github.com/repos/msp-align/msp-sentinel/releases/latest';

    /** @param bool $allowHttp Test suite only. */
    public function __construct(private readonly Settings $settings, private readonly string $url, private readonly string $current, private readonly bool $allowHttp = false)
    {
    }

    /** Check if due (or $force). Returns the latest version seen, or null if the check is off or failed. */
    public function check(bool $force = false): ?string
    {
        if ($this->settings->get('update_check_enabled') !== '1') {
            return null;
        }
        $last = $this->settings->get('update_checked_at');
        if (!$force && $last !== '' && strtotime($last . ' UTC') > time() - 20 * 3600) {
            return $this->settings->get('update_latest_version') ?: null;
        }
        $this->settings->set('update_checked_at', gmdate('Y-m-d H:i:s')); // also on failure, so a down feed isn't retried every minute
        $scheme = strtolower((string) parse_url($this->url, PHP_URL_SCHEME));
        if ($scheme !== 'https' && !($this->allowHttp && $scheme === 'http')) {
            return null;
        }
        $ch = curl_init($this->url);
        $body = '';
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$body): int {
                $body .= $chunk;
                return strlen($body) > 262144 ? 0 : strlen($chunk);
            },
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | ($this->allowHttp ? CURLPROTO_HTTP : 0),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'MSP-Sentinel',
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($ok === false || $status !== 200) {
            return null;
        }
        $data = json_decode($body, true);
        $tag = is_array($data) && is_string($data['tag_name'] ?? null) ? $data['tag_name'] : '';
        if (!preg_match('/^v?(\d{1,4}\.\d{1,4}\.\d{1,4})$/', $tag, $m) || (($data['prerelease'] ?? false) === true) || (($data['draft'] ?? false) === true)) {
            return null;
        }
        $this->settings->set('update_latest_version', $m[1]);
        return $m[1];
    }

    /** The newer version, if one is known and newer than this install. */
    public function newer(): ?string
    {
        $latest = $this->settings->get('update_latest_version');
        return $this->settings->get('update_check_enabled') === '1' && $latest !== '' && version_compare($latest, $this->current, '>') ? $latest : null;
    }
}
