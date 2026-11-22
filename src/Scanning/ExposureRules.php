<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

/**
 * Turns stored TLS and web-page data into issues with a severity, using the
 * agreed grading (design section 4). The findings step (later) reuses these
 * rules, so the UI and the findings always agree.
 *
 * FAIL: expired certificate; firewall or device admin page reachable from the internet.
 * WARN: certificate expiring within 14 days, not yet valid, self-signed or
 *       untrusted, hostname mismatch, TLS 1.0/1.1 accepted, weak key or
 *       signature; VPN portal or remote desktop web access exposed.
 * INFO: other login pages.
 *
 * Security assumptions: pure functions over stored rows. The text produced
 * is plain and escaped by the views.
 */
final class ExposureRules
{
    public const EXPIRY_WARN_DAYS = 14;

    /**
     * Issues for one TLS endpoint row.
     *
     * @param array<string,mixed> $tls Row from tls_endpoints.
     * @return list<array{severity:string,code:string,text:string}>
     */
    public static function tlsIssues(array $tls, ?int $now = null): array
    {
        $now ??= time();
        $issues = [];
        if ($tls['not_after'] !== null) {
            $left = (int) floor((strtotime($tls['not_after'] . ' UTC') - $now) / 86400);
            if ($left < 0) {
                $issues[] = ['severity' => 'fail', 'code' => 'cert_expired', 'text' => __('Certificate expired {n} day(s) ago', ['n' => -$left])];
            } elseif ($left <= self::EXPIRY_WARN_DAYS) {
                $issues[] = ['severity' => 'warn', 'code' => 'cert_expiring', 'text' => __('Certificate expires in {n} day(s)', ['n' => $left])];
            }
        }
        if ($tls['not_before'] !== null && strtotime($tls['not_before'] . ' UTC') > $now) {
            $issues[] = ['severity' => 'warn', 'code' => 'cert_not_yet_valid', 'text' => __('Certificate is not valid yet')];
        }
        if ((int) ($tls['self_signed'] ?? 0) === 1) {
            $issues[] = ['severity' => 'warn', 'code' => 'cert_self_signed', 'text' => __('Self-signed certificate')];
        } elseif (isset($tls['chain_trusted']) && (int) $tls['chain_trusted'] === 0) {
            $issues[] = ['severity' => 'warn', 'code' => 'cert_untrusted', 'text' => __('Certificate could not be verified (untrusted or incomplete chain, or only outdated TLS settings)')];
        }
        if (isset($tls['hostname_match']) && $tls['hostname_match'] !== null && (int) $tls['hostname_match'] === 0) {
            $issues[] = ['severity' => 'warn', 'code' => 'cert_name_mismatch', 'text' => __('Certificate does not match the name {host}', ['host' => $tls['sni']])];
        }
        if ((int) ($tls['accepts_tls10'] ?? 0) === 1 || (int) ($tls['accepts_tls11'] ?? 0) === 1) {
            $old = array_filter(['TLS 1.0' => (int) ($tls['accepts_tls10'] ?? 0) === 1, 'TLS 1.1' => (int) ($tls['accepts_tls11'] ?? 0) === 1]);
            $issues[] = ['severity' => 'warn', 'code' => 'tls_old_protocol', 'text' => __('Still accepts {list}', ['list' => implode(' and ', array_keys($old))])];
        }
        $bits = (int) ($tls['key_bits'] ?? 0);
        if (($tls['key_type'] === 'RSA' && $bits > 0 && $bits < 2048) || ($tls['key_type'] === 'EC' && $bits > 0 && $bits < 224) || $tls['key_type'] === 'DSA') {
            $issues[] = ['severity' => 'warn', 'code' => 'cert_weak_key', 'text' => __('Weak key ({type} {bits} bits)', ['type' => $tls['key_type'], 'bits' => $bits])];
        }
        if (preg_match('/md5|sha1/i', (string) $tls['signature_alg']) && (int) ($tls['self_signed'] ?? 0) === 0) {
            $issues[] = ['severity' => 'warn', 'code' => 'cert_weak_signature', 'text' => __('Weak signature algorithm ({alg})', ['alg' => $tls['signature_alg']])];
        }
        return $issues;
    }

    /**
     * Severity and wording for a detected web page category.
     *
     * @return array{severity:string,text:string}|null
     */
    public static function webIssue(?string $category): ?array
    {
        return match ($category) {
            'firewall_admin' => ['severity' => 'fail', 'text' => __('Firewall admin page reachable from the internet')],
            'device_admin' => ['severity' => 'fail', 'text' => __('Device management page reachable from the internet')],
            'vpn_portal' => ['severity' => 'warn', 'text' => __('VPN login portal exposed: make sure it is patched and uses MFA')],
            'remote_desktop_web' => ['severity' => 'warn', 'text' => __('Remote desktop web access exposed: make sure it uses MFA')],
            'login_page' => ['severity' => 'info', 'text' => __('Login page')],
            default => null,
        };
    }
}
