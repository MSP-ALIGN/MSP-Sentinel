<?php

declare(strict_types=1);

namespace Sentinel\Agent;

/**
 * Grading of risky internal protocols found by the on-premises agent
 * (Balanced, as agreed with the owner):
 *
 * - Fail: SMBv1 enabled; Telnet open; SNMP answering the default "private"
 *   community (usually read-write).
 * - Warning: SMB signing not required; RDP without Network Level
 *   Authentication; FTP open; SNMP answering "public"; a login page over
 *   plain HTTP.
 *
 * Only definite answers count: a check that couldn't decide (null) is never a
 * finding. Untrusted: stored check results (server-validated booleans).
 */
final class ProtocolRules
{
    /**
     * Issues for one agent device.
     *
     * @param array<string,mixed>       $device devices row (checks JSON).
     * @param list<array<string,mixed>> $ports  device_ports rows (checks and web JSON).
     * @return list<array{code:string, severity:string, text:string, detail:string}>
     */
    public static function issues(array $device, array $ports): array
    {
        $out = [];
        foreach ($ports as $p) {
            $port = (int) $p['port'];
            $checks = json_decode((string) ($p['checks'] ?? ''), true) ?: [];
            $web = json_decode((string) ($p['web'] ?? ''), true) ?: [];
            if (($checks['smb1'] ?? null) === true) {
                $out[] = ['code' => 'smb1', 'severity' => 'fail', 'text' => __('SMBv1 is enabled'), 'detail' => __('Port {p}/tcp accepts the old SMBv1 protocol (used by WannaCry-style worms).', ['p' => $port])];
            }
            if (($checks['signing_required'] ?? null) === false) {
                $out[] = ['code' => 'smb_signing', 'severity' => 'warn', 'text' => __('SMB signing is not required'), 'detail' => __('Port {p}/tcp: connections can be relayed or tampered with.', ['p' => $port])];
            }
            if (($checks['nla_required'] ?? null) === false) {
                $out[] = ['code' => 'rdp_no_nla', 'severity' => 'warn', 'text' => __('Remote Desktop without Network Level Authentication'), 'detail' => __('Port {p}/tcp shows the Windows login screen before anyone has signed in.', ['p' => $port])];
            }
            // By the service nmap identified (on any port), not by the port number alone.
            $service = strtolower((string) ($p['service'] ?? ''));
            if ($service === 'telnet') {
                $out[] = ['code' => 'telnet', 'severity' => 'fail', 'text' => __('Telnet is open (passwords sent in clear text)'), 'detail' => __('Port {p}/tcp.', ['p' => $port])];
            }
            if ($service === 'ftp') {
                $out[] = ['code' => 'ftp', 'severity' => 'warn', 'text' => __('FTP is open (unencrypted unless the server requires TLS)'), 'detail' => __('Port {p}/tcp.', ['p' => $port])];
            }
            if (($web['login_over_http'] ?? false) === true) {
                $out[] = ['code' => 'http_login', 'severity' => 'warn', 'text' => __('Login page over plain HTTP'), 'detail' => __('Port {p}/tcp: "{title}".', ['p' => $port, 'title' => (string) ($web['title'] ?? '')])];
            }
        }
        $dev = json_decode((string) ($device['checks'] ?? ''), true) ?: [];
        if (($dev['snmp_private'] ?? null) === true) {
            $out[] = ['code' => 'snmp_private', 'severity' => 'fail', 'text' => __('SNMP answers the default "private" community'), 'detail' => __('Usually read-write: anyone on the network may change the device\'s settings.')];
        } elseif (($dev['snmp_public'] ?? null) === true) {
            $out[] = ['code' => 'snmp_public', 'severity' => 'warn', 'text' => __('SNMP answers the default "public" community'), 'detail' => __('Anyone on the network can read the device\'s configuration and details.')];
        }
        // One finding per code per device (several SMB ports give one finding).
        $unique = [];
        foreach ($out as $i) {
            $unique[$i['code']] ??= $i;
        }
        return array_values($unique);
    }
}
