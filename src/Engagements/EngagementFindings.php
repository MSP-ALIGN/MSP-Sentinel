<?php

declare(strict_types=1);

namespace Sentinel\Engagements;

use Sentinel\Scanning\PortProfile;

/**
 * Turns an engagement's evidence (EngagementRepository::results(): open ports, nmap script results, UDP checks) into
 * pen-test findings: what was found, how serious, the exact evidence, and how to fix it. A pure function of the
 * evidence, so the report always matches what was recorded, and a retest is the same analysis on newer evidence.
 *
 * Severities: 'fail' (fix soon: anonymous write access, SMBv1, default SNMP write community, high-risk services on the
 * internet, Telnet, anonymous FTP), 'warn' (should be fixed: anonymous read access, signing not required, SNMP
 * "public", plain FTP, UPnP on the internet), 'info' (worth knowing: services reachable).
 *
 * Untrusted: all evidence came from the tested hosts. Only fixed phrases are matched; evidence is cut to 600
 * characters and always escaped where shown.
 */
final class EngagementFindings
{
    private const RANK = ['fail' => 0, 'warn' => 1, 'info' => 2];

    /**
     * @param list<array<string,mixed>> $results
     * @return list<array{key:string, severity:string, title:string, target:string, origin:string, evidence:string, fix:string}>
     */
    public static function analyse(array $results): array
    {
        $out = [];
        $add = static function (string $severity, string $key, string $title, string $target, string $origin, string $evidence, string $fix) use (&$out): void {
            $out[$key . '|' . $target] = ['key' => $key, 'severity' => $severity, 'title' => $title, 'target' => $target, 'origin' => $origin,
                'evidence' => mb_substr(trim($evidence), 0, 600), 'fix' => $fix];
        };
        foreach ($results as $r) {
            $ip = (string) $r['ip'];
            $origin = (string) $r['origin'];
            $external = $origin === 'external';
            $scripts = [];
            foreach ((array) ($r['ports_list'] ?? []) as $p) {
                $port = (int) ($p['port'] ?? 0);
                $svc = strtolower((string) ($p['service'] ?? ''));
                $target = $ip . ':' . $port;
                foreach ((array) ($p['scripts'] ?? []) as $sc) {
                    $scripts[] = [(string) ($sc['id'] ?? ''), (string) ($sc['output'] ?? ''), $target];
                }
                if ($port === 23 || $svc === 'telnet') {
                    $add('fail', 'telnet', __('Telnet is open (passwords travel unencrypted)'), $target, $origin, $svc,
                        __('Turn Telnet off and use SSH (or the device\'s HTTPS management page) instead.'));
                } elseif ($external && isset(PortProfile::HIGH_RISK[$port])) {
                    $add('fail', 'exposed_' . $port, __('{s} is reachable from the internet', ['s' => PortProfile::HIGH_RISK[$port]]), $target, $origin, $svc,
                        __('Close it on the firewall; allow it only over a VPN, or from named addresses.'));
                } elseif ($port === 21 || $svc === 'ftp') {
                    $add('warn', 'ftp', __('FTP is open (unencrypted file transfer)'), $target, $origin, trim((string) ($p['product'] ?? '') . ' ' . (string) ($p['version'] ?? '')),
                        __('Replace FTP with SFTP or FTPS, or turn it off.'));
                } elseif ($port === 5900 || str_starts_with($svc, 'vnc')) {
                    $add('warn', 'vnc', __('VNC remote control is open'), $target, $origin, $svc, __('Allow remote control only through your remote-support tool or a VPN, with strong authentication.'));
                } else {
                    $add('info', 'open_' . $port, __('{svc} service on port {p}', ['svc' => $svc !== '' ? $svc : __('Unknown'), 'p' => $port]), $target, $origin,
                        trim((string) ($p['product'] ?? '') . ' ' . (string) ($p['version'] ?? '')), __('Check it is needed; close it if not.'));
                }
            }
            foreach ((array) ($r['checks_list']['hostscripts'] ?? []) as $sc) {
                $scripts[] = [(string) ($sc['id'] ?? ''), (string) ($sc['output'] ?? ''), $ip];
            }
            foreach ($scripts as [$id, $text, $target]) {
                if ($id === 'ftp-anon' && str_contains($text, 'Anonymous FTP login allowed')) {
                    $add('fail', 'ftp_anon', __('Anonymous FTP login is allowed'), $target, $origin, $text, __('Turn off anonymous FTP; give named accounts only to people who need access.'));
                }
                if ($id === 'smb-protocols' && (str_contains($text, 'NT LM 0.12') || stripos($text, 'SMBv1') !== false)) {
                    $add('fail', 'smb1', __('SMBv1 is enabled (the protocol WannaCry spread through)'), $target, $origin, $text, __('Disable SMBv1 on this device; update or replace it if it needs SMBv1.'));
                }
                if ($id === 'smb2-security-mode' && str_contains($text, 'not required')) {
                    $add('warn', 'smb_signing', __('SMB signing is not required (relay attacks)'), $target, $origin, $text, __('Require SMB signing (Group Policy: "Digitally sign communications (always)").'));
                }
                if ($id === 'smb-enum-shares') {
                    foreach (self::shares($text) as $share => $access) {
                        if (strtoupper($share) === 'IPC$') {
                            continue;
                        }
                        if (str_contains($access, 'WRITE')) {
                            $add('fail', 'smb_anon_write', __('Share {s} can be written without a password', ['s' => $share]), $target, $origin, $text,
                                __('Remove guest and anonymous access from this share; grant named users or groups only.'));
                        } elseif (str_contains($access, 'READ')) {
                            $add('warn', 'smb_anon_read', __('Share {s} can be read without a password', ['s' => $share]), $target, $origin, $text,
                                __('Remove guest and anonymous access from this share; grant named users or groups only.'));
                        }
                    }
                }
                if ($id === 'nfs-showmount' && preg_match('#^\s*/\S+#m', $text) === 1) {
                    $everyone = preg_match('#^\s*/\S+\s+(\*|0\.0\.0\.0/0|everyone)\s*$#mi', $text) === 1;
                    $add($everyone ? 'fail' : 'warn', 'nfs_exports', $everyone ? __('NFS exports are open to everyone') : __('NFS exports are listed to anyone who asks'), $target, $origin, $text,
                        __('Restrict each export to the hosts that need it, and require authentication (NFSv4 with Kerberos) where possible.'));
                }
            }
            $udp = (array) ($r['checks_list']['udp'] ?? []);
            $is = static fn (string $k): bool => isset($udp[$k]) && json_decode((string) $udp[$k], true) === true;
            if ($is('snmp_private')) {
                $add('fail', 'snmp_private', __('SNMP answers the default "private" community (settings can be changed)'), $ip . ':161/udp', $origin, 'community "private"',
                    __('Change the community strings, or move to SNMPv3; turn SNMP off if it isn\'t used.'));
            }
            if ($is('snmp_public')) {
                $add($external ? 'fail' : 'warn', 'snmp_public', __('SNMP answers the default "public" community (device details readable)'), $ip . ':161/udp', $origin, 'community "public"',
                    __('Change the community strings, or move to SNMPv3; turn SNMP off if it isn\'t used.'));
            }
            $ssdp = isset($udp['ssdp']) ? json_decode((string) $udp['ssdp'], true) : null;
            if (is_array($ssdp)) {
                $add($external ? 'warn' : 'info', 'ssdp', $external ? __('UPnP discovery (SSDP) answers from the internet (amplification attacks)') : __('UPnP discovery (SSDP) answers'),
                    $ip . ':1900/udp', $origin, (string) ($ssdp['server'] ?? ''), __('Turn UPnP off on this device, or block UDP 1900 at the firewall.'));
            }
            if ($is('ntp')) {
                $add('info', 'ntp', __('A time service (NTP) answers'), $ip . ':123/udp', $origin, '', $external ? __('Allow NTP from the internet only if this is meant to be a public time server.') : __('Normal for servers and network gear.'));
            }
        }
        $list = array_values($out);
        usort($list, static fn (array $a, array $b): int => [self::RANK[$a['severity']], $a['target'], $a['key']] <=> [self::RANK[$b['severity']], $b['target'], $b['key']]);
        return $list;
    }

    /** Counts per severity. @param list<array{severity:string}> $findings @return array{fail:int, warn:int, info:int} */
    public static function counts(array $findings): array
    {
        $c = ['fail' => 0, 'warn' => 0, 'info' => 0];
        foreach ($findings as $f) {
            $c[$f['severity']]++;
        }
        return $c;
    }

    /**
     * Shares and their anonymous access from smb-enum-shares output ("\\host\NAME:" then "Anonymous access: READ").
     *
     * @return array<string,string>
     */
    private static function shares(string $text): array
    {
        $out = [];
        $current = null;
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            if (preg_match('/^\s*\\\\\\\\[^\\\\]+\\\\([^:\\\\]{1,80}):\s*$/', $line, $m) === 1) {
                $current = $m[1];
            } elseif ($current !== null && preg_match('/Anonymous access:\s*(READ\/WRITE|READ|WRITE)/i', $line, $m) === 1) {
                $out[$current] = strtoupper($m[1]);
            }
        }
        return $out;
    }
}
