<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * The operating system and device type of a device the agent found (1.38), from what a scan already learns: the
 * Windows version a server gives in its NTLM challenge (SmbShares::ntlmInfo), and clues in service banners and web
 * page categories (SSH banners name the Linux distribution, printers, NAS boxes and network devices name themselves).
 * Never logs in and sends nothing new beyond the SMB handshake; a guess, shown as such ("from the network").
 *
 * Windows 10/11 and Server share version 10.0: the build tells them apart, except three builds used by both a client
 * and a server release (14393, 17763, 26100), where server clues (a domain controller's Kerberos/LDAP ports, IIS, SQL
 * Server) decide, else both names are shown.
 *
 * Untrusted: every input (it comes from the network through the agent): only matched against fixed patterns, values
 * shortened; the result is plain text, escaped where shown.
 */
final class OsGuess
{
    /** Builds that are a client and a server release at once. */
    private const SHARED_BUILDS = [14393 => ['Windows 10 1607', 'Windows Server 2016'], 17763 => ['Windows 10 1809', 'Windows Server 2019'],
                                   26100 => ['Windows 11 24H2', 'Windows Server 2025']];

    /**
     * @param array<string,mixed>|null $ntlm  major, minor, build (from the agent; validated here)
     * @param list<array<string,mixed>> $ports port, product, version, extra_info, web (category) per open port
     * @return array{os_name:string, os_build:string, device_class:string}|null null when nothing is known
     */
    public static function guess(?array $ntlm, array $ports): ?array
    {
        $open = array_map(static fn (array $p): int => (int) ($p['port'] ?? 0), $ports);
        $products = strtolower(implode(' | ', array_map(static fn (array $p): string => trim((string) ($p['product'] ?? '') . ' ' . (string) ($p['version'] ?? '') . ' ' . (string) ($p['extra_info'] ?? '')), $ports)));
        $categories = array_map(static fn (array $p): string => (string) (is_array($p['web'] ?? null) ? ($p['web']['category'] ?? '') : ''), $ports);
        $serverClues = array_intersect($open, [88, 389, 636, 3268, 1433]) !== [] || str_contains($products, 'microsoft-iis') || str_contains($products, 'microsoft sql server');

        // Windows (or Samba) from the NTLM challenge.
        $major = is_int($ntlm['major'] ?? null) ? $ntlm['major'] : 0;
        $minor = is_int($ntlm['minor'] ?? null) ? $ntlm['minor'] : 0;
        $build = is_int($ntlm['build'] ?? null) ? $ntlm['build'] : 0;
        if ($major > 0 && !str_contains($products, 'samba')) {
            [$name, $class] = self::windows($major, $minor, $build, $serverClues);
            return ['os_name' => $name, 'os_build' => $build > 0 ? (string) $build : '', 'device_class' => $class];
        }
        // Clues from banners and pages, most specific first.
        $rules = [
            ['/synology|diskstation/', 'Synology DSM (NAS)', 'other'], ['/qnap|qts/', 'QNAP QTS (NAS)', 'other'], ['/truenas|freenas/', 'TrueNAS (NAS)', 'other'],
            ['/vmware esxi/', 'VMware ESXi', 'server'], ['/proxmox/', 'Proxmox VE', 'server'],
            ['/idrac|integrated lights-out|\bilo\b|ipmi|supermicro bmc/', 'Server remote management (iDRAC, iLO, IPMI)', 'other'],
            ['/fortigate|fortinet|fortios/', 'Fortinet FortiOS (firewall)', 'other'], ['/pfsense/', 'pfSense (firewall)', 'other'], ['/opnsense/', 'OPNsense (firewall)', 'other'],
            ['/mikrotik|routeros/', 'MikroTik RouterOS', 'other'], ['/cisco/', 'Cisco network device', 'other'], ['/ubiquiti|unifi|edgeos/', 'Ubiquiti network device', 'other'],
            ['/jetdirect|printer|laserjet|brother|canon|epson|lexmark|xerox|ricoh|kyocera|konica|sharp mx/', 'Printer', 'other'],
            ['/samba/', 'Linux or Unix (Samba)', 'server'],
            ['/ubuntu/', 'Ubuntu Linux', 'server'], ['/debian/', 'Debian Linux', 'server'], ['/red hat|rhel|centos|rocky|almalinux/', 'Red Hat family Linux', 'server'],
            ['/freebsd/', 'FreeBSD', 'server'], ['/raspbian/', 'Raspberry Pi OS', 'other'], ['/openssh/', 'Linux or Unix', 'server'],
        ];
        foreach ($rules as [$re, $name, $class]) {
            if (preg_match($re, $products) === 1) {
                return ['os_name' => $name, 'os_build' => '', 'device_class' => $class];
            }
        }
        foreach (['nas_admin' => 'NAS', 'oob_admin' => 'Server remote management (iDRAC, iLO, IPMI)', 'hypervisor_admin' => 'Hypervisor', 'firewall_admin' => 'Firewall'] as $cat => $name) {
            if (in_array($cat, $categories, true)) {
                return ['os_name' => $name, 'os_build' => '', 'device_class' => $cat === 'hypervisor_admin' ? 'server' : 'other'];
            }
        }
        if (array_intersect($open, [9100, 631, 515]) !== []) {
            return ['os_name' => 'Printer', 'os_build' => '', 'device_class' => 'other'];
        }
        if (array_intersect($open, [135, 139, 445]) !== [] || in_array(3389, $open, true)) {
            return ['os_name' => 'Windows', 'os_build' => '', 'device_class' => $serverClues ? 'server' : 'other'];
        }
        return null;
    }

    /** @return array{0:string, 1:string} the Windows name and device class for an NTLM version */
    private static function windows(int $major, int $minor, int $build, bool $serverClues): array
    {
        if ($major === 10 && $minor === 0) {
            if (isset(self::SHARED_BUILDS[$build])) {
                [$client, $server] = self::SHARED_BUILDS[$build];
                return $serverClues ? [$server, 'server'] : [$client . ' or ' . $server, 'other'];
            }
            return match (true) {
                $build === 20348 => ['Windows Server 2022', 'server'],
                $build >= 22000 && $build < 26100, $build > 26100 => ['Windows 11' . self::release($build), 'workstation'],
                $build >= 10240 && $build < 22000 => ['Windows 10' . self::release($build), 'workstation'],
                default => ['Windows 10/11 or Server', $serverClues ? 'server' : 'other'],
            };
        }
        $name = match ($major . '.' . $minor) {
            '6.3' => 'Windows 8.1 or Server 2012 R2', '6.2' => 'Windows 8 or Server 2012', '6.1' => 'Windows 7 or Server 2008 R2',
            '6.0' => 'Windows Vista or Server 2008', '5.2' => 'Windows Server 2003', '5.1' => 'Windows XP', default => 'Windows',
        };
        return [$name, $serverClues ? 'server' : 'other'];
    }

    /** The feature release of a Windows 10/11 build ('' when unknown). */
    private static function release(int $build): string
    {
        $r = [19045 => '22H2', 19044 => '21H2', 19043 => '21H1', 19042 => '20H2', 19041 => '2004', 22000 => '21H2', 22621 => '22H2', 22631 => '23H2', 26200 => '25H2'];
        return isset($r[$build]) ? ' ' . $r[$build] : '';
    }
}
