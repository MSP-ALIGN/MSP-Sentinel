<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

/**
 * Which TCP ports to scan for a client: the default list, plus per-client
 * extras, minus per-client exclusions.
 *
 * Security assumptions:
 * - Port settings are typed by admins (untrusted text). parseList() accepts
 *   only numbers and ranges from 1 to 65535, limits the total, and returns
 *   ints. The nmap argument is built from those ints, never from the raw text.
 * - TCP only: UDP needs raw sockets (root), and the scanner deliberately
 *   runs unprivileged.
 */
final class PortProfile
{
    /** Default ports: risky services and common firewall/VPN admin ports (design section 7). */
    public const DEFAULT_TCP = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 1723, 2049,
        3306, 3389, 4433, 4443, 5060, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 9443,
        10000, 10443, 27017,
    ];

    /** Ports that should never be open to the internet (shown as high risk; FAIL in the findings step). */
    public const HIGH_RISK = [
        23 => 'Telnet', 445 => 'SMB (file sharing)', 3389 => 'Remote Desktop', 5900 => 'VNC', 1433 => 'Microsoft SQL Server',
        1521 => 'Oracle database', 3306 => 'MySQL/MariaDB', 5432 => 'PostgreSQL', 6379 => 'Redis', 9200 => 'Elasticsearch',
        27017 => 'MongoDB', 135 => 'Windows RPC', 139 => 'NetBIOS', 5985 => 'WinRM (HTTP)', 5986 => 'WinRM (HTTPS)',
    ];

    private const MAX_PORTS = 1000;

    /**
     * Parse "8090, 9000-9010" into a sorted list of ports.
     *
     * @param string $text Untrusted admin input.
     * @return list<int>|string Ports, or an error message.
     */
    public static function parseList(string $text): array|string
    {
        $text = trim($text);
        if ($text === '') {
            return [];
        }
        if (strlen($text) > 500) {
            return __('Too long (500 characters at most).');
        }
        $ports = [];
        foreach (preg_split('/[\s,]+/', $text) ?: [] as $part) {
            if ($part === '') {
                continue;
            }
            if (!preg_match('/^(\d{1,5})(?:-(\d{1,5}))?$/D', $part, $m)) {
                return __('"{part}" is not a port or range. Use numbers like 8090 or 9000-9010.', ['part' => mb_substr($part, 0, 20)]);
            }
            $from = (int) $m[1];
            $to = isset($m[2]) ? (int) $m[2] : $from;
            if ($from < 1 || $to > 65535 || $to < $from) {
                return __('Ports must be between 1 and 65535, with the lower number first.');
            }
            if ($to - $from + 1 + count($ports) > self::MAX_PORTS) {
                return __('At most {n} ports.', ['n' => self::MAX_PORTS]);
            }
            for ($p = $from; $p <= $to; $p++) {
                $ports[$p] = true;
            }
        }
        $list = array_keys($ports);
        sort($list);
        return $list;
    }

    /**
     * The ports to scan for a client.
     *
     * @param array<string,mixed> $client Row with ports_extra and ports_excluded (validated when saved).
     * @return list<int>
     */
    public static function forClient(array $client): array
    {
        $extra = self::parseList((string) ($client['ports_extra'] ?? ''));
        $excluded = self::parseList((string) ($client['ports_excluded'] ?? ''));
        $ports = array_diff(array_unique(array_merge(self::DEFAULT_TCP, is_array($extra) ? $extra : [])), is_array($excluded) ? $excluded : []);
        sort($ports);
        return array_values($ports);
    }

    /**
     * Compact nmap -p value: "21-23,25,80" (from validated ints only).
     *
     * @param list<int> $ports
     */
    public static function toNmapArg(array $ports): string
    {
        $out = [];
        $start = $prev = null;
        foreach ($ports as $p) {
            if ($start === null) {
                $start = $prev = $p;
            } elseif ($p === $prev + 1) {
                $prev = $p;
            } else {
                $out[] = $start === $prev ? (string) $start : $start . '-' . $prev;
                $start = $prev = $p;
            }
        }
        if ($start !== null) {
            $out[] = $start === $prev ? (string) $start : $start . '-' . $prev;
        }
        return implode(',', $out);
    }
}
