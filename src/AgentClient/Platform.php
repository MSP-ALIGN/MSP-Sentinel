<?php

declare(strict_types=1);

namespace Sentinel\AgentClient;

/**
 * What differs between the Linux and the Windows agent: where its files live, where nmap is, how the ARP table is
 * read, and which features the system allows. Everything else (jobs, signatures, scans, results) is the same code.
 *
 * Linux: /etc/sentinel-agent (config, root-owned), /var/lib/sentinel-agent (state), /var/lib/sentinel-agent-update
 * (update helper results), /usr/bin/nmap, the ARP table from /proc/net/arp.
 * Windows (Server 2022/2025, Windows 11, 64-bit): C:\ProgramData\MSP Sentinel Agent\config (config; Administrators and
 * SYSTEM can change it, the agent's service account can only read it), ...\state (the service account's only writable
 * folder), ...\update (the SYSTEM update task's results; read-only for the agent), nmap from its default install folder,
 * the ARP table from `arp -a`. No Npcap: nmap runs unprivileged TCP connect scans (-sT --unprivileged), as on Linux.
 * The name-poisoning listener is Linux only: on Windows the system itself owns UDP 137 and 5355.
 *
 * TEST SUITE ONLY: the platform can be forced (testing.platform = 'windows', with SENTINEL_TEST_MODE=1), and the ARP
 * table read from a file in either format (testing.arp_file), so the Windows paths run in the Linux test suite.
 *
 * Untrusted: nothing here comes from the network. The ARP output is parsed strictly (IP and MAC patterns only).
 */
final class Platform
{
    public const LINUX = 'linux';
    public const WINDOWS = 'windows';

    private function __construct(public readonly string $os, private readonly string $arpFile)
    {
    }

    /** The platform this agent runs on (test mode may force one and the ARP source). */
    public static function detect(?string $forced = null, ?string $arpFile = null): self
    {
        $os = $forced === self::WINDOWS || $forced === self::LINUX ? $forced : (PHP_OS_FAMILY === 'Windows' ? self::WINDOWS : self::LINUX);
        return new self($os, $arpFile ?? ($os === self::LINUX ? '/proc/net/arp' : ''));
    }

    public function isWindows(): bool
    {
        return $this->os === self::WINDOWS;
    }

    /** Base folder of the Windows agent's data (ProgramData). */
    private static function windowsData(): string
    {
        $base = getenv('ProgramData');
        return (is_string($base) && $base !== '' ? rtrim($base, '\\/') : 'C:\\ProgramData') . '\\MSP Sentinel Agent';
    }

    /** The default config file (enrolment writes it; the service reads it). */
    public function configFile(): string
    {
        return $this->isWindows() ? self::windowsData() . '\\config\\agent.json' : '/etc/sentinel-agent/agent.json';
    }

    /** The pinned release key file (written by the installer or the update helper, never by the agent). */
    public function releaseKeyFile(): string
    {
        return $this->isWindows() ? self::windowsData() . '\\config\\release-key.pub' : '/etc/sentinel-agent/release-key.pub';
    }

    /** Where the update helper writes its results (the agent reads them). */
    public function updateResultDir(): string
    {
        return $this->isWindows() ? self::windowsData() . '\\update' : '/var/lib/sentinel-agent-update';
    }

    /** nmap's default location (enrolment writes it into the config; the config wins). */
    public function nmapPath(): string
    {
        if (!$this->isWindows()) {
            return '/usr/bin/nmap';
        }
        foreach (['ProgramFiles(x86)', 'ProgramFiles'] as $var) {
            $dir = getenv($var);
            if (is_string($dir) && $dir !== '' && is_file($dir . '\\Nmap\\nmap.exe')) {
                return $dir . '\\Nmap\\nmap.exe';
            }
        }
        return 'C:\\Program Files (x86)\\Nmap\\nmap.exe';
    }

    /** Whether the LLMNR/NetBIOS listener can run (Linux only: Windows owns those ports itself). */
    public function namesListener(): bool
    {
        return !$this->isWindows();
    }

    /**
     * MAC addresses the system's ARP table knows, by IP (lowercase, colon-separated). Linux: /proc/net/arp. Windows:
     * `arp -a` (System32's arp.exe, no shell, 10 seconds at most). A table that can't be read is empty: MAC addresses
     * are a bonus, never required.
     *
     * @return array<string,string>
     */
    public function arpTable(): array
    {
        if ($this->arpFile !== '') {
            $text = is_readable($this->arpFile) ? (string) file_get_contents($this->arpFile, false, null, 0, 1048576) : '';
        } else {
            $text = $this->isWindows() ? self::runArp() : '';
        }
        return $this->isWindows() ? self::parseWindowsArp($text) : self::parseLinuxArp($text);
    }

    /** /proc/net/arp: a header line, then "IP HW-type Flags HW-address Mask Device". */
    public static function parseLinuxArp(string $text): array
    {
        $out = [];
        foreach (array_slice(preg_split('/\R/', $text) ?: [], 1) as $line) {
            $cols = preg_split('/\s+/', trim($line)) ?: [];
            if (count($cols) >= 4 && filter_var($cols[0], FILTER_VALIDATE_IP) && preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i', $cols[3]) && $cols[3] !== '00:00:00:00:00:00') {
                $out[$cols[0]] = strtolower($cols[3]);
            }
        }
        return $out;
    }

    /**
     * `arp -a` on Windows: per interface, lines "  192.168.1.10      00-11-22-33-44-55     dynamic". Only dynamic and
     * static unicast entries with a real MAC address; broadcast and multicast entries (ff-ff-..., 01-00-5e-...) are skipped.
     */
    public static function parseWindowsArp(string $text): array
    {
        $out = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            if (preg_match('/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-f]{2}-){5}[0-9a-f]{2})\s+\S+\s*$/i', $line, $m) !== 1 || !filter_var($m[1], FILTER_VALIDATE_IP)) {
                continue;
            }
            $mac = strtolower(str_replace('-', ':', $m[2]));
            // Not broadcast, not the all-zero address, and not a multicast MAC (lowest bit of the first byte set).
            if ($mac === 'ff:ff:ff:ff:ff:ff' || $mac === '00:00:00:00:00:00' || (hexdec(substr($mac, 0, 2)) & 1) === 1) {
                continue;
            }
            $out[$m[1]] = $mac;
        }
        return $out;
    }

    /** Runs System32's arp.exe -a (array form: no shell), at most 10 seconds and 1 MB of output. */
    private static function runArp(): string
    {
        $root = getenv('SystemRoot');
        $arp = (is_string($root) && $root !== '' ? rtrim($root, '\\/') : 'C:\\Windows') . '\\System32\\ARP.EXE';
        if (!is_file($arp)) {
            return '';
        }
        $p = @proc_open([$arp, '-a'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, null, ['bypass_shell' => true]);
        if (!is_resource($p)) {
            return '';
        }
        stream_set_blocking($pipes[1], false);
        $out = '';
        $end = microtime(true) + 10;
        while (microtime(true) < $end && strlen($out) < 1048576) {
            $chunk = (string) fread($pipes[1], 65536);
            $out .= $chunk;
            if ($chunk === '' && !proc_get_status($p)['running']) {
                break;
            }
            if ($chunk === '') {
                usleep(20000);
            }
        }
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        proc_terminate($p);
        proc_close($p);
        return $out;
    }

    /**
     * Uptime in seconds and available memory in MB for diagnostics, where the system tells (Linux /proc). On Windows
     * these stay null (PHP can't read them without extra extensions; the Windows tools show them).
     *
     * @return array{uptime:?int, memory_mb:?int}
     */
    public function systemInfo(): array
    {
        if ($this->isWindows()) {
            return ['uptime' => null, 'memory_mb' => null];
        }
        $uptime = is_readable('/proc/uptime') ? (int) (float) explode(' ', (string) file_get_contents('/proc/uptime'))[0] : null;
        $mem = null;
        if (is_readable('/proc/meminfo') && preg_match('/MemAvailable:\s+(\d+)/', (string) file_get_contents('/proc/meminfo'), $m)) {
            $mem = intdiv((int) $m[1], 1024);
        }
        return ['uptime' => $uptime, 'memory_mb' => $mem];
    }
}
