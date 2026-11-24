<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

use Sentinel\Core\Config;

/**
 * Runs nmap against ONE IP address with fixed, gentle settings and returns its XML output.
 *
 * Fixed arguments (no user-controlled options):
 *   -sT --unprivileged   TCP connect scan, no root or raw sockets needed
 *   -Pn -n               no ping (many hosts block it), no reverse DNS
 *   -T2 --max-rate 50    "polite" timing (a pause between probes; about 2-3 probes a second in practice), at most
 *                        50 packets per second: the "gentle" profile. Agents can be set per site to "very_gentle"
 *                        (also one probe at a time, at most 10 per second) or "normal" (-T3: no pause between
 *                        probes, in parallel, at most 200 per second; far more traffic). Never faster: PROFILES.
 *   --max-retries 2 --host-timeout 20m
 *   -sV --version-light  light service/version detection on open ports only
 *   -p <ports> -oX -     ports from PortProfile (ints), XML to stdout
 *
 * Security assumptions:
 * - The process is started with an argument ARRAY (proc_open, no shell),
 *   so nothing can be injected. The IP must be a canonical address (checked
 *   here again) and the port list is built from validated integers.
 * - The caller has confirmed the IP is in scope right before calling scan().
 * - While nmap runs, $shouldStop is polled every second (kill switch,
 *   cancel, window end, scope). nmap is terminated as soon as it returns
 *   true OR throws (for example the database went away). A hard timeout
 *   applies as well, and nmap is always terminated and reaped, even when
 *   something goes wrong (try/finally), so no nmap can outlive the worker's control.
 * - nmap is not bundled (its licence is the NPSL). The MSP installs it, and its path comes from config.
 * - Windows (1.47.2): the null device is NUL (not /dev/null, which made nmap fail to start), nmap gets the Windows
 *   environment it needs (SystemRoot, or Winsock can't start; PATH; TEMP), and its output goes to two private
 *   temporary files instead of pipes, because PHP on Windows can't read process pipes without blocking (no
 *   stream_select or non-blocking mode there): the stop check must keep running every second while nmap works.
 */
final class NmapRunner
{
    /**
     * Timing profiles: the nmap arguments that set the pace. Based on -T2 plus explicit limits (the -T1 template waits
     * 15 seconds between probes, too slow to finish real scans). Nothing faster than -T3 exists here.
     */
    public const PROFILES = [
        'very_gentle' => ['-T2', '--max-rate', '10', '--max-parallelism', '1'],
        'gentle' => ['-T2', '--max-rate', '50'],
        'normal' => ['-T3', '--max-rate', '200'],
    ];

    /** Use fromConfig() normally. */
    /** $fileCapture: collect output in temporary files (null: on Windows only; tests can force it to check that path). */
    public function __construct(private readonly string $nmapPath, private readonly int $hostTimeoutSeconds = 1500, private readonly string $profile = 'gentle',
        private readonly ?bool $fileCapture = null)
    {
        if (!isset(self::PROFILES[$profile])) {
            throw new \InvalidArgumentException('Unknown timing profile.');
        }
    }

    /** The same runner with another timing profile (agents: the site's setting from the signed job). */
    public function withProfile(string $profile): self
    {
        return new self($this->nmapPath, $this->hostTimeoutSeconds, $profile, $this->fileCapture);
    }

    /** Build from config: scanner.nmap_path (default /usr/bin/nmap). */
    public static function fromConfig(Config $config): self
    {
        return new self((string) $config->get('scanner.nmap_path', '/usr/bin/nmap'), (int) $config->get('scanner.host_timeout', 1500));
    }

    /** The first line of `nmap --version` (diagnostics), or '' when it can't be run. */
    public function version(): string
    {
        if (!$this->available()) {
            return '';
        }
        // Through the same runner as scans (1.47.2): Windows-safe, and a hung nmap can't block diagnostics (15 s limit).
        try {
            $r = $this->run([$this->nmapPath, '--version'], static fn (): bool => false, 15, 100_000);
        } catch (\RuntimeException) {
            return '';
        }
        return trim(mb_substr(strtok($r['xml'], "\n") ?: '', 0, 200));
    }

    /** True if the configured nmap binary exists and is executable. */
    public function available(): bool
    {
        return is_file($this->nmapPath) && is_executable($this->nmapPath);
    }

    /**
     * The exact command line for one host (public so tests and the UI can show it).
     *
     * @param list<int> $ports
     * @return list<string>
     */
    public function arguments(string $ip, array $ports): array
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || inet_ntop((string) inet_pton($ip)) !== $ip) {
            throw new \InvalidArgumentException('Target must be a canonical IP address.');
        }
        if ($ports === []) {
            throw new \InvalidArgumentException('No ports to scan.');
        }
        foreach ($ports as $p) {
            if (!is_int($p) || $p < 1 || $p > 65535) {
                throw new \InvalidArgumentException('Invalid port.');
            }
        }
        $args = [$this->nmapPath, '-sT', '--unprivileged', '-Pn', '-n', ...self::PROFILES[$this->profile], '--max-retries', '2',
                 '--host-timeout', '20m', '-sV', '--version-light', '--noninteractive', '-p', PortProfile::toNmapArg($ports), '-oX', '-'];
        if (str_contains($ip, ':')) {
            $args[] = '-6';
        }
        $args[] = $ip;
        return $args;
    }

    /**
     * nmap script selection for engagements (fixed strings; nothing from a form reaches nmap):
     * - SAFE_SCRIPTS: nmap's "safe" scripts, minus anything that checks for vulnerabilities (some send attack-like
     *   requests, e.g. Heartbleed or slowloris checks), broadcasts on the local network, contacts third parties,
     *   guesses passwords, may crash a service, exploits, fuzzes or checks for malware;
     * - ANON_SCRIPTS: read-only anonymous-access checks over TCP: anonymous FTP login (lists the top folder) and NFS
     *   exports. (nmap's SMB share script is NOT used: it writes and deletes a test file in every share. SNMP is UDP,
     *   which an unprivileged nmap can't scan: Sentinel's own UDP probes check it.)
     */
    public const SAFE_SCRIPTS = 'safe and not (vuln or broadcast or external or brute or dos or exploit or intrusive or fuzzer or malware)';
    public const ANON_SCRIPTS = 'ftp-anon or nfs-showmount';

    /**
     * The command line for an engagement's deeper scan of ONE host: all TCP ports or a list, and optional scripts.
     * Same unprivileged TCP connect scan and timing profiles as above (never faster than "normal" -T3), a longer host
     * timeout, and a time limit per script.
     *
     * @param list<int>|null $ports null: all 65,535 TCP ports
     * @param list<string> $scripts each one of SAFE_SCRIPTS or ANON_SCRIPTS
     * @return list<string>
     */
    public function engagementArguments(string $ip, ?array $ports, array $scripts): array
    {
        $args = $this->arguments($ip, $ports ?? [1]);
        foreach ($scripts as $sc) {
            if (!in_array($sc, [self::SAFE_SCRIPTS, self::ANON_SCRIPTS], true)) {
                throw new \InvalidArgumentException('Unknown script selection.');
            }
        }
        $i = array_search('-p', $args, true);
        $args[$i + 1] = $ports === null ? '1-65535' : PortProfile::toNmapArg($ports);
        $t = array_search('--host-timeout', $args, true);
        $args[$t + 1] = '180m';
        if ($scripts !== []) {
            $at = array_search('-oX', $args, true);
            array_splice($args, $at, 0, ['--script', '(' . implode(') or (', $scripts) . ')', '--script-timeout', '3m']);
        }
        return $args;
    }

    /**
     * An engagement's deeper scan of one host (see engagementArguments()). Up to 3.5 hours and 20 MB of output.
     *
     * @param list<int>|null $ports
     * @param list<string> $scripts
     * @param callable():bool $shouldStop
     * @return array{exit:int, xml:string, stderr:string, stopped:bool, timed_out:bool, overflow:bool}
     */
    public function deepScan(string $ip, ?array $ports, array $scripts, callable $shouldStop): array
    {
        return $this->run($this->engagementArguments($ip, $ports, $scripts), $shouldStop, 12600, 20_000_000);
    }

    /**
     * Scan one host.
     *
     * @param list<int>      $ports
     * @param callable():bool $shouldStop Polled every second while nmap runs. True terminates it.
     * @return array{exit:int, xml:string, stderr:string, stopped:bool, timed_out:bool, overflow:bool}
     */
    public function scan(string $ip, array $ports, callable $shouldStop): array
    {
        return $this->run($this->arguments($ip, $ports), $shouldStop, $this->hostTimeoutSeconds, 5_000_000);
    }

    /**
     * The command line for a host-discovery sweep (on-premises agent): which hosts in the given networks are up.
     * Unprivileged (TCP connect to common ports, no raw packets), slow timing and a rate limit, no DNS, no port scan.
     *
     * @param list<string> $cidrs Canonical CIDRs of ONE address family, already checked against the signed scope.
     * @return list<string>
     */
    public function discoveryArguments(array $cidrs, array $exclude = []): array
    {
        if ($cidrs === [] || count($cidrs) > 64) {
            throw new \InvalidArgumentException('Between 1 and 64 networks.');
        }
        $v6 = null;
        foreach ($cidrs as $c) {
            if (!is_string($c) || !preg_match('#^([0-9a-f:.]+)/(\d{1,3})$#', $c, $m) || @inet_pton($m[1]) === false || inet_ntop((string) inet_pton($m[1])) !== $m[1]) {
                throw new \InvalidArgumentException('Networks must be canonical CIDRs.');
            }
            $isV6 = str_contains($m[1], ':');
            if ($v6 !== null && $v6 !== $isV6) {
                throw new \InvalidArgumentException('One address family per sweep.');
            }
            $v6 = $isV6;
        }
        $args = [$this->nmapPath, '-sn', '--unprivileged', '-n', ...self::PROFILES[$this->profile], '--max-retries', '1', '--host-timeout', '2m', '-oX', '-'];
        if ($v6) {
            $args[] = '-6';
        }
        // Engagements: hosts never to touch, not even by the sweep (canonical addresses or CIDRs, checked here too).
        $ex = [];
        foreach (array_slice($exclude, 0, 64) as $x) {
            if (!is_string($x) || !preg_match('#^([0-9a-f:.]+)(/\d{1,3})?$#', $x, $m) || @inet_pton($m[1]) === false || inet_ntop((string) inet_pton($m[1])) !== $m[1]) {
                throw new \InvalidArgumentException('Exclusions must be canonical addresses or CIDRs.');
            }
            $ex[] = $x;
        }
        if ($ex !== []) {
            array_push($args, '--exclude', implode(',', $ex));
        }
        return array_merge($args, $cidrs);
    }

    /**
     * Host-discovery sweep (see discoveryArguments()).
     *
     * @param list<string>   $cidrs
     * @param callable():bool $shouldStop
     * @return array{exit:int, xml:string, stderr:string, stopped:bool, timed_out:bool, overflow:bool}
     */
    public function discover(array $cidrs, callable $shouldStop, int $timeoutSeconds = 57600, array $exclude = []): array
    {
        // Large networks: up to 16 hours and 60 MB of output (about 200,000 hosts that are up).
        return $this->run($this->discoveryArguments($cidrs, $exclude), $shouldStop, $timeoutSeconds, 60_000_000);
    }

    /**
     * Run nmap with fixed arguments (no shell), reading its XML, polling $shouldStop every second.
     *
     * @param list<string> $args
     * @return array{exit:int, xml:string, stderr:string, stopped:bool, timed_out:bool, overflow:bool}
     */
    private function run(array $args, callable $shouldStop, int $timeoutSeconds, int $maxBytes): array
    {
        // Always on Windows (its pipes can't be read without blocking); elsewhere only when a test asks for it.
        if (PHP_OS_FAMILY === 'Windows' || $this->fileCapture === true) {
            return $this->runToFiles($args, $shouldStop, $timeoutSeconds, $maxBytes);
        }
        $proc = proc_open($args, [0 => ['file', self::nullDevice(), 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, self::environment($this->nmapPath));
        if (!is_resource($proc)) {
            throw new \RuntimeException('Could not start nmap.');
        }
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $xml = '';
        $stderr = '';
        $stopped = false;
        $timedOut = false;
        $overflow = false;
        $exit = -1;
        $deadline = time() + $timeoutSeconds;
        $lastPoll = 0.0;
        try {
        while (true) {
            $read = [$pipes[1], $pipes[2]];
            $write = $except = null;
            if (@stream_select($read, $write, $except, 0, 200000) > 0) {
                foreach ($read as $r) {
                    $chunk = (string) fread($r, 65536);
                    if ($r === $pipes[1]) {
                        $xml .= $chunk;
                    } elseif (strlen($stderr) < 20000) {
                        $stderr .= $chunk;
                    }
                }
            }
            if (strlen($xml) > $maxBytes) {
                $overflow = true; // runaway output: stop rather than fill memory
            }
            $status = proc_get_status($proc);
            if (!$status['running']) {
                $xml .= (string) stream_get_contents($pipes[1]);
                $stderr .= (string) stream_get_contents($pipes[2]);
                break;
            }
            if (microtime(true) - $lastPoll >= 1.0) {
                $lastPoll = microtime(true);
                try {
                    if (!$stopped && $shouldStop()) {
                        $stopped = true;
                    }
                } catch (\Throwable $ex) {
                    $stopped = true; // if we can't check whether we may continue, we don't
                    error_log('[msp-sentinel] stop check failed, stopping nmap: ' . $ex->getMessage());
                }
            }
            if (time() > $deadline) {
                $timedOut = true;
            }
            if ($stopped || $timedOut || $overflow) {
                break;
            }
        }
        } finally {
            // Always make sure nmap is gone before returning or throwing.
            if (proc_get_status($proc)['running']) {
                proc_terminate($proc, 15);
                for ($i = 0; $i < 10 && proc_get_status($proc)['running']; $i++) {
                    usleep(100000);
                }
                if (proc_get_status($proc)['running']) {
                    proc_terminate($proc, 9);
                }
            }
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exit = proc_close($proc);
        }
        return ['exit' => $exit, 'xml' => $xml, 'stderr' => mb_substr($stderr, 0, 2000), 'stopped' => $stopped, 'timed_out' => $timedOut, 'overflow' => $overflow];
    }

    /**
     * Run nmap with its output going to two private temporary files (Windows, see the class notes): the loop only
     * polls whether nmap is still running, so the stop check runs every second. Same result and limits as run().
     *
     * @param list<string> $args
     * @return array{exit:int, xml:string, stderr:string, stopped:bool, timed_out:bool, overflow:bool}
     */
    private function runToFiles(array $args, callable $shouldStop, int $timeoutSeconds, int $maxBytes): array
    {
        // The service account's temp folder: only that account, SYSTEM and Administrators can read files made there.
        $out = tempnam(sys_get_temp_dir(), 'snx');
        $err = tempnam(sys_get_temp_dir(), 'sne');
        if ($out === false || $err === false) {
            throw new \RuntimeException('Could not start nmap: no temporary file for its output.');
        }
        $proc = proc_open($args, [0 => ['file', self::nullDevice(), 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes, null,
            self::environment($this->nmapPath), ['bypass_shell' => true]);
        if (!is_resource($proc)) {
            @unlink($out);
            @unlink($err);
            throw new \RuntimeException('Could not start nmap.');
        }
        $stopped = false;
        $timedOut = false;
        $overflow = false;
        $exit = -1;
        $deadline = time() + $timeoutSeconds;
        $lastPoll = 0.0;
        try {
            while (proc_get_status($proc)['running']) {
                usleep(200000);
                clearstatcache();
                if ((int) @filesize($out) > $maxBytes || (int) @filesize($err) > 1_000_000) {
                    $overflow = true; // runaway output (results or errors): stop rather than fill the disk
                }
                if (microtime(true) - $lastPoll >= 1.0) {
                    $lastPoll = microtime(true);
                    try {
                        if (!$stopped && $shouldStop()) {
                            $stopped = true;
                        }
                    } catch (\Throwable $ex) {
                        $stopped = true; // if we can't check whether we may continue, we don't
                        error_log('[msp-sentinel] stop check failed, stopping nmap: ' . $ex->getMessage());
                    }
                }
                if (time() > $deadline) {
                    $timedOut = true;
                }
                if ($stopped || $timedOut || $overflow) {
                    break;
                }
            }
        } finally {
            // Always make sure nmap is gone before returning or throwing (bypass_shell: this is nmap itself, not a shell).
            if (proc_get_status($proc)['running']) {
                proc_terminate($proc, 15);
                for ($i = 0; $i < 10 && proc_get_status($proc)['running']; $i++) {
                    usleep(100000);
                }
                if (proc_get_status($proc)['running']) {
                    proc_terminate($proc, 9);
                }
            }
            $exit = proc_close($proc);
            $xml = (string) @file_get_contents($out, false, null, 0, $maxBytes + 1);
            $stderr = (string) @file_get_contents($err, false, null, 0, 20000);
            @unlink($out);
            @unlink($err);
        }
        return ['exit' => $exit, 'xml' => $xml, 'stderr' => mb_substr($stderr, 0, 2000), 'stopped' => $stopped, 'timed_out' => $timedOut, 'overflow' => $overflow];
    }

    /** The null device: NUL on Windows (no /dev/null there), /dev/null elsewhere. */
    private static function nullDevice(): string
    {
        return PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
    }

    /**
     * nmap's environment: nothing inherited but what it needs. Windows: SystemRoot (without it Winsock can't start),
     * PATH (nmap's own folder for its DLLs, then System32) and TEMP; elsewhere a fixed PATH.
     *
     * @return array<string,string>
     */
    private static function environment(string $nmapPath): array
    {
        if (PHP_OS_FAMILY !== 'Windows') {
            return ['PATH' => '/usr/bin:/bin', 'LANG' => 'C'];
        }
        $root = (string) (getenv('SystemRoot') ?: 'C:\\Windows');
        $tmp = sys_get_temp_dir();
        return ['SystemRoot' => $root, 'WINDIR' => $root, 'PATH' => dirname($nmapPath) . ';' . $root . '\\System32', 'TEMP' => $tmp, 'TMP' => $tmp];
    }
}
