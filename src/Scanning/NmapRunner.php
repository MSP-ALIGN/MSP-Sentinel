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
 *   -T2 --max-rate 50    "polite" timing, at most 50 packets per second
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
 */
final class NmapRunner
{
    /** Use fromConfig() normally. */
    public function __construct(private readonly string $nmapPath, private readonly int $hostTimeoutSeconds = 1500)
    {
    }

    /** Build from config: scanner.nmap_path (default /usr/bin/nmap). */
    public static function fromConfig(Config $config): self
    {
        return new self((string) $config->get('scanner.nmap_path', '/usr/bin/nmap'), (int) $config->get('scanner.host_timeout', 1500));
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
        $args = [$this->nmapPath, '-sT', '--unprivileged', '-Pn', '-n', '-T2', '--max-rate', '50', '--max-retries', '2',
                 '--host-timeout', '20m', '-sV', '--version-light', '--noninteractive', '-p', PortProfile::toNmapArg($ports), '-oX', '-'];
        if (str_contains($ip, ':')) {
            $args[] = '-6';
        }
        $args[] = $ip;
        return $args;
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
        return $this->run($this->arguments($ip, $ports), $shouldStop, $this->hostTimeoutSeconds);
    }

    /**
     * The command line for a host-discovery sweep (on-premises agent): which hosts in the given networks are up.
     * Unprivileged (TCP connect to common ports, no raw packets), slow timing and a rate limit, no DNS, no port scan.
     *
     * @param list<string> $cidrs Canonical CIDRs of ONE address family, already checked against the signed scope.
     * @return list<string>
     */
    public function discoveryArguments(array $cidrs): array
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
        $args = [$this->nmapPath, '-sn', '--unprivileged', '-n', '-T2', '--max-rate', '50', '--max-retries', '1', '--host-timeout', '2m', '-oX', '-'];
        if ($v6) {
            $args[] = '-6';
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
    public function discover(array $cidrs, callable $shouldStop, int $timeoutSeconds = 14400): array
    {
        return $this->run($this->discoveryArguments($cidrs), $shouldStop, $timeoutSeconds);
    }

    /**
     * Run nmap with fixed arguments (no shell), reading its XML, polling $shouldStop every second.
     *
     * @param list<string> $args
     * @return array{exit:int, xml:string, stderr:string, stopped:bool, timed_out:bool, overflow:bool}
     */
    private function run(array $args, callable $shouldStop, int $timeoutSeconds): array
    {
        $proc = proc_open($args, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, ['PATH' => '/usr/bin:/bin', 'LANG' => 'C']);
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
            if (strlen($xml) > 5_000_000) {
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
}
