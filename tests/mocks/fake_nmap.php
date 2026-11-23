<?php

declare(strict_types=1);

/**
 * Fake nmap for tests. It NEVER sends a packet. It checks that it was called
 * with exactly the gentle, unprivileged arguments NmapRunner promises, records
 * each call, and prints canned nmap XML from tests/fixtures/nmap_hosts.json.
 *
 * Usage (through the wrapper script run.php writes): fake_nmap.php <args-log> <nmap arguments...>
 *
 * Fixture behaviours per IP: "slow" (sleeps 30 s, for cancel and kill-switch tests),
 * "badxml", "exit1", "hosttimeout" (nmap's own host timeout). Unknown IPs have no open ports.
 * A test can "close" ports (as if the client fixed them) by listing "ip:port" strings in
 * nmap-closed.json next to the args log, and take hosts off the network (discovery) with
 * nmap-down.json. Discovery sweeps (-sn) report the fixture hosts inside the given networks.
 */

$log = $argv[1];
$args = array_slice($argv, 2);
file_put_contents($log, json_encode($args) . "\n", FILE_APPEND);
// The agent's per-site timing profiles (-T1/10, -T3/200) are checked like the default -T2/50; anything else fails.
foreach ([['-T1', '10'], ['-T3', '200']] as [$t, $r]) {
    $i = array_search($t, $args, true);
    if ($i !== false && ($args[$i + 1] ?? '') === '--max-rate' && ($args[$i + 2] ?? '') === $r) {
        $args[$i] = '-T2';
        $args[$i + 2] = '50';
    }
}

// Discovery sweep (on-premises agent): exact gentle arguments, then the fixture hosts inside the given networks.
if (in_array('-sn', $args, true)) {
    $want = ['-sn', '--unprivileged', '-n', '-T2', '--max-rate', '50', '--max-retries', '1', '--host-timeout', '2m', '-oX', '-'];
    if (array_slice($args, 0, count($want)) !== $want) {
        fwrite(STDERR, "fake nmap: discovery arguments not as promised\n");
        exit(2);
    }
    foreach ($args as $a) {
        if (in_array($a, ['-sS', '-sU', '-O', '-A', '--script', '-T4', '-T5', '--privileged', '-PE', '-PP'], true)) {
            fwrite(STDERR, "fake nmap: forbidden argument {$a}\n");
            exit(2);
        }
    }
    $cidrs = array_values(array_filter(array_slice($args, count($want)), static fn (string $a): bool => $a !== '-6'));
    $inside = static function (string $ip, string $cidr): bool {
        [$net, $bits] = explode('/', $cidr);
        $a = inet_pton($ip); $b = inet_pton($net);
        if ($a === false || $b === false || strlen($a) !== strlen($b)) { return false; }
        for ($i = 0, $n = (int) $bits; $n > 0; $i++, $n -= 8) {
            $m = $n >= 8 ? 0xFF : (0xFF << (8 - $n)) & 0xFF;
            if ((ord($a[$i]) & $m) !== (ord($b[$i]) & $m)) { return false; }
        }
        return true;
    };
    $hosts = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/nmap_hosts.json'), true);
    $gone = is_file(dirname($log) . '/nmap-down.json') ? (array) json_decode((string) file_get_contents(dirname($log) . '/nmap-down.json'), true) : [];
    echo "<?xml version=\"1.0\"?>\n<nmaprun scanner=\"nmap\" args=\"fake\">\n";
    foreach ($hosts as $ip => $h) {
        $in = false;
        foreach ($cidrs as $c) { $in = $in || $inside((string) $ip, $c); }
        if (!$in || in_array($ip, $gone, true)) { continue; }
        echo '<host><status state="up" reason="syn-ack"/><address addr="' . htmlspecialchars((string) $ip) . '" addrtype="' . (str_contains((string) $ip, ':') ? 'ipv6' : 'ipv4') . '"/>'
            . (isset($h['mac']) ? '<address addr="' . htmlspecialchars($h['mac']) . '" addrtype="mac"/>' : '') . "</host>\n";
    }
    echo "<runstats><finished exit=\"success\"/></runstats></nmaprun>\n";
    exit(0);
}

$required = ['-sT', '--unprivileged', '-Pn', '-n', '-T2', '--max-rate', '50', '--max-retries', '2', '--host-timeout', '20m', '-sV', '--version-light', '--noninteractive', '-oX', '-'];
$pos = 0;
foreach ($required as $want) {
    $found = array_search($want, array_slice($args, $pos), true);
    if ($found === false) {
        fwrite(STDERR, "fake nmap: missing or misplaced argument {$want}\n");
        exit(2);
    }
    $pos += $found + 1;
}
foreach ($args as $a) {
    if (in_array($a, ['-sS', '-sU', '-O', '-A', '--script', '-T4', '-T5', '--privileged'], true)) {
        fwrite(STDERR, "fake nmap: forbidden argument {$a}\n");
        exit(2);
    }
}
$pIndex = array_search('-p', $args, true);
$ports = [];
foreach (explode(',', $args[$pIndex + 1]) as $part) {
    [$a, $b] = array_pad(explode('-', $part), 2, null);
    for ($p = (int) $a; $p <= (int) ($b ?? $a); $p++) {
        $ports[$p] = true;
    }
}
$ip = end($args);
$hosts = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/nmap_hosts.json'), true);
$host = $hosts[$ip] ?? ['open' => []];
$closed = is_file(dirname($log) . '/nmap-closed.json') ? (array) json_decode((string) file_get_contents(dirname($log) . '/nmap-closed.json'), true) : [];
$host['open'] = array_values(array_filter($host['open'] ?? [], static fn (array $s): bool => !in_array($ip . ':' . $s['port'], $closed, true)));

switch ($host['behaviour'] ?? '') {
    case 'slow':
        sleep(30);
        break;
    case 'badxml':
        echo "<?xml version=\"1.0\"?><nmaprun><host><unclosed>";
        exit(0);
    case 'exit1':
        fwrite(STDERR, "Failed to resolve something\n");
        exit(1);
    case 'hosttimeout':
        // What real nmap prints when --host-timeout fires: the host has no <ports>, but the run "succeeds".
        echo "<?xml version=\"1.0\"?><nmaprun><host starttime=\"1\" endtime=\"2\" timedout=\"true\"><status state=\"up\"/><address addr=\"{$ip}\" addrtype=\"ipv4\"/></host>"
            . "<runstats><finished time=\"2\" exit=\"success\"/></runstats></nmaprun>\n";
        exit(0);
}

$e = static fn (string $s): string => htmlspecialchars($s, ENT_XML1 | ENT_QUOTES, 'UTF-8');
$addrType = str_contains($ip, ':') ? 'ipv6' : 'ipv4';
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner=\"nmap\" args=\"fake\" version=\"7.94SVN\" xmloutputversion=\"1.05\">\n";
echo "<host><status state=\"up\" reason=\"user-set\"/><address addr=\"{$e($ip)}\" addrtype=\"{$addrType}\"/><ports>\n";
foreach ($host['open'] as $svc) {
    if (!isset($ports[$svc['port']])) {
        continue; // only report ports that were asked for
    }
    echo "<port protocol=\"tcp\" portid=\"{$svc['port']}\"><state state=\"open\" reason=\"syn-ack\"/>";
    echo "<service name=\"{$e($svc['name'] ?? '')}\" product=\"{$e($svc['product'] ?? '')}\" version=\"{$e($svc['version'] ?? '')}\" extrainfo=\"{$e($svc['extra'] ?? '')}\" method=\"probed\" conf=\"10\">";
    if (isset($svc['cpe'])) {
        echo "<cpe>{$e($svc['cpe'])}</cpe>";
    }
    echo "</service></port>\n";
}
// A host with a different address must be ignored by the parser.
echo "</ports></host>\n<host><address addr=\"192.0.2.250\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"1\"><state state=\"open\"/></port></ports></host>\n";
echo "<runstats><finished time=\"0\" exit=\"success\"/></runstats></nmaprun>\n";
