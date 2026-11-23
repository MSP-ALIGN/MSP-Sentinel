<?php

declare(strict_types=1);

namespace Sentinel\Directory;

/**
 * Listens, without ever answering, for LLMNR (UDP 5355, multicast 224.0.0.252) and NetBIOS name service (UDP 137,
 * broadcast) queries on the agent's network for a fixed time. A device that sends them falls back to these protocols
 * when DNS has no answer, and a name-poisoning tool (Responder and the like) can answer instead and capture its
 * users' password hashes. Only queries count; nothing is ever sent.
 *
 * Port 137 is below 1024: the agent's service has CAP_NET_BIND_SERVICE for it (and nothing else). When a port can't
 * be opened, that protocol is reported as not listened to (never as "nothing heard").
 *
 * Untrusted: every packet. Only the source address (kept only when inside the signed ranges, by the caller's filter)
 * and the queried name (decoded defensively, cleaned, shortened) are kept; sources and names are capped.
 */
final class NameListener
{
    public const MAX_SOURCES = 500;
    private const MAX_NAMES = 10;

    /**
     * @param string $bindIp      address to listen on (0.0.0.0; 127.0.0.1 in the test suite)
     * @param bool   $multicast   join the LLMNR multicast group (off in the test suite)
     * @param string $loopbackAs  TEST SUITE ONLY: packets from 127.0.0.1 count as from this address (tests can't send
     *                            from inside the signed ranges); '' in production
     */
    public function __construct(private readonly string $bindIp = '0.0.0.0', private readonly int $llmnrPort = 5355, private readonly int $nbnsPort = 137,
        private readonly bool $multicast = true, private readonly string $loopbackAs = '')
    {
    }

    /**
     * Listen for $seconds.
     *
     * @param callable(string):bool $accept which source addresses may be kept (the signed ranges)
     * @param callable():bool       $stop   true to stop early (kill switch)
     * @return array{seconds:int, llmnr:bool, nbns:bool, sources:list<array{ip:string, protocols:list<string>, names:list<string>}>}
     */
    public function listen(int $seconds, callable $accept, callable $stop): array
    {
        $out = ['seconds' => 0, 'llmnr' => false, 'nbns' => false, 'sources' => []];
        if (!function_exists('socket_create')) {
            return $out;
        }
        $sockets = [];
        foreach (['llmnr' => $this->llmnrPort, 'nbns' => $this->nbnsPort] as $proto => $port) {
            $s = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
            if ($s === false) {
                continue;
            }
            @socket_set_option($s, SOL_SOCKET, SO_REUSEADDR, 1);
            if ($proto === 'nbns') {
                @socket_set_option($s, SOL_SOCKET, SO_BROADCAST, 1);
            }
            if (!@socket_bind($s, $this->bindIp, $port)) {
                socket_close($s);
                continue;
            }
            if ($proto === 'llmnr' && $this->multicast && !@socket_set_option($s, IPPROTO_IP, MCAST_JOIN_GROUP, ['group' => '224.0.0.252', 'interface' => 0])) {
                socket_close($s);
                continue;
            }
            $sockets[$proto] = $s;
            $out[$proto] = true;
        }
        $seen = [];
        $start = microtime(true);
        while ($sockets !== [] && microtime(true) - $start < $seconds && !$stop()) {
            $read = array_values($sockets);
            $w = $e = null;
            if (@socket_select($read, $w, $e, 1) < 1) {
                continue;
            }
            foreach ($read as $s) {
                $proto = (string) array_search($s, $sockets, true);
                $buf = '';
                $from = '';
                $fromPort = 0;
                if (@socket_recvfrom($s, $buf, 1500, 0, $from, $fromPort) === false || !is_string($from)) {
                    continue;
                }
                if ($from === '127.0.0.1' && $this->loopbackAs !== '') {
                    $from = $this->loopbackAs;
                }
                if (filter_var($from, FILTER_VALIDATE_IP) === false || !$accept($from)) {
                    continue;
                }
                $name = $proto === 'llmnr' ? self::llmnrName($buf) : self::nbnsName($buf);
                if ($name === null) {
                    continue; // not a query (an answer, or garbage)
                }
                if (!isset($seen[$from]) && count($seen) >= self::MAX_SOURCES) {
                    continue;
                }
                $seen[$from]['protocols'][$proto] = true;
                if (count($seen[$from]['names'] ?? []) < self::MAX_NAMES && $name !== '') {
                    $seen[$from]['names'][strtolower($name)] = $name;
                }
            }
        }
        foreach ($sockets as $s) {
            socket_close($s);
        }
        $out['seconds'] = (int) round(microtime(true) - $start);
        foreach ($seen as $ip => $d) {
            $out['sources'][] = ['ip' => (string) $ip, 'protocols' => array_keys($d['protocols']), 'names' => array_values($d['names'] ?? [])];
        }
        return $out;
    }

    /** The name asked for in an LLMNR query, '' when unreadable, null when it isn't a query. */
    public static function llmnrName(string $p): ?string
    {
        if (strlen($p) < 17) {
            return null;
        }
        $flags = unpack('n', substr($p, 2, 2))[1];
        $qd = unpack('n', substr($p, 4, 2))[1];
        if (($flags & 0x8000) !== 0 || ($flags & 0x7800) !== 0 || $qd < 1) {
            return null; // a response, or not a standard query
        }
        $labels = [];
        for ($o = 12, $n = strlen($p); $o < $n && count($labels) < 10;) {
            $len = ord($p[$o]);
            if ($len === 0 || $len > 63 || $o + 1 + $len > $n) {
                break;
            }
            $labels[] = substr($p, $o + 1, $len);
            $o += 1 + $len;
        }
        return self::clean(implode('.', $labels));
    }

    /** The NetBIOS name asked for in a name-service query, '' when unreadable, null when it isn't a name query. */
    public static function nbnsName(string $p): ?string
    {
        if (strlen($p) < 46) {
            return null;
        }
        $flags = unpack('n', substr($p, 2, 2))[1];
        $qd = unpack('n', substr($p, 4, 2))[1];
        if (($flags & 0x8000) !== 0 || (($flags >> 11) & 0xF) !== 0 || $qd < 1 || ord($p[12]) !== 32) {
            return null; // a response, a registration or release (not a query), or not a NetBIOS name
        }
        $enc = substr($p, 13, 32);
        $name = '';
        for ($i = 0; $i < 30; $i += 2) { // 15 characters; the 16th is the suffix (service type)
            $hi = ord($enc[$i]) - 0x41;
            $lo = ord($enc[$i + 1]) - 0x41;
            if ($hi < 0 || $hi > 15 || $lo < 0 || $lo > 15) {
                return '';
            }
            $name .= chr(($hi << 4) | $lo);
        }
        return self::clean(rtrim($name));
    }

    private static function clean(string $s): string
    {
        return mb_substr(trim((string) preg_replace('/[^\x21-\x7E]/', '', $s)), 0, 64);
    }
}
