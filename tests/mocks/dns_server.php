<?php

declare(strict_types=1);

/**
 * Fake DNS server for tests (UDP and TCP on 127.0.0.1). Answers from a JSON
 * zone file. It is never used in production and never forwards queries anywhere.
 *
 * Usage: php tests/mocks/dns_server.php <port> <zone.json> [query-log-file]
 *
 * Zone file:
 *   {"records": {"name": {"A": [...], "AAAA": [...], "MX": [...], "NS": [...], "CNAME": [...], "PTR": [...], "TXT": [...]}},
 *    "behaviours": {"name-or-.suffix": "timeout" | "garbage" | "servfail" | "wrong-id" | "truncate" | "extra-answer"}}
 * "extra-answer" adds an unrelated A record (unrelated.example 203.0.113.99) that clients must ignore.
 * Unknown names get NXDOMAIN. Known names without the asked type get an empty NOERROR.
 * For A/AAAA queries on a name with a CNAME, the CNAME and the target's records are returned.
 * Zone transfers (AXFR, TCP only): zones listed in "axfr_open" get SOA, every record under the zone, then SOA again,
 * spread over two messages; every other AXFR gets REFUSED (and any AXFR over UDP too).
 */

if (PHP_SAPI !== 'cli' || $argc < 3) {
    exit(2);
}
$port = (int) $argv[1];
$zone = json_decode((string) file_get_contents($argv[2]), true, 16, JSON_THROW_ON_ERROR);
$log = $argv[3] ?? null;
$types = ['A' => 1, 'NS' => 2, 'CNAME' => 5, 'PTR' => 12, 'MX' => 15, 'TXT' => 16, 'AAAA' => 28];
$typeNames = array_flip($types);

$udp = stream_socket_server("udp://127.0.0.1:{$port}", $errno, $errstr, STREAM_SERVER_BIND);
$tcp = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
if ($udp === false || $tcp === false) {
    fwrite(STDERR, "mock dns: cannot bind {$port}: {$errstr}\n");
    exit(1);
}

function encodeName(string $name): string
{
    $out = '';
    foreach (explode('.', $name) as $label) {
        if ($label === '') {
            continue; // "." is the root (a null MX)
        }
        $out .= chr(strlen($label)) . $label;
    }
    return $out . "\0";
}

function behaviour(array $zone, string $name): ?string
{
    foreach ($zone['behaviours'] ?? [] as $key => $what) {
        if ($name === $key || (str_starts_with($key, '.') && str_ends_with($name, $key))) {
            return $what;
        }
    }
    return null;
}

/** Build the answer for one query packet, or null for "no reply" (timeout). */
function answer(string $q, array $zone, array $types, array $typeNames, ?string $log, bool $overTcp): string|array|null
{
    if (strlen($q) < 17) {
        return null;
    }
    $id = unpack('n', substr($q, 0, 2))[1];
    $pos = 12;
    $labels = [];
    while (($len = ord($q[$pos])) !== 0) {
        $labels[] = strtolower(substr($q, $pos + 1, $len));
        $pos += $len + 1;
    }
    $qname = implode('.', $labels);
    $qtype = unpack('n', substr($q, $pos + 1, 2))[1];
    $question = substr($q, 12, $pos + 5 - 12);
    if ($log !== null) {
        file_put_contents($log, ($qtype === 252 ? 'AXFR' : ($typeNames[$qtype] ?? $qtype)) . ' ' . $qname . "\n", FILE_APPEND);
    }
    if ($qtype === 252) {
        return axfr($id, $qname, $question, $zone, $types, $overTcp);
    }
    $records = $zone['records'] ?? [];
    $b = behaviour($zone, $qname);
    if ($b === 'timeout') {
        return null;
    }
    if ($b === 'garbage') {
        return pack('n', $id) . random_bytes(7);
    }
    $rcode = 0;
    $answers = [];
    $rr = static function (string $owner, int $type, string $rdata) use ($qname): string {
        // Owner equal to the question name uses a compression pointer to offset 12 (exercises the client's pointer handling).
        $ownerWire = $owner === $qname ? "\xc0\x0c" : encodeName($owner);
        return $ownerWire . pack('nnNn', $type, 1, 300, strlen($rdata)) . $rdata;
    };
    $typeName = $typeNames[$qtype] ?? null;
    if ($b === 'servfail') {
        $rcode = 2;
    } elseif (!isset($records[$qname])) {
        $rcode = 3;
    } else {
        $name = $qname;
        for ($hops = 0; $hops < 5; $hops++) {
            $rec = $records[$name] ?? [];
            if (in_array($typeName, ['A', 'AAAA'], true) && isset($rec['CNAME'][0])) {
                $target = $rec['CNAME'][0];
                $answers[] = $rr($name, 5, encodeName($target));
                $name = $target;
                continue;
            }
            foreach ($rec[$typeName] ?? [] as $value) {
                $rdata = match ($typeName) {
                    'A', 'AAAA' => inet_pton($value),
                    'MX' => pack('n', 10) . encodeName($value),
                    // TXT: split into 255-byte character-strings, like real servers do for long SPF/DKIM records.
                    'TXT' => implode('', array_map(static fn (string $c): string => chr(strlen($c)) . $c, str_split($value, 255) ?: [''])),
                    default => encodeName($value),
                };
                $answers[] = $rr($name, $qtype, $rdata);
            }
            break;
        }
    }
    if ($b === 'extra-answer') {
        $answers[] = $rr('unrelated.example', 1, inet_pton('203.0.113.99'));
    }
    $truncate = $b === 'truncate' && !$overTcp;
    $flags = 0x8180 | $rcode | ($truncate ? 0x0200 : 0);
    $respId = $b === 'wrong-id' ? ($id ^ 0xffff) : $id;
    $out = pack('nnnnnn', $respId, $flags, 1, $truncate ? 0 : count($answers), 0, 0) . $question;
    return $truncate ? $out : $out . implode('', $answers);
}

/**
 * A zone transfer answer: a list of messages (TCP), or one REFUSED message.
 *
 * @return string|list<string>
 */
function axfr(int $id, string $zoneName, string $question, array $zone, array $types, bool $overTcp): string|array
{
    if (!$overTcp || !in_array($zoneName, $zone['axfr_open'] ?? [], true)) {
        return pack('nnnnnn', $id, 0x8180 | 5, 1, 0, 0, 0) . $question;
    }
    $soaData = encodeName('ns1.' . $zoneName) . encodeName('hostmaster.' . $zoneName) . pack('NNNNN', 2026010101, 3600, 600, 86400, 300);
    $soa = encodeName($zoneName) . pack('nnNn', 6, 1, 300, strlen($soaData)) . $soaData;
    $rrs = [];
    foreach ($zone['records'] ?? [] as $name => $rec) {
        if ($name !== $zoneName && !str_ends_with($name, '.' . $zoneName)) {
            continue;
        }
        foreach ($rec as $typeName => $values) {
            foreach ($values as $value) {
                $rdata = in_array($typeName, ['A', 'AAAA'], true) ? inet_pton($value)
                    : ($typeName === 'TXT' ? chr(strlen($value)) . $value : ($typeName === 'MX' ? pack('n', 10) . encodeName($value) : encodeName($value)));
                $rrs[] = encodeName($name) . pack('nnNn', $types[$typeName], 1, 300, strlen($rdata)) . $rdata;
            }
        }
    }
    $half = intdiv(count($rrs), 2);
    $first = array_merge([$soa], array_slice($rrs, 0, $half));
    $second = array_merge(array_slice($rrs, $half), [$soa]);
    return [
        pack('nnnnnn', $id, 0x8480, 1, count($first), 0, 0) . $question . implode('', $first),
        pack('nnnnnn', $id, 0x8480, 0, count($second), 0, 0) . implode('', $second),
    ];
}

while (true) {
    $read = [$udp, $tcp];
    $write = $except = null;
    if (@stream_select($read, $write, $except, 1) < 1) {
        continue;
    }
    foreach ($read as $sock) {
        if ($sock === $udp) {
            $q = stream_socket_recvfrom($udp, 4096, 0, $peer);
            $resp = answer((string) $q, $zone, $types, $typeNames, $log, false);
            if (is_string($resp)) {
                stream_socket_sendto($udp, $resp, 0, $peer);
            }
        } else {
            $conn = @stream_socket_accept($tcp, 1);
            if ($conn === false) {
                continue;
            }
            stream_set_timeout($conn, 2);
            $lenBytes = (string) fread($conn, 2);
            if (strlen($lenBytes) === 2) {
                $q = (string) fread($conn, unpack('n', $lenBytes)[1]);
                $resp = answer($q, $zone, $types, $typeNames, $log, true);
                foreach ($resp === null ? [] : (array) $resp as $msg) {
                    fwrite($conn, pack('n', strlen($msg)) . $msg);
                }
            }
            fclose($conn);
        }
    }
}
