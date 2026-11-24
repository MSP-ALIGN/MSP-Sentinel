<?php

declare(strict_types=1);

/**
 * Mock SMB, RDP and SNMP servers for the risky-protocol tests (127.0.0.1 only). They answer the agent's read-only
 * probes like a real server would, configured per instance. No real host is ever contacted.
 *
 * Usage: proto_server.php <port> smb <smb1:on|off> <signing:required|optional>
 *        proto_server.php <port> rdp <nla:required|off>
 *        proto_server.php <port> snmp <communities, comma-separated>   (UDP)
 */

[$self, $port, $mode] = $argv + [null, '0', ''];
$a = $argv[3] ?? '';
$b = $argv[4] ?? '';

if ($mode === 'snmp') {
    $sock = stream_socket_server("udp://127.0.0.1:{$port}", $errno, $errstr, STREAM_SERVER_BIND);
    $communities = array_filter(explode(',', $a));
    while (true) {
        $pkt = stream_socket_recvfrom($sock, 2048, 0, $peer);
        if ($pkt === false || $pkt === '') {
            continue;
        }
        // Parse just enough: SEQUENCE { INTEGER version, OCTET STRING community, A0 { INTEGER id ... } }.
        $p = 2;
        $p += 2 + ord($pkt[$p + 1]);                 // version
        $clen = ord($pkt[$p + 1]);
        $community = substr($pkt, $p + 2, $clen);
        $p += 2 + $clen;
        $p += 2;                                     // A0 tag + length
        $idLen = ord($pkt[$p + 1]);
        $id = substr($pkt, $p + 2, $idLen);
        if (!in_array($community, $communities, true)) {
            continue;                                // wrong community: real agents stay silent
        }
        $descr = 'Example switch';
        $varbind = "\x30" . chr(12 + strlen($descr)) . "\x30" . chr(10 + strlen($descr)) . "\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x04" . chr(strlen($descr)) . $descr;
        $pdu = "\x02" . chr($idLen) . $id . "\x02\x01\x00\x02\x01\x00" . $varbind;
        $msg = "\x02\x01\x01\x04" . chr($clen) . $community . "\xa2" . chr(strlen($pdu)) . $pdu;
        stream_socket_sendto($sock, "\x30" . chr(strlen($msg)) . $msg, 0, $peer);
    }
}

$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
while (true) {
    $conn = @stream_socket_accept($server, -1);
    if ($conn === false) {
        continue;
    }
    stream_set_timeout($conn, 5);
    $req = (string) fread($conn, 4096);
    if ($mode === 'rdp') {
        // X.224 Connection Confirm with RDP_NEG_RSP (TLS accepted: no NLA) or RDP_NEG_FAILURE (HYBRID_REQUIRED_BY_SERVER).
        $neg = $a === 'required' ? "\x03\x00\x08\x00" . pack('V', 5) : "\x02\x00\x08\x00" . pack('V', 1);
        fwrite($conn, "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00" . $neg);
    } elseif ($mode === 'smb' && substr($req, 4, 4) === "\xffSMB") {
        if ($a === 'on') {
            // SMB1 negotiate response accepting dialect 0 (NT LM 0.12).
            $hdr = "\xffSMB\x72" . "\x00\x00\x00\x00" . "\x98" . "\x01\x48" . str_repeat("\x00", 12) . "\xff\xff\x00\x00\x00\x00\x00\x00";
            $body = "\x11" . "\x00\x00" . str_repeat("\x00", 32) . "\x00\x00";
            $msg = $hdr . $body;
            fwrite($conn, "\x00" . substr(pack('N', strlen($msg)), 1) . $msg);
        }
        // SMBv1 off: close without answering, like a modern Windows server.
    } elseif ($mode === 'smb' && substr($req, 4, 4) === "\xfeSMB") {
        $hdr = "\xfeSMB" . pack('v', 64) . pack('v', 0) . pack('V', 0) . pack('v', 0) . pack('v', 1) . pack('V', 1) . pack('V', 0) . pack('P', 0)
            . pack('V', 0) . pack('V', 0) . pack('P', 0) . str_repeat("\x00", 16);
        $security = $b === 'required' ? 0x0003 : 0x0001;
        $body = pack('v', 65) . pack('v', $security) . pack('v', 0x0302) . pack('v', 0) . random_bytes(16) . pack('V', 0) . pack('V', 65536) . pack('V', 65536) . pack('V', 65536)
            . pack('P', 0) . pack('P', 0) . pack('v', 128) . pack('v', 0) . pack('V', 0);
        $msg = $hdr . $body;
        fwrite($conn, "\x00" . substr(pack('N', strlen($msg)), 1) . $msg);
    }
    fclose($conn);
}
