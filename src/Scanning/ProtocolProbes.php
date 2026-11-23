<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

/**
 * Read-only checks of risky internal protocols, used by the on-premises agent
 * on devices inside its signed authorisation:
 *
 * - SMB (445/tcp): offers only the old SMBv1 dialect to see whether it is
 *   still enabled, then a normal SMB2 negotiation to read whether signing
 *   is REQUIRED. No session, no login.
 * - RDP (3389/tcp): asks for TLS without Network Level Authentication and
 *   reads whether the server agrees (no NLA) or insists on NLA. No login.
 * - SNMP (161/udp, listed in the signed job): one read of the system
 *   description with the well-known default communities "public" and
 *   "private" (SNMPv2c, and SNMPv1 if there was no answer). This is trying a
 *   default credential (read only); the owner chose to include it. Replies
 *   must come from the probed address (connected UDP socket).
 *
 * - NTP (123/udp, engagements only): one ordinary client time request (mode 3, what any computer sends); answered
 *   means a time service is reachable. Nothing else (no control or monitor queries).
 * - SSDP (1900/udp, engagements only): one unicast discovery request (M-SEARCH); answered means UPnP discovery is
 *   reachable (on the internet, a known amplification risk).
 *
 * Every check is one short exchange with a small timeout and a read limit.
 * Answers are untrusted binary data, only parsed at fixed offsets. "null"
 * means the check couldn't decide (no answer, unexpected reply).
 *
 * Security assumptions: the caller has checked the address against the
 * signed scope. Connections go through the Connector (mock servers in tests).
 */
final class ProtocolProbes
{
    private const TIMEOUT = 5.0;
    private const MAX_READ = 4096;

    /** Uses the connector for every connection. */
    public function __construct(private readonly Connector $connector)
    {
    }

    /**
     * SMB: is SMBv1 enabled, and is signing required?
     *
     * @return array{smb1:?bool, signing_required:?bool}
     */
    public function smb(string $ip, int $port = 445): array
    {
        return ['smb1' => $this->smb1($ip, $port), 'signing_required' => $this->smb2Signing($ip, $port)];
    }

    /**
     * RDP: is Network Level Authentication required?
     *
     * @return array{nla_required:?bool}
     */
    public function rdp(string $ip, int $port = 3389): array
    {
        // TPKT + X.224 Connection Request + RDP_NEG_REQ asking for TLS only (not CredSSP/NLA).
        $req = "\x03\x00\x00\x13" . "\x0e\xe0\x00\x00\x00\x00\x00" . "\x01\x00\x08\x00" . pack('V', 1);
        $r = $this->exchange($ip, $port, $req);
        return ['nla_required' => $r['data'] === '' ? null : self::parseRdp($r['data'])];
    }

    /**
     * Read an X.224 Connection Confirm ([MS-RDPBCGR] 2.2.1.2) answering a TLS-only request.
     * true: the server insists on NLA (failure code 5, HYBRID_REQUIRED_BY_SERVER); false: it accepted TLS without
     * NLA (RDP_NEG_RSP), refused TLS because it only does old RDP security (code 2), or sent no negotiation data at
     * all; null: anything else (truncated, other codes such as 6, which is TLS with client certificates).
     */
    public static function parseRdp(string $res): ?bool
    {
        if (strlen($res) < 11 || $res[0] !== "\x03" || (ord($res[5]) & 0xF0) !== 0xD0) {
            return null;
        }
        $total = unpack('n', substr($res, 2, 2))[1];
        if (strlen($res) < $total) {
            return null; // cut short: can't tell
        }
        $li = ord($res[4]);
        if ($li === 6) {
            return false; // a complete confirm without negotiation data: only old RDP security, certainly no NLA
        }
        if ($li < 14 || $total < 19) {
            return null;
        }
        $type = ord($res[11]);
        $value = unpack('V', substr($res, 15, 4))[1];
        return match (true) {
            $type === 0x02 => false,                  // RDP_NEG_RSP: TLS accepted without NLA
            $type === 0x03 && $value === 5 => true,   // HYBRID_REQUIRED_BY_SERVER
            $type === 0x03 && $value === 2 => false,  // SSL_NOT_ALLOWED_BY_SERVER: Standard RDP Security only
            default => null,
        };
    }

    /**
     * SNMP: does the device answer to the default communities?
     *
     * @return array{public:bool, private:bool}|null null when no answer to either could be checked.
     */
    public function snmp(string $ip, int $port = 161): ?array
    {
        $out = ['public' => false, 'private' => false];
        $checked = false;
        foreach (['public', 'private'] as $community) {
            // SNMPv2c first; old v1-only agents (printers, UPSes) ignore v2c, so v1 when there was no answer.
            foreach ([1, 0] as $version) {
                $id = random_int(1, 0x7FFFFFFF);
                $answer = $this->udp($ip, $port, self::snmpGet($community, $id, $version));
                if ($answer === false) {
                    continue 2; // couldn't send: unknown for this community
                }
                $checked = true;
                if ($answer !== '' && self::snmpAnswered($answer, $id)) {
                    $out[$community] = true;
                    break;
                }
            }
        }
        return $checked ? $out : null;
    }

    /**
     * An engagement's UDP checks of one address (each one request, read only): SNMP's default communities, NTP, SSDP.
     * Values are JSON strings (null: no answer or couldn't decide). The same shape from Sentinel and from agents.
     *
     * @return array<string,string>
     */
    public function udpChecks(string $ip): array
    {
        $snmp = $this->snmp($ip);
        return ['snmp_public' => (string) json_encode($snmp['public'] ?? null), 'snmp_private' => (string) json_encode($snmp['private'] ?? null),
                'ntp' => (string) json_encode($this->ntp($ip)), 'ssdp' => (string) json_encode($this->ssdp($ip))];
    }

    /** NTP: true if a time service answers an ordinary client request, false if not, null if it couldn't be sent. */
    public function ntp(string $ip, int $port = 123): ?bool
    {
        $answer = $this->udp($ip, $port, "\x1B" . str_repeat("\0", 47)); // LI 0, version 3, mode 3 (client)
        if ($answer === false) {
            return null;
        }
        return strlen($answer) >= 48 && (ord($answer[0]) & 0x07) === 4; // mode 4: a server's reply
    }

    /**
     * SSDP: the device's answer to one unicast M-SEARCH, or null when there was none.
     *
     * @return array{server:string}|null server: its SERVER header (untrusted, cleaned)
     */
    public function ssdp(string $ip, int $port = 1900): ?array
    {
        $answer = $this->udp($ip, $port, "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n");
        if (!is_string($answer) || !str_starts_with($answer, 'HTTP/1.1 200')) {
            return null;
        }
        $server = preg_match('/^server:\s*(.+)$/mi', $answer, $m) === 1 ? (string) preg_replace('/[^\x20-\x7E]/', '', trim($m[1])) : '';
        return ['server' => mb_substr($server, 0, 200)];
    }

    /** SMBv1: offer only "NT LM 0.12"; true if the server accepts it. */
    private function smb1(string $ip, int $port): ?bool
    {
        $smb = "\xffSMB" . "\x72" . "\x00\x00\x00\x00" . "\x18" . "\x01\x48" . str_repeat("\x00", 12) . "\xff\xff" . "\x00\x00" . "\x00\x00" . "\x00\x00"
            . "\x00" . pack('v', 12) . "\x02NT LM 0.12\x00";
        $r = $this->exchange($ip, $port, "\x00" . substr(pack('N', strlen($smb)), 1) . $smb);
        if ($r['data'] === '') {
            // Connected, then closed without a word: what a server with SMBv1 turned off does. No connection or
            // no answer at all: unknown.
            return $r['state'] === 'closed' ? false : null;
        }
        return self::parseSmb1($r['data']);
    }

    /**
     * Read an answer to the SMBv1-only negotiate ([MS-SMB] 2.2.4.5.2): true if it accepted the dialect, false if it
     * answered with SMB2 or refused every dialect, null if the answer isn't a proper negotiate response.
     */
    public static function parseSmb1(string $res): ?bool
    {
        if (strlen($res) >= 8 && substr($res, 4, 4) === "\xfeSMB") {
            return false;
        }
        if (strlen($res) < 39 || substr($res, 4, 4) !== "\xffSMB" || $res[8] !== "\x72" || (ord($res[13]) & 0x80) === 0) {
            return null; // not a negotiate response (the reply flag must be set)
        }
        $status = unpack('V', substr($res, 9, 4))[1];
        $words = ord($res[36]);
        if ($status !== 0 || $words < 1) {
            return null;
        }
        return unpack('v', substr($res, 37, 2))[1] !== 0xFFFF; // DialectIndex 0xFFFF: no dialect accepted
    }

    /** SMB2: negotiate dialects 2.0.2 to 3.0.2 and read whether signing is required. */
    private function smb2Signing(string $ip, int $port): ?bool
    {
        $dialects = [0x0202, 0x0210, 0x0300, 0x0302];
        $header = "\xfeSMB" . pack('v', 64) . pack('v', 0) . pack('V', 0) . pack('v', 0) . pack('v', 1) . pack('V', 0) . pack('V', 0) . pack('P', 0)
            . pack('V', 0) . pack('V', 0) . pack('P', 0) . str_repeat("\x00", 16);
        $body = pack('v', 36) . pack('v', count($dialects)) . pack('v', 1) . pack('v', 0) . pack('V', 0) . random_bytes(16) . pack('P', 0);
        foreach ($dialects as $d) {
            $body .= pack('v', $d);
        }
        $msg = $header . $body;
        $r = $this->exchange($ip, $port, "\x00" . substr(pack('N', strlen($msg)), 1) . $msg);
        return $r['data'] === '' ? null : self::parseSmb2($r['data']);
    }

    /**
     * Read an SMB2 NEGOTIATE response ([MS-SMB2] 2.2.4): true if signing is required, false if not, null if the
     * server refused the dialects or the answer isn't a proper negotiate response.
     */
    public static function parseSmb2(string $res): ?bool
    {
        if (strlen($res) < 4 + 64 + 4 || substr($res, 4, 4) !== "\xfeSMB") {
            return null;
        }
        if (unpack('V', substr($res, 12, 4))[1] !== 0 || unpack('v', substr($res, 16, 2))[1] !== 0 || unpack('v', substr($res, 68, 2))[1] !== 65) {
            return null; // an error, not a NEGOTIATE answer, or the wrong structure
        }
        return (unpack('v', substr($res, 70, 2))[1] & 0x0002) === 0x0002;
    }

    /**
     * One TCP request and its answer.
     *
     * @return array{data:string, state:string} state: 'answered', 'closed' (connected, then closed or reset by the
     *         peer without data), or 'failed' (no connection, or no answer in time).
     */
    private function exchange(string $ip, int $port, string $request): array
    {
        try {
            [$host, $realPort] = $this->connector->endpoint($ip, $port);
        } catch (\RuntimeException) {
            return ['data' => '', 'state' => 'failed'];
        }
        $fp = @stream_socket_client('tcp://' . Connector::hostPort($host, $realPort), $errno, $errstr, self::TIMEOUT);
        if ($fp === false) {
            return ['data' => '', 'state' => 'failed'];
        }
        stream_set_timeout($fp, (int) self::TIMEOUT);
        @fwrite($fp, $request);
        $data = '';
        $state = 'failed';
        $deadline = microtime(true) + self::TIMEOUT;
        while (strlen($data) < self::MAX_READ && microtime(true) < $deadline) {
            $chunk = @fread($fp, self::MAX_READ - strlen($data));
            if ($chunk === false || $chunk === '') {
                // Blocking socket: an empty read is the end (closed or reset) or a timeout. Never spin.
                $state = stream_get_meta_data($fp)['timed_out'] ? 'failed' : 'closed';
                break;
            }
            $data .= $chunk;
            // A complete NetBIOS/TPKT frame is enough.
            if (strlen($data) >= 4) {
                $need = $data[0] === "\x03" ? unpack('n', substr($data, 2, 2))[1] : (unpack('N', "\x00" . substr($data, 1, 3))[1] + 4);
                if (strlen($data) >= $need) {
                    break;
                }
            }
        }
        fclose($fp);
        return ['data' => $data, 'state' => $data !== '' ? 'answered' : $state];
    }

    /** One UDP request; the answer ('' if none in time), or false if it couldn't be sent. */
    private function udp(string $ip, int $port, string $request): string|false
    {
        try {
            [$host, $realPort] = $this->connector->endpoint($ip, $port);
        } catch (\RuntimeException) {
            return false;
        }
        $fp = @stream_socket_client('udp://' . Connector::hostPort($host, $realPort), $errno, $errstr, self::TIMEOUT);
        if ($fp === false) {
            return false;
        }
        stream_set_timeout($fp, 1);
        if (@fwrite($fp, $request) === false) {
            fclose($fp);
            return false;
        }
        $answer = (string) @fread($fp, self::MAX_READ);
        fclose($fp);
        return $answer;
    }

    /** SNMP GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0); version 1 = SNMPv2c, 0 = SNMPv1. */
    public static function snmpGet(string $community, int $requestId, int $version = 1): string
    {
        $tlv = static fn (int $tag, string $v): string => chr($tag) . self::berLength(strlen($v)) . $v;
        $int = static function (int $n) use ($tlv): string {
            $b = '';
            do {
                $b = chr($n & 0xFF) . $b;
                $n >>= 8;
            } while ($n > 0);
            if (ord($b[0]) & 0x80) {
                $b = "\x00" . $b;
            }
            return $tlv(0x02, $b);
        };
        $varbind = $tlv(0x30, $tlv(0x30, $tlv(0x06, "\x2b\x06\x01\x02\x01\x01\x01\x00") . "\x05\x00"));
        $pdu = $tlv(0xA0, $int($requestId) . $int(0) . $int(0) . $varbind);
        return $tlv(0x30, $int($version === 0 ? 0 : 1) . $tlv(0x04, $community) . $pdu);
    }

    /**
     * True if the answer is an SNMP GetResponse to this request. Any error status counts too (for example
     * noSuchName): agents silently drop requests with a wrong community (RFC 3416/3584), so any matching
     * response proves the community was accepted.
     */
    public static function snmpAnswered(string $answer, int $requestId): bool
    {
        // Walk the BER structure at fixed positions: SEQUENCE { version, community, GetResponse { id, error-status, ... } }.
        $pos = 0;
        $read = static function (string $s, int &$p): ?array {
            if ($p + 2 > strlen($s)) {
                return null;
            }
            $tag = ord($s[$p++]);
            $len = ord($s[$p++]);
            if ($len & 0x80) {
                $n = $len & 0x7F;
                if ($n < 1 || $n > 2 || $p + $n > strlen($s)) {
                    return null;
                }
                $len = 0;
                for ($i = 0; $i < $n; $i++) {
                    $len = ($len << 8) | ord($s[$p++]);
                }
            }
            return $p + $len <= strlen($s) ? [$tag, $len] : null;
        };
        $outer = $read($answer, $pos);
        if ($outer === null || $outer[0] !== 0x30) {
            return false;
        }
        foreach ([0x02, 0x04] as $want) { // version, community
            $t = $read($answer, $pos);
            if ($t === null || $t[0] !== $want) {
                return false;
            }
            $pos += $t[1];
        }
        $pdu = $read($answer, $pos);
        if ($pdu === null || $pdu[0] !== 0xA2) {
            return false;
        }
        $values = [];
        foreach ([0, 1] as $_) { // request-id, error-status
            $t = $read($answer, $pos);
            if ($t === null || $t[0] !== 0x02 || $t[1] < 1 || $t[1] > 5) {
                return false;
            }
            $v = 0;
            for ($i = 0; $i < $t[1]; $i++) {
                $v = ($v << 8) | ord($answer[$pos++]);
            }
            $values[] = $v;
        }
        return $values[0] === $requestId;
    }

    /** BER length octets. */
    private static function berLength(int $n): string
    {
        return $n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n));
    }
}
