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
 * - SNMP (161/udp): one SNMPv2c read of the system description with the
 *   well-known default communities "public" and "private". This is trying a
 *   default credential (read only); the owner chose to include it.
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
        $res = $this->exchange($ip, $port, $req);
        if ($res === null || strlen($res) < 11 || $res[0] !== "\x03" || (ord($res[5]) & 0xF0) !== 0xD0) {
            return ['nla_required' => null];
        }
        if (strlen($res) < 19) {
            return ['nla_required' => false]; // no negotiation at all: only old RDP security, certainly no NLA
        }
        $type = ord($res[11]);
        $value = unpack('V', substr($res, 15, 4))[1];
        return match (true) {
            $type === 0x02 => ['nla_required' => false],                  // RDP_NEG_RSP: it accepted TLS without NLA
            $type === 0x03 && in_array($value, [5, 6], true) => ['nla_required' => true], // HYBRID_REQUIRED_BY_SERVER (or with Early User Auth)
            default => ['nla_required' => null],
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
            $id = random_int(1, 0x7FFFFFFF);
            $answer = $this->udp($ip, $port, self::snmpGet($community, $id));
            if ($answer === false) {
                continue; // couldn't send (e.g. no route): unknown
            }
            $checked = true;
            $out[$community] = $answer !== '' && self::snmpAnswered($answer, $id);
        }
        return $checked ? $out : null;
    }

    /** SMBv1: offer only "NT LM 0.12"; true if the server accepts it. */
    private function smb1(string $ip, int $port): ?bool
    {
        $smb = "\xffSMB" . "\x72" . "\x00\x00\x00\x00" . "\x18" . "\x01\x48" . str_repeat("\x00", 12) . "\xff\xff" . "\x00\x00" . "\x00\x00" . "\x00\x00"
            . "\x00" . pack('v', 12) . "\x02NT LM 0.12\x00";
        $res = $this->exchange($ip, $port, "\x00" . substr(pack('N', strlen($smb)), 1) . $smb);
        if ($res === null) {
            return false; // a server with SMBv1 off simply closes the connection
        }
        if (strlen($res) >= 39 && substr($res, 4, 4) === "\xffSMB" && $res[8] === "\x72") {
            $status = unpack('V', substr($res, 9, 4))[1];
            $dialect = unpack('v', substr($res, 37, 2))[1];
            return $status === 0 && $dialect !== 0xFFFF;
        }
        return substr($res, 4, 4) === "\xfeSMB" ? false : null;
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
        $res = $this->exchange($ip, $port, "\x00" . substr(pack('N', strlen($msg)), 1) . $msg);
        if ($res === null || strlen($res) < 4 + 64 + 4 || substr($res, 4, 4) !== "\xfeSMB") {
            return null;
        }
        if (unpack('V', substr($res, 12, 4))[1] !== 0) {
            return null; // the server refused these dialects: can't tell
        }
        $securityMode = unpack('v', substr($res, 4 + 64 + 2, 2))[1];
        return ($securityMode & 0x0002) === 0x0002;
    }

    /** One TCP request/answer, or null (no connection or no answer). */
    private function exchange(string $ip, int $port, string $request): ?string
    {
        try {
            [$host, $realPort] = $this->connector->endpoint($ip, $port);
        } catch (\RuntimeException) {
            return null;
        }
        $fp = @stream_socket_client('tcp://' . Connector::hostPort($host, $realPort), $errno, $errstr, self::TIMEOUT);
        if ($fp === false) {
            return null;
        }
        stream_set_timeout($fp, (int) self::TIMEOUT);
        fwrite($fp, $request);
        $data = '';
        $deadline = microtime(true) + self::TIMEOUT;
        while (strlen($data) < self::MAX_READ && microtime(true) < $deadline) {
            $chunk = fread($fp, self::MAX_READ - strlen($data));
            if ($chunk === false || $chunk === '') {
                if (feof($fp) || stream_get_meta_data($fp)['timed_out']) {
                    break;
                }
                continue;
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
        return $data === '' ? null : $data;
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
        stream_set_timeout($fp, 2);
        if (@fwrite($fp, $request) === false) {
            fclose($fp);
            return false;
        }
        $answer = (string) @fread($fp, self::MAX_READ);
        fclose($fp);
        return $answer;
    }

    /** SNMPv2c GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0). */
    public static function snmpGet(string $community, int $requestId): string
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
        return $tlv(0x30, $int(1) . $tlv(0x04, $community) . $pdu);
    }

    /** True if the answer is an SNMP GetResponse to this request without an error. */
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
        return $values[0] === $requestId && $values[1] === 0;
    }

    /** BER length octets. */
    private static function berLength(int $n): string
    {
        return $n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n));
    }
}
