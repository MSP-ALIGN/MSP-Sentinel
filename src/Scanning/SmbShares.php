<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

/**
 * Safe SMB share check for pen-test engagements (1.30, part of the 'anon_access' test): which file shares a server
 * hands out, and which can be read, WITHOUT ANY ACCOUNT.
 *
 * What it does (SMB2/3, dialects 2.0.2 to 3.0.2), on one host:
 * 1. An ANONYMOUS session (NTLM with no username, no password, no domain): no account is ever named, so nothing can be
 *    locked. Refused: stop there.
 * 2. The share list: IPC$, the "srvsvc" pipe, one NetrShareEnum (level 1: names, types, remarks).
 * 3. For each disk share (at most 30): open it, open its TOP folder for listing only (read access, no write or
 *    delete rights requested), count the entries (no names are kept), close. Never opens a file, never enters a
 *    subfolder, never writes.
 * Then log off. nmap's own share script is not used: it writes and deletes a test file in every share.
 *
 * Evidence: share names and types, readable yes/no, the number of items in the top folder. No file or folder names.
 *
 * Untrusted: everything the server sends (parsed at fixed offsets with bounds checks, every read capped at 1 MB and
 * a 5-second timeout, the whole host capped at 60 seconds, NDR counts capped). A hostile server can't make it loop.
 * Security assumptions: the caller checked the address against the engagement's targets, exclusions and the live
 * authorisation right before calling, and passes a stop callback (checked between steps). Connections go through
 * the Connector (mock server in tests).
 */
final class SmbShares
{
    private const TIMEOUT = 5.0;
    private const HOST_BUDGET = 60.0;
    private const MAX_FRAME = 1_048_576;
    private const MAX_SHARES = 100;
    private const MAX_TESTED = 30;
    private const MAX_COUNT = 100_000;

    private const STATUS_SUCCESS = 0;
    private const STATUS_PENDING = 0x00000103;
    private const STATUS_MORE_PROCESSING = 0xC0000016;
    private const STATUS_NO_MORE_FILES = 0x80000006;
    private const STATUS_BUFFER_OVERFLOW = 0x80000005;

    /** @var resource|null */
    private $sock = null;
    private int $messageId = 0;
    private int $sessionId = 0;
    private float $deadline = 0.0;

    public function __construct(private readonly Connector $connector)
    {
    }

    /**
     * @param callable():bool $shouldStop true when the engagement must stop (checked between steps)
     * @return array{session:string, listed:bool, shares:list<array{name:string, type:string, readable:?bool, items:?int, complete:bool}>}
     *         items: entries counted (null: opened, but not counted); complete: the count reached the end (else "at
     *         least items"); session: 'anonymous' | 'guest' (the server treated the anonymous session as its guest) | 'refused' |
     *         'error'; listed: the share list was handed out; readable null: not tested (not a disk share, or the cap)
     */
    public function check(string $ip, callable $shouldStop, int $port = 445): array
    {
        $out = ['session' => 'error', 'listed' => false, 'shares' => []];
        $this->deadline = microtime(true) + self::HOST_BUDGET;
        $this->messageId = 0;
        $this->sessionId = 0;
        try {
            [$host, $real] = $this->connector->endpoint($ip, $port);
            $sock = @stream_socket_client('tcp://' . Connector::hostPort($host, $real), $errno, $errstr, self::TIMEOUT);
            if ($sock === false) {
                return $out;
            }
            stream_set_timeout($sock, (int) self::TIMEOUT);
            $this->sock = $sock;
            if (!$this->negotiate()) {
                return $out;
            }
            $session = $this->anonymousSession();
            $out['session'] = $session;
            if (!in_array($session, ['anonymous', 'guest'], true) || $shouldStop()) {
                return $out;
            }
            $list = $this->shareList($ip);
            if ($list === null) {
                return $out;
            }
            $out['listed'] = $list !== []; // an empty list proves nothing
            $tested = 0;
            foreach (array_slice($list, 0, self::MAX_SHARES) as $s) {
                $entry = ['name' => $s['name'], 'type' => $s['type'], 'readable' => null, 'items' => null, 'complete' => false];
                if ($s['type'] === 'disk' && $tested < self::MAX_TESTED && !$shouldStop() && microtime(true) < $this->deadline) {
                    $tested++;
                    $c = $this->countTopFolder($ip, $s['path']);
                    $entry['readable'] = $c !== null;
                    $entry['items'] = $c['items'] ?? null;
                    $entry['complete'] = $c['complete'] ?? false;
                }
                $out['shares'][] = $entry;
            }
            return $out;
        } catch (\RuntimeException) {
            return $out; // no usable answer: whatever was learnt so far stands
        } finally {
            if ($this->sock !== null) {
                if ($this->sessionId !== 0) {
                    try {
                        $this->send(2, pack('vv', 4, 0)); // LOGOFF, no answer awaited
                    } catch (\RuntimeException) {
                    }
                }
                @fclose($this->sock);
                $this->sock = null;
            }
        }
    }

    /**
     * The Windows version and names a server gives in its NTLM challenge (1.38), without logging in: SMB2 negotiate,
     * then a session setup carrying an NTLM NEGOTIATE; the server's CHALLENGE holds its version (major.minor.build) and
     * its NetBIOS and DNS names. The handshake stops there (no AUTHENTICATE is sent) and the connection is closed: read
     * only, nothing to log in with, the same information nmap's ntlm-info reads. Null when it doesn't answer like a
     * Windows/Samba SMB server.
     *
     * Untrusted: everything in the answer (lengths and offsets are bounds-checked, names cleaned and shortened).
     *
     * @return array{major:int, minor:int, build:int, netbios_name:string, netbios_domain:string, dns_name:string, dns_domain:string}|null
     */
    public function ntlmInfo(string $ip, int $port = 445): ?array
    {
        $this->deadline = microtime(true) + 20;
        $this->messageId = 0;
        $this->sessionId = 0;
        try {
            [$host, $real] = $this->connector->endpoint($ip, $port);
            $sock = @stream_socket_client('tcp://' . Connector::hostPort($host, $real), $errno, $errstr, self::TIMEOUT);
            if ($sock === false) {
                return null;
            }
            stream_set_timeout($sock, (int) self::TIMEOUT);
            $this->sock = $sock;
            if (!$this->negotiate()) {
                return null;
            }
            // NEGOTIATE asking for the version and target info (NTLMSSP_NEGOTIATE_VERSION, _TARGET_INFO).
            $flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000 | 0x00080000 | 0x00800000 | 0x02000000 | 0x20000000 | 0x80000000;
            $ntlmNegotiate = "NTLMSSP\0" . pack('VV', 1, $flags) . str_repeat("\0", 16);
            $mech = self::der(0x06, "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a");
            $init = self::der(0x60, self::der(0x06, "\x2b\x06\x01\x05\x05\x02")
                . self::der(0xa0, self::der(0x30, self::der(0xa0, self::der(0x30, $mech)) . self::der(0xa2, self::der(0x04, $ntlmNegotiate)))));
            $r = $this->call(1, pack('vCCVVvvP', 25, 0, 1, 0, 0, 88, strlen($init), 0) . $init);
            $this->sessionId = 0; // never logged in: nothing to log off
            $p = strpos($r['raw'], "NTLMSSP\0\x02\0\0\0");
            return $p === false ? null : self::parseChallenge(substr($r['raw'], $p));
        } catch (\RuntimeException) {
            return null;
        } finally {
            if ($this->sock !== null) {
                @fclose($this->sock);
                $this->sock = null;
            }
        }
    }

    /**
     * An NTLM CHALLENGE message's version and names ([MS-NLMP] 2.2.1.2, 2.2.2.1); null when it is malformed.
     *
     * @return array{major:int, minor:int, build:int, netbios_name:string, netbios_domain:string, dns_name:string, dns_domain:string}|null
     */
    public static function parseChallenge(string $c): ?array
    {
        if (strlen($c) < 48 || substr($c, 0, 12) !== "NTLMSSP\0\x02\0\0\0") {
            return null;
        }
        $flags = unpack('V', substr($c, 20, 4))[1];
        $out = ['major' => 0, 'minor' => 0, 'build' => 0, 'netbios_name' => '', 'netbios_domain' => '', 'dns_name' => '', 'dns_domain' => ''];
        if (($flags & 0x02000000) !== 0 && strlen($c) >= 56) {
            $v = unpack('Cmajor/Cminor/vbuild', substr($c, 48, 4));
            $out['major'] = $v['major'];
            $out['minor'] = $v['minor'];
            $out['build'] = $v['build'];
        }
        $ti = unpack('vlen/vmax/Voff', substr($c, 40, 8));
        if ($ti['len'] > 0 && $ti['off'] >= 48 && $ti['off'] + $ti['len'] <= strlen($c) && $ti['len'] <= 4096) {
            $info = substr($c, $ti['off'], $ti['len']);
            $o = 0;
            $names = [1 => 'netbios_name', 2 => 'netbios_domain', 3 => 'dns_name', 4 => 'dns_domain'];
            while ($o + 4 <= strlen($info)) {
                ['id' => $id, 'len' => $len] = unpack('vid/vlen', substr($info, $o, 4));
                $o += 4;
                if ($id === 0 || $o + $len > strlen($info)) {
                    break; // MsvAvEOL, or a pair running past the end
                }
                if (isset($names[$id])) {
                    $text = (string) @mb_convert_encoding(substr($info, $o, $len), 'UTF-8', 'UTF-16LE');
                    $out[$names[$id]] = mb_substr(trim((string) preg_replace('/[^\p{L}\p{N}._-]+/u', '', $text)), 0, 64);
                }
                $o += $len;
            }
        }
        return $out['major'] === 0 && $out['netbios_name'] === '' && $out['dns_name'] === '' ? null : $out;
    }

    // ------------------------------------------------------------------ SMB2 framing

    /** Send one SMB2 request; returns its message id. */
    private function send(int $command, string $body, int $treeId = 0): int
    {
        $id = $this->messageId++;
        $header = "\xfeSMB" . pack('vvVvvVVPVVP', 64, 1, 0, $command, 31, 0, 0, $id, 0xFEFF, $treeId, $this->sessionId) . str_repeat("\0", 16);
        $msg = $header . $body;
        if (@fwrite($this->sock, "\0" . substr(pack('N', strlen($msg)), 1) . $msg) === false) {
            throw new \RuntimeException('write failed');
        }
        return $id;
    }

    /** Exactly $n bytes or an exception (deadline, end of stream). */
    private function readN(int $n): string
    {
        $buf = '';
        while (strlen($buf) < $n) {
            if (microtime(true) > $this->deadline || feof($this->sock)) {
                throw new \RuntimeException('short read');
            }
            $chunk = @fread($this->sock, min(65536, $n - strlen($buf)));
            if ($chunk === false || $chunk === '') {
                throw new \RuntimeException('short read');
            }
            $buf .= $chunk;
        }
        return $buf;
    }

    /**
     * The answer to message $id (interim "pending" answers are skipped).
     *
     * @return array{status:int, tree:int, session:int, body:string, raw:string} raw: the whole SMB2 message (offsets
     *         in answers count from its start)
     */
    private function receive(int $id): array
    {
        for ($i = 0; $i < 20; $i++) {
            $nb = $this->readN(4);
            $len = unpack('N', "\0" . substr($nb, 1, 3))[1];
            if ($nb[0] !== "\0" || $len < 64 || $len > self::MAX_FRAME) {
                throw new \RuntimeException('bad frame');
            }
            $raw = $this->readN($len);
            if (substr($raw, 0, 4) !== "\xfeSMB") {
                throw new \RuntimeException('not SMB2');
            }
            $status = unpack('V', substr($raw, 8, 4))[1];
            $flags = unpack('V', substr($raw, 16, 4))[1];
            $mid = unpack('P', substr($raw, 24, 8))[1];
            if ($mid === -1) {
                continue; // an unsolicited notice (oplock/lease break, MessageId 0xFFFFFFFFFFFFFFFF): not our answer
            }
            if (($flags & 0x1) === 0 || $mid !== $id) {
                throw new \RuntimeException('unexpected message');
            }
            if ($status === self::STATUS_PENDING && ($flags & 0x2) !== 0) {
                continue; // interim answer: the real one follows
            }
            return ['status' => $status, 'tree' => unpack('V', substr($raw, 36, 4))[1], 'session' => unpack('P', substr($raw, 40, 8))[1],
                'body' => substr($raw, 64), 'raw' => $raw];
        }
        throw new \RuntimeException('too many interim answers');
    }

    private function call(int $command, string $body, int $treeId = 0): array
    {
        return $this->receive($this->send($command, $body, $treeId));
    }

    // ------------------------------------------------------------------ steps

    private function negotiate(): bool
    {
        $dialects = [0x0202, 0x0210, 0x0300, 0x0302];
        $body = pack('vvvvV', 36, count($dialects), 1, 0, 0) . random_bytes(16) . pack('P', 0);
        foreach ($dialects as $d) {
            $body .= pack('v', $d);
        }
        $r = $this->call(0, $body);
        return $r['status'] === self::STATUS_SUCCESS && strlen($r['body']) >= 2 && unpack('v', substr($r['body'], 0, 2))[1] === 65;
    }

    /** NTLM anonymous logon inside SPNEGO. @return string 'anonymous' | 'guest' | 'refused' | 'error' */
    private function anonymousSession(): string
    {
        $flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00000800 | 0x00008000 | 0x00080000 | 0x20000000 | 0x80000000;
        $ntlmNegotiate = "NTLMSSP\0" . pack('VV', 1, $flags) . str_repeat("\0", 16);
        $mech = self::der(0x06, "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"); // NTLMSSP
        $init = self::der(0x60, self::der(0x06, "\x2b\x06\x01\x05\x05\x02")
            . self::der(0xa0, self::der(0x30, self::der(0xa0, self::der(0x30, $mech)) . self::der(0xa2, self::der(0x04, $ntlmNegotiate)))));
        $r = $this->call(1, pack('vCCVVvvP', 25, 0, 1, 0, 0, 88, strlen($init), 0) . $init);
        if ($r['status'] !== self::STATUS_MORE_PROCESSING || strpos($r['raw'], "NTLMSSP\0\x02\0\0\0") === false) {
            return in_array($r['status'], [0xC0000022, 0xC000006D, 0xC0000072, 0xC000015B], true) ? 'refused' : 'error';
        }
        $this->sessionId = $r['session'];
        // AUTHENTICATE, anonymous: LM response one zero byte, everything else empty ([MS-NLMP] 3.2.5.1.2).
        $field = static fn (int $len, int $offset): string => pack('vvV', $len, $len, $offset);
        $auth = "NTLMSSP\0" . pack('V', 3) . $field(1, 64) . $field(0, 65) . $field(0, 65) . $field(0, 65) . $field(0, 65) . $field(0, 65)
            . pack('V', $flags) . "\0";
        $resp = self::der(0xa1, self::der(0x30, self::der(0xa2, self::der(0x04, $auth))));
        $r = $this->call(1, pack('vCCVVvvP', 25, 0, 1, 0, 0, 88, strlen($resp), 0) . $resp);
        if ($r['status'] !== self::STATUS_SUCCESS) {
            $this->sessionId = 0;
            return in_array($r['status'], [0xC0000022, 0xC000006D, 0xC0000072, 0xC000015B], true) ? 'refused' : 'error';
        }
        $sessionFlags = strlen($r['body']) >= 4 ? unpack('v', substr($r['body'], 2, 2))[1] : 0;
        // Samba sets both IS_GUEST and IS_NULL for anonymous logons: IS_NULL decides.
        return ($sessionFlags & 0x2) !== 0 || ($sessionFlags & 0x1) === 0 ? 'anonymous' : 'guest';
    }

    /** Tree connect; the tree id or null when refused. */
    private function treeConnect(string $ip, string $share): ?int
    {
        $path = self::utf16('\\\\' . $ip . '\\' . $share);
        $r = $this->call(3, pack('vvvv', 9, 0, 72, strlen($path)) . $path);
        return $r['status'] === self::STATUS_SUCCESS ? $r['tree'] : null;
    }

    private function treeDisconnect(int $tree): void
    {
        try {
            $this->call(4, pack('vv', 4, 0), $tree);
        } catch (\RuntimeException) {
        }
    }

    /** CREATE (open existing only); the 16-byte file id, or null. */
    private function open(int $tree, string $name, int $access, int $options): ?string
    {
        $n = self::utf16($name);
        $body = pack('vCCVPPVVVVVvvVV', 57, 0, 0, 2, 0, 0, $access, 0, 7, 1, $options, 120, strlen($n), 0, 0) . ($n === '' ? "\0" : $n);
        $r = $this->call(5, $body, $tree);
        return $r['status'] === self::STATUS_SUCCESS && strlen($r['body']) >= 80 ? substr($r['body'], 64, 16) : null;
    }

    private function close(int $tree, string $fileId): void
    {
        try {
            $this->call(6, pack('vvV', 24, 0, 0) . $fileId, $tree);
        } catch (\RuntimeException) {
        }
    }

    /**
     * The share list through IPC$ / srvsvc (NetrShareEnum, level 1), or null when it is refused.
     *
     * @return list<array{name:string, type:string}>|null
     */
    private function shareList(string $ip): ?array
    {
        $tree = $this->treeConnect($ip, 'IPC$');
        if ($tree === null) {
            return null;
        }
        try {
            $pipe = $this->open($tree, 'srvsvc', 0x0012019F, 0);
            if ($pipe === null) {
                return null;
            }
            try {
                // DCE/RPC bind: srvsvc 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0, NDR transfer syntax.
                $srvsvc = "\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88" . pack('vv', 3, 0);
                $ndr = "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60" . pack('V', 2);
                $bind = pack('vvVV', 4280, 4280, 0, 1) . pack('vCC', 0, 1, 0) . $srvsvc . $ndr;
                $ack = $this->rpc($tree, $pipe, 11, 1, $bind);
                if ($ack === null || $ack['type'] !== 12) {
                    return null;
                }
                // NetrShareEnum (opnum 15): no server name, level 1, empty container, any length, no resume handle.
                $stub = pack('VVVVVVVV', 0, 1, 1, 0x00020004, 0, 0, 0xFFFFFFFF, 0);
                $resp = $this->rpc($tree, $pipe, 0, 2, pack('Vvv', strlen($stub), 0, 15) . $stub);
                if ($resp === null || $resp['type'] !== 2) {
                    return null;
                }
                return self::parseShareEnum($resp['stub']);
            } finally {
                $this->close($tree, $pipe);
            }
        } finally {
            $this->treeDisconnect($tree);
        }
    }

    /**
     * One DCE/RPC exchange on the pipe (WRITE, then READ until the last fragment).
     *
     * @return array{type:int, stub:string}|null type: the answer's packet type; stub: the joined response stubs
     */
    private function rpc(int $tree, string $pipe, int $ptype, int $callId, string $payload): ?array
    {
        $pdu = pack('CCCCVvvV', 5, 0, $ptype, 3, 0x10, 16 + strlen($payload), 0, $callId) . $payload;
        $w = $this->call(9, pack('vvVPa16VVvvV', 49, 112, strlen($pdu), 0, $pipe, 0, 0, 0, 0, 0) . $pdu, $tree);
        if ($w['status'] !== self::STATUS_SUCCESS) {
            return null;
        }
        $buf = '';
        $stub = '';
        $type = -1;
        for ($reads = 0; $reads < 64; $reads++) {
            $r = $this->call(8, pack('vCCVPa16VVVvvC', 49, 0x50, 0, 65536, 0, $pipe, 0, 0, 0, 0, 0, 0), $tree);
            if (!in_array($r['status'], [self::STATUS_SUCCESS, self::STATUS_BUFFER_OVERFLOW], true) || strlen($r['body']) < 16) {
                return null;
            }
            $off = ord($r['body'][2]);
            $len = unpack('V', substr($r['body'], 4, 4))[1];
            if ($off < 64 || $off + $len > strlen($r['raw'])) {
                return null;
            }
            $buf .= substr($r['raw'], $off, $len);
            if (strlen($buf) > self::MAX_FRAME) {
                return null;
            }
            // Whole fragments in the buffer: take them.
            while (strlen($buf) >= 16) {
                $fragLen = unpack('v', substr($buf, 8, 2))[1];
                if ($fragLen < 16 || ord($buf[0]) !== 5) {
                    return null;
                }
                if (strlen($buf) < $fragLen) {
                    break;
                }
                $frag = substr($buf, 0, $fragLen);
                $buf = substr($buf, $fragLen);
                $type = ord($frag[2]);
                $last = (ord($frag[3]) & 0x02) !== 0;
                if ($type === 2) {
                    $authLen = unpack('v', substr($frag, 10, 2))[1];
                    $stub .= substr($frag, 24, $fragLen - 24 - ($authLen > 0 ? $authLen + 8 : 0));
                } elseif ($type !== 12) {
                    return ['type' => $type, 'stub' => '']; // fault or bind refused
                }
                if ($last) {
                    return ['type' => $type, 'stub' => $stub];
                }
            }
        }
        return null;
    }

    /**
     * Read NetrShareEnum's level-1 answer (NDR): share names and types. Counts capped; bounds checked throughout.
     *
     * @return list<array{name:string, path:string, type:string}>|null null: malformed, or the server refused (non-zero
     *         result code)
     */
    public static function parseShareEnum(string $s): ?array
    {
        $o = 0;
        $u32 = static function () use ($s, &$o): int {
            if ($o + 4 > strlen($s)) {
                throw new \RuntimeException('short NDR');
            }
            $v = unpack('V', substr($s, $o, 4))[1];
            $o += 4;
            return $v;
        };
        $str = static function () use ($s, &$o, $u32): string {
            $u32(); // max count
            $u32(); // offset
            $actual = $u32();
            if ($actual > 1024 || $o + $actual * 2 > strlen($s)) {
                throw new \RuntimeException('bad NDR string');
            }
            $raw = substr($s, $o, $actual * 2);
            $o += $actual * 2;
            $o += (4 - ($o % 4)) % 4;
            $text = (string) mb_convert_encoding($raw, 'UTF-8', 'UTF-16LE');
            return rtrim($text, "\0");
        };
        try {
            if ($u32() !== 1 || $u32() !== 1) {
                return null; // not level 1
            }
            if ($u32() === 0) {
                return null; // no container
            }
            $entries = $u32();
            $buffer = $u32();
            if ($entries > 10000 || ($buffer === 0 && $entries !== 0)) {
                return null;
            }
            $items = [];
            if ($buffer !== 0) {
                $max = $u32();
                if ($max < $entries) {
                    return null;
                }
                for ($i = 0; $i < $entries; $i++) {
                    $items[] = ['name' => $u32(), 'type' => $u32(), 'remark' => $u32()];
                }
            }
            $out = [];
            foreach ($items as $it) {
                $name = $it['name'] !== 0 ? $str() : '';
                if ($it['remark'] !== 0) {
                    $str();
                }
                $full = (string) preg_replace('/[\x00-\x1F\x7F\\\\\/]/u', '', $name);
                $base = $it['type'] & 0x0FFFFFFF;
                $type = match ($base) {
                    0 => 'disk',
                    1 => 'printer',
                    3 => 'ipc',
                    default => 'other',
                };
                if ($full !== '' && count($out) < self::MAX_SHARES) {
                    // 'name' for the evidence (80 characters); 'path' (the whole name) only for opening the share.
                    $out[] = ['name' => mb_substr($full, 0, 80), 'path' => $full, 'type' => $type];
                }
            }
            // After the strings: TotalEntries, the resume handle (a pointer) and the call's own result. A server that
            // refuses the list (e.g. Samba's "restrict anonymous = 1") answers an empty container with an error code.
            $u32();
            if ($u32() !== 0) {
                $u32();
            }
            return $u32() === 0 ? $out : null;
        } catch (\RuntimeException) {
            return null;
        }
    }

    /**
     * Open the share and count the entries of its top folder (read only); null when it can't be opened for listing.
     * Opening the folder for listing already proves it is readable; the count may be partial.
     *
     * @return array{items:?int, complete:bool}|null items null: opened, but no listing answer came back in time
     */
    private function countTopFolder(string $ip, string $share): ?array
    {
        $tree = $this->treeConnect($ip, $share);
        if ($tree === null) {
            return null;
        }
        try {
            // FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE; FILE_DIRECTORY_FILE. No write or delete rights.
            $dir = $this->open($tree, '', 0x00100081, 0x00000001);
            if ($dir === null) {
                return null;
            }
            try {
                $count = 0;
                $answered = 0;
                $pattern = self::utf16('*');
                for ($q = 0; $q < 50 && microtime(true) < $this->deadline; $q++) {
                    $body = pack('vCCVa16vvV', 33, 0x0C, $q === 0 ? 0x01 : 0x00, 0, $dir, 96, strlen($pattern), 65536) . $pattern;
                    try {
                        $r = $this->call(0x0E, $body, $tree);
                    } catch (\RuntimeException) {
                        break; // the budget ran out mid-answer: the count so far, marked incomplete
                    }
                    // The end of the listing; an empty drive root (no "." or "..") says "no such file" at once.
                    if ($r['status'] === self::STATUS_NO_MORE_FILES || ($q === 0 && $r['status'] === 0xC000000F)) {
                        return ['items' => $count, 'complete' => true];
                    }
                    if ($r['status'] !== self::STATUS_SUCCESS || strlen($r['body']) < 8) {
                        break;
                    }
                    $off = unpack('v', substr($r['body'], 2, 2))[1];
                    $len = unpack('V', substr($r['body'], 4, 4))[1];
                    if ($off < 64 || $off + $len > strlen($r['raw'])) {
                        break;
                    }
                    $answered++;
                    $data = substr($r['raw'], $off, $len);
                    // FileNamesInformation: NextEntryOffset, FileIndex, FileNameLength, FileName. Names are only
                    // compared with "." and "..", never kept.
                    $p = 0;
                    for ($n = 0; $n < 10000 && $p + 12 <= strlen($data); $n++) {
                        $next = unpack('V', substr($data, $p, 4))[1];
                        $nameLen = unpack('V', substr($data, $p + 8, 4))[1];
                        $name = substr($data, $p + 12, min($nameLen, 8));
                        if ($name !== ".\0" && $name !== ".\0.\0") {
                            $count++;
                        }
                        if ($next === 0 || $next < 12) {
                            break;
                        }
                        $p += $next;
                    }
                    if ($count >= self::MAX_COUNT) {
                        break;
                    }
                }
                return ['items' => $answered > 0 ? min($count, self::MAX_COUNT) : null, 'complete' => false];
            } finally {
                $this->close($tree, $dir);
            }
        } finally {
            $this->treeDisconnect($tree);
        }
    }

    /**
     * Results received from an agent (untrusted), reduced to check()'s shape.
     *
     * @param array<mixed> $raw
     * @return array{session:string, listed:bool, shares:list<array{name:string, type:string, readable:?bool, items:?int, complete:bool}>}
     */
    public static function cleanResults(array $raw): array
    {
        $session = in_array($raw['session'] ?? null, ['anonymous', 'guest', 'refused', 'error'], true) ? (string) $raw['session'] : 'error';
        $shares = [];
        foreach (array_slice(array_values(array_filter((array) ($raw['shares'] ?? []), 'is_array')), 0, self::MAX_SHARES) as $s) {
            $name = is_string($s['name'] ?? null) ? mb_substr((string) preg_replace('/[\x00-\x1F\x7F\\\\\/]/u', '', mb_convert_encoding($s['name'], 'UTF-8', 'UTF-8')), 0, 80) : '';
            if ($name === '') {
                continue;
            }
            $readable = is_bool($s['readable'] ?? null) ? $s['readable'] : null;
            $items = $readable === true && is_int($s['items'] ?? null) ? max(0, min(self::MAX_COUNT, $s['items'])) : null;
            $shares[] = ['name' => $name, 'type' => in_array($s['type'] ?? null, ['disk', 'printer', 'ipc', 'other'], true) ? (string) $s['type'] : 'other',
                'readable' => $readable, 'items' => $items, 'complete' => $items !== null && ($s['complete'] ?? false) === true];
        }
        return ['session' => $session, 'listed' => ($raw['listed'] ?? false) === true && $shares !== [], 'shares' => $shares];
    }

    // ------------------------------------------------------------------ helpers

    private static function utf16(string $s): string
    {
        return (string) mb_convert_encoding($s, 'UTF-16LE', 'UTF-8');
    }

    /** One DER element (tag, definite length). */
    private static function der(int $tag, string $content): string
    {
        $n = strlen($content);
        $len = $n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n));
        return chr($tag) . $len . $content;
    }
}
