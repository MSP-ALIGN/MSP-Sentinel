<?php

declare(strict_types=1);

/**
 * Fake SMB2 file server for the safe share check tests (127.0.0.1 only; never used in production).
 *
 * Usage: php tests/mocks/smb_server.php <port> <mode> <request-log>
 *
 * Modes: open (anonymous sessions allowed; shares Public (3 items), Scans (250 items, answered in two parts), Finance
 * and C$ (refused), IPC$, Printer), restricted (anonymous session allowed, IPC$ refused: no share list), noanon
 * (anonymous logon refused), enumdenied (the share list call answers an empty list with "access denied", as Samba's
 * "restrict anonymous = 1" does).
 * Every request is logged as one line ("<command> <details>") so tests can prove nothing was written or opened
 * beyond the top folders. The share list answer is split into two DCE/RPC fragments.
 */

if (PHP_SAPI !== 'cli' || $argc < 4) {
    exit(2);
}
[, $port, $mode, $log] = $argv;
$srv = stream_socket_server('tcp://127.0.0.1:' . (int) $port, $errno, $errstr);
if ($srv === false) {
    fwrite(STDERR, "smb mock: cannot bind {$port}: {$errstr}\n");
    exit(1);
}
$note = static function (string $line) use ($log): void {
    file_put_contents($log, $line . "\n", FILE_APPEND);
};
$utf16 = static fn (string $s): string => (string) mb_convert_encoding($s, 'UTF-16LE', 'UTF-8');
$from16 = static fn (string $s): string => (string) mb_convert_encoding($s, 'UTF-8', 'UTF-16LE');
$names = ['CREATE' => 5, 'NEGOTIATE' => 0, 'SESSION_SETUP' => 1, 'LOGOFF' => 2, 'TREE_CONNECT' => 3, 'TREE_DISCONNECT' => 4, 'CLOSE' => 6, 'READ' => 8, 'WRITE' => 9,
    'IOCTL' => 11, 'QUERY_DIRECTORY' => 14];
$cmdName = array_flip($names);
$shares = [['Public', 0, 'Shared documents'], ['Scans', 0, 'Scanner drop folder'], ['Finance', 0, ''], ['IPC$', 0x80000003, 'Remote IPC'], ['C$', 0x80000000, 'Default share'],
    ['Printer', 1, 'Office printer']];
$readable = ['Public' => 3, 'Scans' => 250];

while (true) {
    $c = @stream_socket_accept($srv, 60);
    if ($c === false) {
        continue;
    }
    stream_set_timeout($c, 5);
    $trees = [1 => 'IPC$'];
    $nextTree = 2;
    $files = [];
    $pending = '';
    $session = 0;
    while (true) {
        $nb = fread($c, 4);
        if ($nb === false || strlen($nb) !== 4) {
            break;
        }
        $len = unpack('N', "\0" . substr($nb, 1, 3))[1];
        $raw = '';
        while (strlen($raw) < $len && !feof($c)) {
            $raw .= (string) fread($c, $len - strlen($raw));
        }
        $cmd = unpack('v', substr($raw, 12, 2))[1];
        $mid = unpack('P', substr($raw, 24, 8))[1];
        $tree = unpack('V', substr($raw, 36, 4))[1];
        $body = substr($raw, 64);
        $status = 0;
        $outTree = $tree;
        $reply = static function (int $status, string $rb) use ($c, $cmd, $mid, &$outTree, &$session): void {
            $h = "\xfeSMB" . pack('vvVvvVVPVVP', 64, 0, $status, $cmd, 31, 1, 0, $mid, 0xFEFF, $outTree, $session) . str_repeat("\0", 16);
            $m = $h . $rb;
            fwrite($c, "\0" . substr(pack('N', strlen($m)), 1) . $m);
        };
        $error = static fn (int $st) => $reply($st, pack('vCCV', 9, 0, 0, 0) . "\0");
        $name = $cmdName[$cmd] ?? (string) $cmd;
        switch ($cmd) {
            case 0:
                $note('NEGOTIATE');
                $reply(0, pack('vvvv', 65, 1, 0x0302, 0) . str_repeat("\x11", 16) . pack('VVVVPPvvV', 0, 65536, 65536, 65536, 0, 0, 128, 0, 0) . "\0");
                break;
            case 1:
                $blobOff = unpack('v', substr($body, 12, 2))[1];
                $blobLen = unpack('v', substr($body, 14, 2))[1];
                $blob = substr($raw, $blobOff, $blobLen);
                $p = strpos($blob, "NTLMSSP\0");
                $type = $p === false ? 0 : unpack('V', substr($blob, $p + 8, 4))[1];
                if ($type === 1) {
                    $note('SESSION_SETUP negotiate');
                    $session = 0x5151;
                    // A Windows Server 2022 answer (1.38): version 10.0.20348 and made-up names in the target info.
                    $u16 = static fn (string $t): string => (string) mb_convert_encoding($t, 'UTF-16LE', 'UTF-8');
                    $av = '';
                    foreach ([2 => 'EXAMPLE', 1 => 'FILESRV01', 4 => 'corp.example', 3 => 'filesrv01.corp.example'] as $id => $text) {
                        $av .= pack('vv', $id, strlen($u16($text))) . $u16($text);
                    }
                    $av .= pack('vv', 0, 0);
                    $challenge = "NTLMSSP\0" . pack('V', 2) . pack('vvV', 0, 0, 56) . pack('V', 0x02888207) . random_bytes(8) . str_repeat("\0", 8)
                        . pack('vvV', strlen($av), strlen($av), 56) . pack('CCvCCCC', 10, 0, 20348, 0, 0, 0, 15) . $av;
                    $tok = "\xa1" . chr(strlen($challenge) + 6) . "\x30" . chr(strlen($challenge) + 4) . "\xa2" . chr(strlen($challenge) + 2) . "\x04" . chr(strlen($challenge)) . $challenge;
                    $reply(0xC0000016, pack('vvvv', 9, 0, 72, strlen($tok)) . $tok);
                } else {
                    $userLen = $p === false ? -1 : unpack('v', substr($blob, $p + 36, 2))[1];
                    $note('SESSION_SETUP authenticate user_length=' . $userLen);
                    if ($mode === 'noanon' || $userLen !== 0) {
                        $session = 0;
                        $error(0xC000006D);
                    } else {
                        $reply(0, pack('vvvv', 9, 0x0002, 72, 0));
                    }
                }
                break;
            case 3:
                $off = unpack('v', substr($body, 4, 2))[1];
                $plen = unpack('v', substr($body, 6, 2))[1];
                $path = $from16(substr($raw, $off, $plen));
                $share = substr($path, (int) strrpos($path, '\\') + 1);
                $note('TREE_CONNECT ' . $share);
                if ($share === 'IPC$' && $mode !== 'restricted') {
                    $outTree = 1;
                    $reply(0, pack('vCCVVV', 16, 2, 0, 0, 0, 0x001F01FF));
                } elseif (isset($readable[$share])) {
                    $outTree = $nextTree++;
                    $trees[$outTree] = $share;
                    $reply(0, pack('vCCVVV', 16, 1, 0, 0, 0, 0x00120089));
                } else {
                    $error(0xC0000022);
                }
                break;
            case 5:
                $access = unpack('V', substr($body, 24, 4))[1];
                $nOff = unpack('v', substr($body, 44, 2))[1];
                $nLen = unpack('v', substr($body, 46, 2))[1];
                $fname = $nLen > 0 ? $from16(substr($raw, $nOff, $nLen)) : '';
                $note('CREATE ' . ($trees[$tree] ?? '?') . ' "' . $fname . '" access=' . sprintf('%08x', $access));
                $fid = pack('PP', $tree, count($files) + 1);
                $files[$fid] = ['tree' => $tree, 'name' => $fname, 'pos' => 0];
                $reply(0, pack('vCCV', 89, 0, 0, 1) . str_repeat("\0", 32) . pack('PPVV', 0, 0, 0x10, 0) . $fid . pack('VV', 0, 0));
                break;
            case 9:
                $doff = unpack('v', substr($body, 2, 2))[1];
                $dlen = unpack('V', substr($body, 4, 4))[1];
                $pdu = substr($raw, $doff, $dlen);
                $ptype = ord($pdu[2]);
                $callId = unpack('V', substr($pdu, 12, 4))[1];
                $note('WRITE ' . ($trees[$tree] ?? '?') . ' rpc_type=' . $ptype . ($ptype === 0 ? ' opnum=' . unpack('v', substr($pdu, 22, 2))[1] : ''));
                $hdr = static fn (int $type, int $flags, string $payload) => pack('CCCCVvvV', 5, 0, $type, $flags, 0x10, 16 + strlen($payload), 0, $callId) . $payload;
                if ($ptype === 11) {
                    $sec = "\\PIPE\\srvsvc\0";
                    $ack = pack('vvV', 4280, 4280, 0x1234) . pack('v', strlen($sec)) . $sec;
                    $ack .= str_repeat("\0", (4 - (strlen($ack) + 16) % 4) % 4) . pack('V', 1) . pack('vv', 0, 0)
                        . "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60" . pack('V', 2);
                    $pending = $hdr(12, 3, $ack);
                } else {
                    $str = static function (string $s) use ($utf16): string {
                        $u = $utf16($s . "\0");
                        $n = intdiv(strlen($u), 2);
                        $o = pack('VVV', $n, 0, $n) . $u;
                        return $o . str_repeat("\0", (4 - strlen($o) % 4) % 4);
                    };
                    if ($mode === 'enumdenied') {
                        $pending = $hdr(2, 3, pack('VvCC', 32, 0, 0, 0) . pack('VVVVVVVV', 1, 1, 0x20000, 0, 0, 0, 0, 5));
                        $reply(0, pack('vvVVvv', 17, 0, $dlen, 0, 0, 0));
                        break;
                    }
                    $n = count($shares);
                    $stub = pack('VVVVVV', 1, 1, 0x20000, $n, 0x20004, $n);
                    foreach ($shares as $i => [$sn, $st]) {
                        $stub .= pack('VVV', 0x20008 + $i * 8, $st, 0x2000c + $i * 8);
                    }
                    foreach ($shares as [$sn, $st, $rm]) {
                        $stub .= $str($sn) . $str($rm);
                    }
                    $stub .= pack('VVV', $n, 0, 0);
                    $half = intdiv(strlen($stub), 2);
                    $frag = static fn (int $flags, string $part) => $hdr(2, $flags, pack('VvCC', strlen($part), 0, 0, 0) . $part);
                    $pending = $frag(1, substr($stub, 0, $half)) . $frag(2, substr($stub, $half));
                }
                $reply(0, pack('vvVVvv', 17, 0, $dlen, 0, 0, 0));
                break;
            case 8:
                $note('READ ' . ($trees[$tree] ?? '?'));
                $data = $pending;
                $pending = '';
                $reply(0, pack('vCCVVV', 17, 80, 0, strlen($data), 0, 0) . $data);
                break;
            case 14:
                $fid = substr($body, 8, 16);
                $f = $files[$fid] ?? null;
                $share = $trees[$f['tree'] ?? 0] ?? '?';
                $note('QUERY_DIRECTORY ' . $share);
                $total = $readable[$share] ?? 0;
                $all = array_merge(['.', '..'], array_map(static fn (int $i): string => 'item-' . $i . '.txt', range(1, max(1, $total))));
                if ($total === 0) {
                    $all = ['.', '..'];
                }
                $chunk = array_slice($all, $f['pos'], 200);
                if ($chunk === []) {
                    $error(0x80000006);
                    break;
                }
                $files[$fid]['pos'] += count($chunk);
                $data = '';
                foreach ($chunk as $i => $entry) {
                    $u = $utf16($entry);
                    $rec = pack('VVV', 0, $i, strlen($u)) . $u;
                    $rec .= str_repeat("\0", (8 - strlen($rec) % 8) % 8);
                    if ($i < count($chunk) - 1) {
                        $rec = pack('V', strlen($rec)) . substr($rec, 4);
                    }
                    $data .= $rec;
                }
                $reply(0, pack('vvV', 9, 72, strlen($data)) . $data);
                break;
            case 6:
                $note('CLOSE');
                $reply(0, pack('vv', 60, 0) . str_repeat("\0", 56));
                break;
            case 4:
                $note('TREE_DISCONNECT ' . ($trees[$tree] ?? '?'));
                $reply(0, pack('vv', 4, 0));
                break;
            case 2:
                $note('LOGOFF');
                $reply(0, pack('vv', 4, 0));
                break 2;
            default:
                $note('UNEXPECTED ' . $name);
                $error(0xC00000BB);
        }
    }
    fclose($c);
}
