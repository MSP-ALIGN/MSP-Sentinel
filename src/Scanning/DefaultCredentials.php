<?php

declare(strict_types=1);

namespace Sentinel\Scanning;

/**
 * Default-credential checks for pen-test engagements (1.29, only when the engagement's signed tests include
 * 'default_creds' and the client's authorisation explicitly allows it). Used by Sentinel (external targets) and by
 * the on-premises agent (internal ranges).
 *
 * What it does, per open service that nmap identified:
 * - Logins with a short, fixed list of vendor defaults: FTP, HTTP Basic authentication (only where the start page
 *   asks for it), MySQL/MariaDB and PostgreSQL. At most THREE attempts per service, and NO USERNAME IS EVER TRIED
 *   TWICE ON ONE HOST (whatever the port or service: one device often serves the same accounts on several ports), so
 *   no account sees more than one failed attempt. Attempts on a host run one at a time, SPACING seconds apart (also
 *   between services). It stops at the first success, at any "locked" / "too many attempts" / "blocked" answer, at
 *   the per-host time budget, and when the caller says stop. Re-runs: the caller passes $only so a host already
 *   tested in the engagement isn't tried again, and a retest tries only the account that worked before (one attempt).
 * - "Open without any password" checks (no guessing): Redis (PING), MongoDB (one command that needs a login; its
 *   answer is discarded), Elasticsearch/OpenSearch (the start page), Memcached (VERSION).
 * After a successful login it disconnects at once: no commands, nothing read.
 *
 * Never: SSH, SMB, RDP, WinRM, LDAP or anything tied to Windows or directory accounts (lockout risk): Microsoft
 * products (IIS, HTTP.sys/WinRM, IIS FTP) are skipped by name and port, and a web page that also offers Negotiate or
 * NTLM sign-in is never tried (its Basic login checks Windows accounts). No brute force; nothing beyond the fixed
 * list; nothing that writes.
 *
 * Evidence: the service, the username and which list entry worked; the password only MASKED (first and last
 * character). The full password never leaves this class.
 *
 * Untrusted: every byte from the tested service (parsed at fixed offsets, length-capped, short timeouts). A hostile
 * server can't make it loop: every read has a byte cap and a deadline, SCRAM iteration counts are capped.
 * Security assumptions: the caller checked the address against the engagement's targets, exclusions and the live
 * authorisation right before calling, and passes a stop callback that re-checks them. Connections go through the
 * Connector (mock servers in tests).
 */
final class DefaultCredentials
{
    private const TIMEOUT = 5.0;
    private const MAX_READ = 65536;
    private const MAX_SCRAM_ITERATIONS = 100_000;
    /** Ports of Windows' own HTTP services (WinRM, HTTP.sys): never tried. */
    private const WINDOWS_PORTS = [5985, 5986, 47001];
    /** Longest the checks may take on one host (seconds); later services are left untried. */
    public const HOST_BUDGET = 600.0;

    /**
     * The vetted list: service => up to three [username, password] pairs, each a different account. Generic vendor
     * defaults only (no leaked or customer passwords).
     */
    public const LIST = [
        'ftp' => [['admin', 'admin'], ['root', 'root'], ['user', 'user']],
        'http_basic' => [['admin', 'admin'], ['root', 'root'], ['ubnt', 'ubnt']],
        'mysql' => [['root', ''], ['admin', 'admin'], ['mysql', 'mysql']],
        'postgresql' => [['postgres', 'postgres'], ['admin', 'admin'], ['root', 'root']],
    ];

    /** Human names for the report. */
    public const NAMES = ['ftp' => 'FTP', 'http_basic' => 'Web admin page (HTTP Basic)', 'mysql' => 'MySQL/MariaDB', 'postgresql' => 'PostgreSQL',
        'redis' => 'Redis', 'mongodb' => 'MongoDB', 'elasticsearch' => 'Elasticsearch/OpenSearch', 'memcached' => 'Memcached'];

    private readonly float $spacing;

    /** @param float $spacing seconds between two attempts on a host (5; shorter only in the test suite; never above 5) */
    public function __construct(private readonly Connector $connector, float $spacing = 5.0)
    {
        $this->spacing = is_finite($spacing) && $spacing >= 0 ? min(5.0, $spacing) : 5.0;
    }

    /**
     * Run the checks on one host's open ports.
     *
     * @param list<array<string,mixed>> $ports NmapXmlParser 'open' entries (port, service, product, ...)
     * @param callable():bool $shouldStop true when the engagement must stop (checked before every attempt)
     * @param array<string,string>|null $only null: the full list; otherwise only these logins ("service:port" =>
     *        username), one attempt each (a retest re-checks the account that worked; [] tries no logins at all).
     *        The no-password checks always run (they guess nothing).
     * @return list<array{port:int, service:string, result:string, user:string, masked:string, tried:int}>
     *         result: 'login' (a default worked), 'no_auth' (open without a password), 'denied' (every default
     *         refused / a password is required), 'locked' (it signalled a lockout or block: stopped), 'error' (no
     *         usable answer)
     */
    public function check(string $ip, array $ports, callable $shouldStop, ?array $only = null, float $budget = self::HOST_BUDGET): array
    {
        $out = [];
        $this->usedUsers = [];
        $this->lastAttempt = 0.0;
        $this->deadline = microtime(true) + max(0.0, min(self::HOST_BUDGET, $budget));
        foreach (array_slice($ports, 0, 200) as $p) {
            $port = (int) ($p['port'] ?? 0);
            $kind = self::kindFor($port, strtolower((string) ($p['service'] ?? '')), strtolower((string) ($p['product'] ?? '')));
            if ($kind === null || $port < 1 || $port > 65535 || $shouldStop() || microtime(true) > $this->deadline) {
                continue;
            }
            $login = !in_array($kind, ['redis', 'mongodb', 'elasticsearch', 'memcached'], true);
            $onlyUser = null;
            if ($login && $only !== null) {
                $onlyUser = $only[$kind . ':' . $port] ?? null;
                if ($onlyUser === null) {
                    continue; // a re-run: only what worked before is checked again
                }
            }
            $tls = $kind === 'http_basic' && self::looksTls($port, strtolower((string) ($p['service'] ?? '')));
            $r = $login ? $this->tryList($kind, $ip, $port, $tls, $shouldStop, $onlyUser)
                : ['result' => $this->noAuth($kind, $ip, $port), 'user' => '', 'masked' => '', 'tried' => 0];
            if ($r !== null) {
                $out[] = ['port' => $port, 'service' => $kind] + $r;
            }
        }
        return $out;
    }

    /**
     * Results received from an agent (untrusted), reduced to the shape check() returns: known services and results
     * only, short plain-text usernames and masks, at most 200 entries.
     *
     * @param array<mixed> $raw
     * @return list<array{port:int, service:string, result:string, user:string, masked:string, tried:int}>
     */
    public static function cleanResults(array $raw): array
    {
        $out = [];
        $text = static fn ($v): string => is_string($v) ? mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]/u', '', mb_convert_encoding($v, 'UTF-8', 'UTF-8'))), 0, 64) : '';
        foreach (array_slice(array_values(array_filter($raw, 'is_array')), 0, 200) as $r) {
            $port = (int) ($r['port'] ?? 0);
            $service = (string) ($r['service'] ?? '');
            $result = (string) ($r['result'] ?? '');
            if ($port < 1 || $port > 65535 || !isset(self::NAMES[$service]) || !in_array($result, ['login', 'no_auth', 'denied', 'locked', 'error'], true)) {
                continue;
            }
            $masked = $text($r['masked'] ?? '');
            // A mask shows at most the first and last character: anything else is not a mask and isn't kept.
            if ($masked !== '' && $masked !== '(blank)' && preg_match('/^.?•+.?$/u', $masked) !== 1) {
                $masked = '•••';
            }
            $out[] = ['port' => $port, 'service' => $service, 'result' => $result, 'user' => $result === 'login' ? $text($r['user'] ?? '') : '',
                'masked' => $result === 'login' ? $masked : '', 'tried' => max(0, min(3, (int) ($r['tried'] ?? 0)))];
        }
        return $out;
    }

    /** Which check fits an open port (nmap's service name first, the usual port second). */
    public static function kindFor(int $port, string $service, string $product): ?string
    {
        if (in_array($port, self::WINDOWS_PORTS, true) || preg_match('/microsoft|\biis\b|httpapi|windows/i', $product) === 1) {
            return null; // Windows services check Windows/directory accounts: never tried
        }
        if (str_contains($product, 'elasticsearch') || str_contains($product, 'opensearch') || $port === 9200) {
            return 'elasticsearch';
        }
        return match (true) {
            $service === 'ftp' || ($port === 21 && $service === '') => 'ftp',
            $service === 'mysql' || ($port === 3306 && $service === '') => 'mysql',
            $service === 'postgresql' || ($port === 5432 && $service === '') => 'postgresql',
            $service === 'redis' || ($port === 6379 && $service === '') => 'redis',
            $service === 'mongodb' || ($port === 27017 && $service === '') => 'mongodb',
            $service === 'memcached' || ($port === 11211 && $service === '') => 'memcached',
            str_starts_with($service, 'http') || str_starts_with($service, 'ssl/http') || in_array($port, [80, 443, 8080, 8443], true) => 'http_basic',
            default => null,
        };
    }

    /** A password shown in evidence: first and last character only ("a•••n"); "(blank)" for an empty one. */
    public static function mask(string $password): string
    {
        $n = mb_strlen($password);
        return match (true) {
            $n === 0 => '(blank)',
            $n <= 2 => str_repeat('•', $n),
            default => mb_substr($password, 0, 1) . str_repeat('•', $n - 2) . mb_substr($password, -1),
        };
    }

    private static function looksTls(int $port, string $service): bool
    {
        return str_contains($service, 'https') || str_starts_with($service, 'ssl/') || in_array($port, [443, 8443, 9443, 4443, 10443], true);
    }

    /** Usernames already tried on the current host (any service): never tried twice. @var array<string,true> */
    private array $usedUsers = [];
    private float $lastAttempt = 0.0;
    private float $deadline = 0.0;

    /**
     * Up to three accounts from the list (or the one in $onlyUser), one at a time, spaced from the host's previous
     * attempt; a username already tried on this host is skipped. Stops at the first success or lockout.
     *
     * @return array{result:string, user:string, masked:string, tried:int}|null null: nothing was tried (a web page that
     *         doesn't ask for Basic authentication, or offers Windows sign-in; every account already used on this host)
     */
    private function tryList(string $kind, string $ip, int $port, bool $tls, callable $shouldStop, ?string $onlyUser): ?array
    {
        if ($kind === 'http_basic') {
            $tls = $this->asksBasic($ip, $port, $tls);
            if ($tls === null) {
                return null; // no Basic authentication here, or Windows sign-in: nothing is tried
            }
        }
        $tried = 0;
        $last = 'error';
        foreach (self::LIST[$kind] as [$user, $pass]) {
            if (($onlyUser !== null && $user !== $onlyUser) || isset($this->usedUsers[$user])) {
                continue;
            }
            $wait = $this->lastAttempt + $this->spacing - microtime(true);
            if ($wait > 0) {
                usleep((int) ($wait * 1_000_000));
            }
            if ($shouldStop() || microtime(true) > $this->deadline) {
                break;
            }
            $tried++;
            $this->usedUsers[$user] = true;
            $r = match ($kind) {
                'ftp' => $this->ftp($ip, $port, $user, $pass),
                'http_basic' => $this->httpBasic($ip, $port, $tls, $user, $pass),
                'mysql' => $this->mysql($ip, $port, $user, $pass),
                'postgresql' => $this->postgres($ip, $port, $user, $pass),
            };
            $this->lastAttempt = microtime(true);
            if ($r === 'login') {
                return ['result' => 'login', 'user' => $user, 'masked' => self::mask($pass), 'tried' => $tried];
            }
            if ($r === 'locked') {
                return ['result' => 'locked', 'user' => '', 'masked' => '', 'tried' => $tried];
            }
            if ($r === 'denied') { // one refusal is enough to say a password is required
                $last = 'denied';
            }
            if ($r === 'stop') {
                break; // e.g. this host may not log in at all (not allowed from here), or a Windows FTP server
            }
        }
        return $tried === 0 ? null : ['result' => $last, 'user' => '', 'masked' => '', 'tried' => $tried];
    }

    // ------------------------------------------------------------------ connections

    /** @return resource|null */
    private function open(string $ip, int $port, bool $tls = false)
    {
        try {
            [$host, $real] = $this->connector->endpoint($ip, $port);
        } catch (\RuntimeException) {
            return null;
        }
        $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true, 'SNI_enabled' => false]]);
        $fp = @stream_socket_client(($tls ? 'tls://' : 'tcp://') . Connector::hostPort($host, $real), $errno, $errstr, self::TIMEOUT, STREAM_CLIENT_CONNECT, $ctx);
        if ($fp === false) {
            return null;
        }
        stream_set_timeout($fp, (int) self::TIMEOUT);
        return $fp;
    }

    /** Exactly $n bytes, or fewer at the deadline or the end of the stream. @param resource $fp */
    private static function readN($fp, int $n, float $deadline): string
    {
        $buf = '';
        while (strlen($buf) < $n && microtime(true) < $deadline && !feof($fp)) {
            $chunk = @fread($fp, min(8192, $n - strlen($buf)));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $buf .= $chunk;
        }
        return $buf;
    }

    /** One text line (CRLF), at most 1024 bytes. @param resource $fp */
    private static function line($fp, float $deadline): ?string
    {
        if (microtime(true) > $deadline) {
            return null;
        }
        $l = @fgets($fp, 1024);
        return $l === false ? null : rtrim($l, "\r\n");
    }

    // ------------------------------------------------------------------ FTP

    /** @return string 'login' | 'denied' | 'locked' | 'error' */
    private function ftp(string $ip, int $port, string $user, string $pass): string
    {
        $fp = $this->open($ip, $port);
        if ($fp === null) {
            return 'error';
        }
        $deadline = microtime(true) + self::TIMEOUT * 2;
        try {
            $text = '';
            $reply = static function () use ($fp, $deadline, &$text): int {
                // Multi-line replies: "220-..." lines until "220 ...". At most 50 lines; their text is kept (1 KB).
                $text = '';
                for ($i = 0; $i < 50; $i++) {
                    $l = self::line($fp, $deadline);
                    if ($l === null) {
                        return 0;
                    }
                    $text = mb_substr($text . ' ' . $l, 0, 1024);
                    if (preg_match('/^(\d{3}) /', $l, $m) === 1 || preg_match('/^(\d{3})$/', $l, $m) === 1) {
                        return (int) $m[1];
                    }
                }
                return 0;
            };
            $lockedText = static function () use (&$text): bool {
                return preg_match('/lock|too many|blocked|banned/i', $text) === 1;
            };
            $greet = $reply();
            if ($greet === 421) {
                return 'locked';
            }
            if ($greet !== 220) {
                return 'error';
            }
            if (stripos($text, 'microsoft') !== false) {
                return 'stop'; // IIS FTP checks Windows accounts: never tried
            }
            fwrite($fp, 'USER ' . $user . "\r\n");
            $u = $reply();
            if ($u === 230) {
                return 'login'; // logged in without even a password
            }
            if ($u === 421) {
                return 'locked';
            }
            if ($u !== 331) {
                return $u === 530 ? ($lockedText() ? 'locked' : 'denied') : 'error';
            }
            fwrite($fp, 'PASS ' . $pass . "\r\n");
            $p = $reply();
            return match (true) {
                $p === 230 || $p === 202 => 'login',
                $p === 421 => 'locked',
                $p === 530 => $lockedText() ? 'locked' : 'denied',
                default => 'error',
            };
        } finally {
            @fwrite($fp, "QUIT\r\n");
            fclose($fp);
        }
    }

    // ------------------------------------------------------------------ HTTP

    /**
     * One GET / (Connection: close), with optional Basic credentials.
     *
     * @return array{status:int, headers:string, body:string}|null
     */
    private function httpGet(string $ip, int $port, bool $tls, ?string $auth): ?array
    {
        $fp = $this->open($ip, $port, $tls);
        if ($fp === null) {
            return null;
        }
        $host = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        fwrite($fp, "GET / HTTP/1.1\r\nHost: {$host}\r\nUser-Agent: MSP-Sentinel-engagement\r\nAccept: */*\r\nConnection: close\r\n"
            . ($auth !== null ? 'Authorization: Basic ' . base64_encode($auth) . "\r\n" : '') . "\r\n");
        $raw = self::readN($fp, self::MAX_READ, microtime(true) + self::TIMEOUT);
        fclose($fp);
        if (preg_match('#^HTTP/\d(?:\.\d)? (\d{3})#', $raw, $m) !== 1) {
            return null;
        }
        $split = strpos($raw, "\r\n\r\n");
        return ['status' => (int) $m[1], 'headers' => $split === false ? $raw : substr($raw, 0, $split), 'body' => $split === false ? '' : substr($raw, $split + 4)];
    }

    /**
     * Whether the start page asks for Basic authentication: the scheme that answered (true: HTTPS), or null. The likely
     * scheme is tried first, the other only if it got no HTTP answer at all.
     */
    private function asksBasic(string $ip, int $port, bool $tls): ?bool
    {
        foreach ([$tls, !$tls] as $scheme) {
            $r = $this->httpGet($ip, $port, $scheme, null);
            if ($r !== null) {
                // Windows sign-in on offer (Negotiate/NTLM, or a Microsoft server): its Basic login checks directory accounts.
                if (preg_match('/^WWW-Authenticate:\s*(Negotiate|NTLM)\b/mi', $r['headers']) === 1 || preg_match('/^Server:\s*Microsoft/mi', $r['headers']) === 1) {
                    return null;
                }
                return $r['status'] === 401 && preg_match('/^WWW-Authenticate:\s*Basic\b/mi', $r['headers']) === 1 ? $scheme : null;
            }
        }
        return null;
    }

    private function httpBasic(string $ip, int $port, bool $tls, string $user, string $pass): string
    {
        $r = $this->httpGet($ip, $port, $tls, $user . ':' . $pass);
        return match (true) {
            $r === null => 'error',
            $r['status'] >= 200 && $r['status'] < 300 => 'login', // a redirect may be the device's "wrong password" page
            $r['status'] === 401 => 'denied',
            in_array($r['status'], [403, 423, 429, 503], true) => 'locked', // blocked or rate-limited: stop here
            default => 'error',
        };
    }

    // ------------------------------------------------------------------ MySQL / MariaDB

    /** @return string 'login' | 'denied' | 'locked' | 'error' | 'stop' */
    private function mysql(string $ip, int $port, string $user, string $pass): string
    {
        $fp = $this->open($ip, $port);
        if ($fp === null) {
            return 'error';
        }
        $deadline = microtime(true) + self::TIMEOUT * 2;
        $read = static function () use ($fp, $deadline): ?array {
            $h = self::readN($fp, 4, $deadline);
            if (strlen($h) !== 4) {
                return null;
            }
            $len = unpack('V', substr($h, 0, 3) . "\0")[1];
            if ($len > self::MAX_READ) {
                return null;
            }
            $body = self::readN($fp, $len, $deadline);
            return strlen($body) === $len ? ['seq' => ord($h[3]), 'body' => $body] : null;
        };
        $send = static function (int $seq, string $body) use ($fp): void {
            fwrite($fp, substr(pack('V', strlen($body)), 0, 3) . chr($seq & 0xff) . $body);
        };
        $err = static function (string $b): string {
            $code = strlen($b) >= 3 ? unpack('v', substr($b, 1, 2))[1] : 0;
            return match (true) {
                $code === 1045 => 'denied',
                in_array($code, [1129, 3118, 3955, 4151], true) => 'locked', // host blocked, account locked (MySQL, MariaDB), too many failures
                in_array($code, [1130, 1040], true) => 'stop',           // host not allowed / too many connections
                default => 'error',
            };
        };
        try {
            $hs = $read();
            if ($hs === null || $hs['body'] === '') {
                return 'error';
            }
            $b = $hs['body'];
            if ($b[0] === "\xff") {
                return $err($b);
            }
            if ($b[0] !== "\x0a") {
                return 'error';
            }
            $nul = strpos($b, "\0", 1);
            if ($nul === false || strlen($b) < $nul + 1 + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10) {
                return 'error';
            }
            $o = $nul + 1 + 4;
            $salt = substr($b, $o, 8);
            $o += 8 + 1 + 2 + 1 + 2 + 2;
            $authLen = ord($b[$o]);
            $o += 1 + 10;
            $part2 = substr($b, $o, max(13, $authLen - 8));
            $salt .= rtrim($part2, "\0");
            $o += strlen($part2);
            $pe = strpos($b, "\0", $o);
            $plugin = $pe === false ? substr($b, $o) : substr($b, $o, $pe - $o);
            $plugin = in_array($plugin, ['mysql_native_password', 'caching_sha2_password'], true) ? $plugin : 'mysql_native_password';
            $caps = 0x00000001 | 0x00000200 | 0x00002000 | 0x00008000 | 0x00080000; // long pw, 4.1, transactions, secure conn, plugin auth
            $auth = self::mysqlScramble($plugin, $pass, $salt);
            $send(1, pack('VVC', $caps, 0x01000000, 45) . str_repeat("\0", 23) . $user . "\0" . chr(strlen($auth)) . $auth . $plugin . "\0");
            for ($step = 0; $step < 4; $step++) {
                $r = $read();
                if ($r === null || $r['body'] === '') {
                    return 'error';
                }
                $rb = $r['body'];
                if ($rb[0] === "\x00") {
                    return 'login';
                }
                if ($rb[0] === "\xff") {
                    return $err($rb);
                }
                if ($rb[0] === "\xfe") { // auth switch: plugin\0data
                    $pe = strpos($rb, "\0", 1);
                    $newPlugin = $pe === false ? substr($rb, 1) : substr($rb, 1, $pe - 1);
                    if (!in_array($newPlugin, ['mysql_native_password', 'caching_sha2_password'], true)) {
                        return 'error';
                    }
                    $salt = rtrim($pe === false ? '' : substr($rb, $pe + 1), "\0");
                    $send($r['seq'] + 1, self::mysqlScramble($newPlugin, $pass, $salt));
                    continue;
                }
                if ($rb[0] === "\x01" && strlen($rb) >= 2) {
                    if ($rb[1] === "\x03") {
                        continue; // fast authentication worked; the OK packet follows
                    }
                    return 'error'; // full authentication needs TLS or the server's RSA key: can't tell, nothing more sent
                }
                return 'error';
            }
            return 'error';
        } finally {
            @$send(0, "\x01"); // COM_QUIT
            fclose($fp);
        }
    }

    /** The scrambled password for MySQL's two common authentication plugins (empty password: empty answer). */
    public static function mysqlScramble(string $plugin, string $pass, string $salt): string
    {
        if ($pass === '') {
            return '';
        }
        $salt = substr($salt, 0, 20);
        if ($plugin === 'caching_sha2_password') {
            $p1 = hash('sha256', $pass, true);
            return $p1 ^ hash('sha256', hash('sha256', $p1, true) . $salt, true);
        }
        $p1 = sha1($pass, true);
        return $p1 ^ sha1($salt . sha1($p1, true), true);
    }

    // ------------------------------------------------------------------ PostgreSQL

    /** @return string 'login' | 'denied' | 'locked' | 'error' | 'stop' */
    private function postgres(string $ip, int $port, string $user, string $pass): string
    {
        $fp = $this->open($ip, $port);
        if ($fp === null) {
            return 'error';
        }
        $deadline = microtime(true) + self::TIMEOUT * 2;
        $read = static function () use ($fp, $deadline): ?array {
            $h = self::readN($fp, 5, $deadline);
            if (strlen($h) !== 5) {
                return null;
            }
            $len = unpack('N', substr($h, 1, 4))[1];
            if ($len < 4 || $len > self::MAX_READ) {
                return null;
            }
            $body = self::readN($fp, $len - 4, $deadline);
            return strlen($body) === $len - 4 ? ['type' => $h[0], 'body' => $body] : null;
        };
        $send = static function (string $type, string $body) use ($fp): void {
            fwrite($fp, $type . pack('N', strlen($body) + 4) . $body);
        };
        try {
            $startup = pack('N', 196608) . "user\0" . $user . "\0database\0postgres\0application_name\0msp-sentinel-engagement\0\0";
            fwrite($fp, pack('N', strlen($startup) + 4) . $startup);
            $scram = null;
            for ($step = 0; $step < 6; $step++) {
                $m = $read();
                if ($m === null) {
                    return 'error';
                }
                if ($m['type'] === 'E') {
                    $code = preg_match('/(?:^|\0)C([0-9A-Z]{5})\0/', $m['body'], $c) === 1 ? $c[1] : '';
                    return match (true) {
                        in_array($code, ['28P01', '28000'], true) => stripos($m['body'], 'no pg_hba.conf entry') !== false ? 'stop' : 'denied',
                        $code === '53300' => 'stop', // too many connections
                        default => 'error',
                    };
                }
                if ($m['type'] !== 'R' || strlen($m['body']) < 4) {
                    return 'error';
                }
                $code = unpack('N', substr($m['body'], 0, 4))[1];
                $data = substr($m['body'], 4);
                if ($code === 0) {
                    return 'login';
                }
                if ($code === 3) {
                    $send('p', $pass . "\0");
                } elseif ($code === 5 && strlen($data) === 4) {
                    $send('p', 'md5' . md5(md5($pass . $user) . $data) . "\0");
                } elseif ($code === 10) {
                    if (!in_array('SCRAM-SHA-256', explode("\0", $data), true)) {
                        return 'error';
                    }
                    $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
                    $scram = ['bare' => 'n=,r=' . $nonce, 'nonce' => $nonce];
                    $first = 'n,,' . $scram['bare'];
                    $send('p', "SCRAM-SHA-256\0" . pack('N', strlen($first)) . $first);
                } elseif ($code === 11 && $scram !== null) {
                    $final = self::scramFinal($pass, $scram['bare'], $scram['nonce'], $data);
                    if ($final === null) {
                        return 'error';
                    }
                    $send('p', $final);
                } elseif ($code === 12) {
                    continue; // server's final SCRAM message; AuthenticationOk follows
                } else {
                    return 'error'; // Kerberos, GSS, SSPI, certificates: not tried
                }
            }
            return 'error';
        } finally {
            @fwrite($fp, 'X' . pack('N', 4));
            fclose($fp);
        }
    }

    /** SCRAM-SHA-256 client-final message for the server-first message, or null when it isn't acceptable. */
    public static function scramFinal(string $pass, string $clientBare, string $nonce, string $serverFirst): ?string
    {
        $attrs = [];
        foreach (explode(',', $serverFirst) as $kv) {
            if (strlen($kv) > 2 && $kv[1] === '=') {
                $attrs[$kv[0]] = substr($kv, 2);
            }
        }
        $salt = base64_decode($attrs['s'] ?? '', true);
        $iter = (int) ($attrs['i'] ?? 0);
        if (!isset($attrs['r']) || !str_starts_with($attrs['r'], $nonce) || $salt === false || $iter < 1 || $iter > self::MAX_SCRAM_ITERATIONS) {
            return null;
        }
        $salted = hash_pbkdf2('sha256', $pass, $salt, $iter, 32, true);
        $clientKey = hash_hmac('sha256', 'Client Key', $salted, true);
        $withoutProof = 'c=biws,r=' . $attrs['r'];
        $authMessage = $clientBare . ',' . $serverFirst . ',' . $withoutProof;
        $proof = $clientKey ^ hash_hmac('sha256', $authMessage, hash('sha256', $clientKey, true), true);
        return $withoutProof . ',p=' . base64_encode($proof);
    }

    // ------------------------------------------------------------------ open without a password

    /** @return string 'no_auth' | 'denied' | 'error' */
    private function noAuth(string $kind, string $ip, int $port): string
    {
        if ($kind === 'elasticsearch') {
            foreach ([false, true] as $tls) {
                $r = $this->httpGet($ip, $port, $tls, null);
                if ($r === null) {
                    continue;
                }
                if ($r['status'] === 200 && str_contains($r['body'], '"cluster_name"')) {
                    return 'no_auth';
                }
                return $r['status'] === 401 || $r['status'] === 403 ? 'denied' : 'error';
            }
            return 'error';
        }
        $fp = $this->open($ip, $port);
        if ($fp === null) {
            return 'error';
        }
        $deadline = microtime(true) + self::TIMEOUT;
        try {
            if ($kind === 'redis') {
                fwrite($fp, "PING\r\n");
                $l = (string) self::line($fp, $deadline);
                return str_starts_with($l, '+PONG') ? 'no_auth' : (str_starts_with($l, '-NOAUTH') || str_starts_with($l, '-DENIED') || str_starts_with($l, '-ERR') ? 'denied' : 'error');
            }
            if ($kind === 'memcached') {
                fwrite($fp, "version\r\n");
                $l = (string) self::line($fp, $deadline);
                return str_starts_with($l, 'VERSION ') ? 'no_auth' : ($l !== '' ? 'denied' : 'error');
            }
            // MongoDB: OP_MSG with one command that needs a login when access control is on; the answer is discarded.
            $doc = self::bson(['listDatabases' => 1, 'nameOnly' => true, '$db' => 'admin']);
            $body = pack('V', 0) . "\0" . $doc;
            fwrite($fp, pack('VVVV', 16 + strlen($body), random_int(1, 0x7fffffff), 0, 2013) . $body);
            $h = self::readN($fp, 16, $deadline);
            if (strlen($h) !== 16) {
                return 'error';
            }
            $len = unpack('V', substr($h, 0, 4))[1];
            if ($len < 21 || $len > self::MAX_READ || unpack('V', substr($h, 12, 4))[1] !== 2013) {
                return 'error';
            }
            $rest = self::readN($fp, $len - 16, $deadline);
            if (strlen($rest) !== $len - 16 || $rest[4] !== "\0") {
                return 'error';
            }
            $ok = self::bsonOk(substr($rest, 5));
            return $ok === null ? 'error' : ($ok ? 'no_auth' : 'denied');
        } finally {
            fclose($fp);
        }
    }

    /** A tiny BSON document of int32, bool and string fields. @param array<string,int|bool|string> $fields */
    private static function bson(array $fields): string
    {
        $e = '';
        foreach ($fields as $k => $v) {
            $e .= match (true) {
                is_bool($v) => "\x08" . $k . "\0" . ($v ? "\x01" : "\x00"),
                is_int($v) => "\x10" . $k . "\0" . pack('V', $v),
                default => "\x02" . $k . "\0" . pack('V', strlen($v) + 1) . $v . "\0",
            };
        }
        return pack('V', strlen($e) + 5) . $e . "\0";
    }

    /** The top-level "ok" field of a BSON reply (true when 1), or null when it can't be read. */
    private static function bsonOk(string $doc): ?bool
    {
        if (strlen($doc) < 5) {
            return null;
        }
        $end = min(strlen($doc), unpack('V', substr($doc, 0, 4))[1]);
        $o = 4;
        for ($n = 0; $n < 200 && $o < $end - 1; $n++) {
            $type = ord($doc[$o]);
            $ke = strpos($doc, "\0", $o + 1);
            if ($ke === false || $ke >= $end) {
                return null;
            }
            $key = substr($doc, $o + 1, $ke - $o - 1);
            $o = $ke + 1;
            if ($key === 'ok') {
                return match ($type) {
                    0x01 => strlen($doc) >= $o + 8 ? unpack('e', substr($doc, $o, 8))[1] == 1.0 : null,
                    0x10 => strlen($doc) >= $o + 4 ? unpack('V', substr($doc, $o, 4))[1] === 1 : null,
                    0x12 => strlen($doc) >= $o + 8 ? unpack('P', substr($doc, $o, 8))[1] === 1 : null,
                    0x08 => isset($doc[$o]) ? $doc[$o] === "\x01" : null,
                    default => null,
                };
            }
            $size = match ($type) {
                0x01, 0x09, 0x11, 0x12 => 8,
                0x13 => 16,
                0x07 => 12,
                0x08 => 1,
                0x10 => 4,
                0x0A => 0,
                0x02, 0x0D, 0x0E => strlen($doc) >= $o + 4 ? 4 + unpack('V', substr($doc, $o, 4))[1] : -1,
                0x03, 0x04 => strlen($doc) >= $o + 4 ? unpack('V', substr($doc, $o, 4))[1] : -1,
                0x05 => strlen($doc) >= $o + 4 ? 5 + unpack('V', substr($doc, $o, 4))[1] : -1,
                default => -1,
            };
            if ($size < 0) {
                return null;
            }
            $o += $size;
        }
        return null;
    }
}
