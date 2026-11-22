<?php

declare(strict_types=1);

namespace Sentinel\Tests;

use PDO;

/**
 * Minimal test toolkit (no Composer, no PHPUnit): assertions, an HTTP client
 * with a cookie jar, and the shared context handed to every test.
 *
 * Security assumptions: tests only ever talk to 127.0.0.1 (the PHP built-in
 * server started by tests/run.php) and a throwaway database. No outside
 * host is contacted.
 */
final class AssertionFailed extends \RuntimeException
{
}

final class Assert
{
    public static function true(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new AssertionFailed($message);
        }
    }

    public static function same(mixed $expected, mixed $actual, string $message = ''): void
    {
        if ($expected !== $actual) {
            throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
        }
    }

    public static function contains(string $needle, string $haystack, string $message = ''): void
    {
        if (!str_contains($haystack, $needle)) {
            throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . 'expected to find ' . var_export($needle, true));
        }
    }

    public static function notContains(string $needle, string $haystack, string $message = ''): void
    {
        if (str_contains($haystack, $needle)) {
            throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . 'did not expect to find ' . var_export($needle, true));
        }
    }

    public static function status(int $expected, HttpResult $res, string $message = ''): void
    {
        if ($res->status !== $expected) {
            throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . "expected HTTP {$expected}, got {$res->status}"
                . ($res->location() !== null ? ' (Location: ' . $res->location() . ')' : ''));
        }
    }

    public static function redirect(string $path, HttpResult $res, string $message = ''): void
    {
        if (!in_array($res->status, [301, 302, 303], true) || $res->location() !== $path) {
            throw new AssertionFailed(($message !== '' ? $message . ': ' : '') . "expected redirect to {$path}, got HTTP {$res->status} to " . var_export($res->location(), true));
        }
    }
}

final class HttpResult
{
    /** @param array<string,list<string>> $headers lower-case name => values */
    public function __construct(public readonly int $status, public readonly array $headers, public readonly string $body)
    {
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)][0] ?? null;
    }

    public function location(): ?string
    {
        return $this->header('location');
    }

    /** First CSRF token found in the page. */
    public function csrf(): string
    {
        if (!preg_match('/name="_csrf" value="([a-f0-9]{64})"/', $this->body, $m)) {
            throw new AssertionFailed('No CSRF token on page (HTTP ' . $this->status . ')');
        }
        return $m[1];
    }
}

/**
 * A browser-like client: keeps cookies, never follows redirects (tests check them).
 */
final class HttpClient
{
    private \CurlHandle $curl;

    public function __construct(private readonly string $baseUrl)
    {
        $this->curl = curl_init();
        curl_setopt_array($this->curl, [
            CURLOPT_COOKIEFILE => '', // in-memory cookie jar
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_PROXY => '', // never send test traffic through a proxy
            CURLOPT_NOPROXY => '*',
        ]);
    }

    public function get(string $path): HttpResult
    {
        return $this->request('GET', $path, null);
    }

    /** @param array<string,string> $fields */
    public function post(string $path, array $fields): HttpResult
    {
        return $this->request('POST', $path, $fields);
    }

    /**
     * Load a page, take its CSRF token and post a form, like a user would.
     *
     * @param array<string,string> $fields
     */
    public function submit(string $formPage, string $action, array $fields): HttpResult
    {
        $page = $this->get($formPage);
        return $this->post($action, $fields + ['_csrf' => $page->csrf()]);
    }

    /**
     * Post a multipart form with one file (like a browser upload). Takes the CSRF token from $formPage.
     *
     * @param array<string,string> $fields
     */
    public function upload(string $formPage, string $action, array $fields, string $fileField, string $filePath, string $mime): HttpResult
    {
        $page = $this->get($formPage);
        return $this->request('POST', $action, $fields + ['_csrf' => $page->csrf(), $fileField => new \CURLFile($filePath, $mime, basename($filePath))], true);
    }

    /** Value of a cookie in the jar, or null. */
    public function cookie(string $name): ?string
    {
        foreach (curl_getinfo($this->curl, CURLINFO_COOKIELIST) ?: [] as $line) {
            $parts = explode("\t", $line);
            if (($parts[5] ?? null) === $name) {
                return $parts[6] ?? '';
            }
        }
        return null;
    }

    /** @param array<string,mixed>|null $fields */
    private function request(string $method, string $path, ?array $fields, bool $multipart = false): HttpResult
    {
        $headers = [];
        curl_setopt_array($this->curl, [
            CURLOPT_URL => $this->baseUrl . $path,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_POST => $method === 'POST',
            CURLOPT_POSTFIELDS => $fields === null ? null : ($multipart ? $fields : http_build_query($fields)),
            CURLOPT_HTTPGET => $method === 'GET',
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headers): int {
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $headers[strtolower(trim($name))][] = trim($value);
                }
                return strlen($line);
            },
        ]);
        if ($method === 'GET') {
            curl_setopt($this->curl, CURLOPT_POSTFIELDS, null);
        }
        $body = curl_exec($this->curl);
        if ($body === false) {
            throw new AssertionFailed('HTTP request failed: ' . curl_error($this->curl));
        }
        return new HttpResult((int) curl_getinfo($this->curl, CURLINFO_RESPONSE_CODE), $headers, (string) $body);
    }
}

/**
 * Shared state for tests: base URL, database, and helpers to sign users in.
 */
final class TestContext
{
    /** @var array<string,string> username => TOTP secret captured at enrolment */
    public array $secrets = [];
    /** Mock DNS server port, its query log, and the mock crt.sh base URL (all 127.0.0.1). */
    public int $dnsPort = 0;
    public string $dnsLog = '';
    public string $crtshUrl = '';
    /** Fake mail servers (spool of received messages, ports) and the fake webhook's log. */
    public string $mailSpool = '';
    public int $smtpPlainPort = 0;
    public int $smtpTlsPort = 0;
    public string $webhookLog = '';
    /** Where the fake event receiver records posts ({event, signature, body} per line). */
    public string $eventLog = '';

    /**
     * Call the API with a bearer token (no cookies). $json is sent as the body for POST.
     *
     * @param array<string,mixed>|null $json
     */
    public function api(string $method, string $path, ?string $token, ?array $json = null, ?string $rawBody = null): HttpResult
    {
        $ch = curl_init($this->baseUrl . $path);
        $headers = [];
        $send = $rawBody ?? ($json !== null ? json_encode($json) : null);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array_values(array_filter([$token !== null ? 'Authorization: Bearer ' . $token : null, $send !== null ? 'Content-Type: application/json' : null])),
            CURLOPT_POSTFIELDS => $send,
            CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$headers): int {
                if (str_contains($line, ':')) {
                    [$n, $v] = explode(':', $line, 2);
                    $headers[strtolower(trim($n))][] = trim($v);
                }
                return strlen($line);
            },
        ]);
        $body = curl_exec($ch);
        if ($body === false) {
            throw new AssertionFailed('API request failed: ' . curl_error($ch));
        }
        return new HttpResult((int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), $headers, (string) $body);
    }

    /**
     * Messages received by the fake mail servers, oldest first, with the decoded subject and body.
     *
     * @return list<array{from:string,to:list<string>,auth_user:string,tls:bool,subject:string,body:string}>
     */
    public function mails(): array
    {
        $out = [];
        $files = glob($this->mailSpool . '/*.json') ?: [];
        sort($files);
        foreach ($files as $file) {
            $m = json_decode((string) file_get_contents($file), true);
            [$head, $body] = array_pad(explode("\r\n\r\n", (string) $m['data'], 2), 2, '');
            // The subject may be folded into several encoded words (RFC 2047).
            preg_match('/^Subject: ([^\r\n]*(?:\r\n [^\r\n]*)*)/m', $head, $sm);
            preg_match_all('/=\?UTF-8\?B\?([^?]*)\?=/', $sm[1] ?? '', $words);
            $subject = implode('', array_map('base64_decode', $words[1]));
            $out[] = ['from' => $m['from'], 'to' => $m['to'], 'auth_user' => $m['auth_user'], 'tls' => $m['tls'],
                      'raw' => (string) $m['data'], 'subject' => $subject, 'body' => (string) base64_decode(str_replace(["\r", "\n"], '', $body))];
        }
        return $out;
    }

    /** Mock threat-feed server base URL and its request log. */
    public string $feedsUrl = '';
    public string $feedsLog = '';
    /** File where the fake nmap records the arguments of every call. */
    public string $nmapLog = '';

    /**
     * Run a CLI script with the test config (e.g. bin/worker.php).
     *
     * @return array{0:int,1:string} [exit code, output]
     */
    public function cli(string $script, array $args = [], array $env = []): array
    {
        $proc = proc_open(array_merge([PHP_BINARY, $this->root . '/' . $script], $args), [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->root,
            $env + ['SENTINEL_CONFIG' => $this->configPath, 'PATH' => (string) getenv('PATH'), 'SENTINEL_ALLOW_ROOT' => '1', 'SENTINEL_TEST_MODE' => '1']);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        return [proc_close($proc), $out];
    }

    public function __construct(
        public readonly string $baseUrl,
        public readonly PDO $db,
        public readonly string $root,
        public readonly string $configPath,
    ) {
    }

    public function client(): HttpClient
    {
        return new HttpClient($this->baseUrl);
    }

    /** Current TOTP code for a user whose secret we captured. */
    public function totp(string $username, int $offsetSteps = 0): string
    {
        return \Sentinel\Auth\Totp::code($this->secrets[$username], \Sentinel\Auth\Totp::currentStep() + $offsetSteps);
    }

    /**
     * Let a user sign in again within the same 30 seconds: forget the last
     * used step. (Replay protection itself has its own test.)
     */
    public function allowFreshCode(string $username): void
    {
        $this->db->prepare('UPDATE users SET totp_last_step = NULL WHERE username = :u')->execute(['u' => $username]);
    }

    /** Create a user straight in the database (fast test setup). */
    public function createUser(string $username, string $role, string $password, bool $mustChange = false): int
    {
        $stmt = $this->db->prepare(
            "INSERT INTO users (username, display_name, email, role, password_hash, must_change_password, is_active, session_version, created_at, updated_at)
             VALUES (:u, :d, '', :r, :p, :m, 1, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())"
        );
        $stmt->execute(['u' => $username, 'd' => ucfirst($username) . ' Example', 'r' => $role, 'p' => password_hash($password, PASSWORD_ARGON2ID), 'm' => $mustChange ? 1 : 0]);
        return (int) $this->db->lastInsertId();
    }

    /**
     * Full sign-in for a user: password, then 2FA enrolment (first time) or a TOTP code.
     * Returns the client, signed in.
     */
    /**
     * All of a client's pages (overview and every section) in one string, for checks that don't care which page
     * shows something. Every page must load (200), so a broken section fails here too.
     */
    public function clientPages(HttpClient $client, int $clientId): string
    {
        $out = '';
        foreach (array_merge([''], array_map(static fn (string $s): string => '/' . $s, array_slice(\Sentinel\Controllers\ClientController::SECTIONS, 1))) as $suffix) {
            $res = $client->get('/clients/' . $clientId . $suffix);
            if ($res->status !== 200) {
                throw new \RuntimeException("/clients/{$clientId}{$suffix} returned HTTP {$res->status}");
            }
            $out .= $res->body;
        }
        return $out;
    }

    public function login(string $username, string $password, ?HttpClient $client = null): HttpClient
    {
        $client ??= $this->client();
        $res = $client->submit('/login', '/login', ['username' => $username, 'password' => $password]);
        if ($res->location() === '/2fa/setup') {
            $page = $client->get('/2fa/setup');
            if (!preg_match('/data-testid="totp-secret">([A-Z2-7 ]+)</', $page->body, $m)) {
                throw new AssertionFailed('No TOTP secret on the enrolment page');
            }
            $this->secrets[$username] = str_replace(' ', '', $m[1]);
            $res = $client->post('/2fa/setup', ['_csrf' => $page->csrf(), 'code' => $this->totp($username)]);
            Assert::redirect('/recovery-codes', $res, 'enrolment for ' . $username);
            $client->get('/recovery-codes');
            return $client;
        }
        Assert::redirect('/login/2fa', $res, 'password step for ' . $username);
        $this->allowFreshCode($username);
        $res = $client->submit('/login/2fa', '/login/2fa', ['code' => $this->totp($username)]);
        Assert::redirect('/', $res, 'second factor for ' . $username);
        return $client;
    }

    /** Clear login throttling between tests. */
    public function clearThrottle(): void
    {
        $this->db->exec('DELETE FROM auth_throttle');
    }
}
