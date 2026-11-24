<?php

declare(strict_types=1);

namespace Sentinel\Breach;

/**
 * Reads breach data for the MSP's verified domains from XposedOrNot (1.33), read-only.
 *
 * API facts used (XposedOrNot-API, api/v1/domain_breaches.py):
 * - POST {base}/v1/domain-breaches/ with header "x-api-key", no body. The answer covers every domain verified under
 *   the key's account: {"status":"success","metrics":{"Breaches_Details":[{"email","domain","breach"}, ...],
 *   "Detailed_Breach_Info":{"<breach>":{"breached_date","xposed_data","xposure_desc",...}}, "Domain_Summary":{...}}}.
 * - 401 {"detail": "..."} for a wrong or inactive key; 429 with Retry-After when over its limits (the domain endpoint
 *   allows 50 calls a day per address; Sentinel calls it once a week, plus "Check now").
 * A domain must be verified in the MSP's XposedOrNot account (their dashboard) before it appears; the free key is for
 * low-volume use, xonAPI+ keys work the same way.
 *
 * Security assumptions:
 * - The address is XposedOrNot's own (fixed); only the test suite may point it elsewhere (plain http allowed there).
 *   Verified certificates, no redirects, so the key only ever goes to that address.
 * - Every answer is untrusted: the size is capped (16 MB), JSON decoded defensively, every value cast, addresses
 *   validated, entries and breaches capped. Passwords are never part of the answer and never stored.
 * - The API key is never logged or put in an exception message.
 */
final class XonClient
{
    public const DEFAULT_BASE = 'https://api.xposedornot.com';
    private const MAX_BYTES = 8388608; // decoded JSON takes several times this in memory
    private const MAX_ENTRIES = 50000;
    private const MAX_BREACHES = 5000;

    /** @param bool $allowHttp Test suite only. */
    public function __construct(private readonly string $apiKey, private readonly string $baseUrl = self::DEFAULT_BASE, private readonly bool $allowHttp = false)
    {
    }

    /** Whether a value looks like an API key (printable, no spaces, a sensible length). */
    public static function validKey(string $key): bool
    {
        return preg_match('/^[\x21-\x7E]{16,256}$/', $key) === 1; // printable ASCII: no spaces or line breaks (header safe)
    }

    /**
     * Breached addresses of every verified domain, with each breach's date and exposed data.
     *
     * @return array{exposures:list<array{email:string, domain:string, breach:string}>,
     *               breaches:array<string, array{date:string, data:list<string>}>,
     *               domains:list<string>}
     *         date: Y-m-d ('' when unknown); domains: the verified domains the answer covers
     * @throws XonException with a message fit for admins (never containing the key)
     */
    public function domainBreaches(): array
    {
        $data = $this->post('/v1/domain-breaches/');
        $metrics = is_array($data['metrics'] ?? null) ? $data['metrics'] : null;
        if (($data['status'] ?? '') !== 'success' || $metrics === null) {
            throw new XonException('XposedOrNot returned an unexpected answer.');
        }
        $exposures = [];
        foreach (array_slice(is_array($metrics['Breaches_Details'] ?? null) ? $metrics['Breaches_Details'] : [], 0, self::MAX_ENTRIES) as $e) {
            if (!is_array($e)) {
                continue;
            }
            $email = strtolower(trim(self::str($e['email'] ?? '', 254)));
            $domain = strtolower(trim(self::str($e['domain'] ?? '', 253), " \t."));
            $breach = self::str($e['breach'] ?? '', 120);
            if ($breach === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false || preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/', $domain) !== 1
                || !str_ends_with($email, '@' . $domain)) {
                continue; // malformed, or an address that isn't on the domain it is listed under
            }
            $exposures[] = ['email' => $email, 'domain' => $domain, 'breach' => $breach];
        }
        $breaches = [];
        foreach (is_array($metrics['Detailed_Breach_Info'] ?? null) ? $metrics['Detailed_Breach_Info'] : [] as $name => $info) {
            if (count($breaches) >= self::MAX_BREACHES || !is_string($name) || !is_array($info)) {
                continue;
            }
            $raw = $info['xposed_data'] ?? '';
            $classes = is_array($raw) ? $raw : explode(';', self::str($raw, 2000));
            $breaches[self::str($name, 120)] = [
                'date' => self::date($info['breached_date'] ?? ''),
                'data' => array_values(array_slice(array_filter(array_map(static fn ($c): string => self::str($c, 60), $classes), static fn (string $c): bool => $c !== ''), 0, 30)),
            ];
        }
        $domains = [];
        foreach (array_keys(is_array($metrics['Domain_Summary'] ?? null) ? $metrics['Domain_Summary'] : []) as $d) {
            $d = strtolower(self::str((string) $d, 253));
            if (preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/', $d) === 1 && count($domains) < 1000) {
                $domains[] = $d;
            }
        }
        return ['exposures' => $exposures, 'breaches' => $breaches, 'domains' => array_values(array_unique($domains))];
    }

    /** @return array<string,mixed> */
    private function post(string $path): array
    {
        $p = parse_url($this->baseUrl);
        if (!is_array($p) || !in_array($p['scheme'] ?? '', $this->allowHttp ? ['https', 'http'] : ['https'], true) || ($p['host'] ?? '') === '') {
            throw new XonException('The XposedOrNot address is not valid.');
        }
        $body = '';
        $ch = curl_init(rtrim($this->baseUrl, '/') . $path);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => '',
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'x-api-key: ' . $this->apiKey, 'Content-Length: 0'],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_PROTOCOLS => $this->allowHttp ? (CURLPROTO_HTTP | CURLPROTO_HTTPS) : CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'MSP-Sentinel',
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$body): int {
                $body .= $chunk;
                return strlen($body) > self::MAX_BYTES ? 0 : strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($ok === false) {
            throw new XonException('Could not reach XposedOrNot: ' . mb_substr($err, 0, 200));
        }
        $data = json_decode($body, true);
        if ($status !== 200 || !is_array($data)) {
            throw new XonException(match ($status) {
                401 => 'XposedOrNot refused the API key (wrong, reset or inactive), or the account has no verified domain.',
                429 => 'XposedOrNot asked Sentinel to slow down (its daily limit). Sentinel tries again later.',
                200 => 'XposedOrNot returned an unexpected answer.',
                default => 'XposedOrNot answered HTTP ' . $status . '.',
            });
        }
        return $data;
    }

    /** A value as plain text: no control characters, at most $max characters. */
    private static function str(mixed $v, int $max): string
    {
        return is_scalar($v) ? mb_substr(trim((string) preg_replace('/[\p{Cc}\p{Cf}]+/u', ' ', mb_convert_encoding((string) $v, 'UTF-8', 'UTF-8'))), 0, $max) : '';
    }

    /** A breach date as Y-m-d, or '' when it can't be read. */
    private static function date(mixed $v): string
    {
        $s = is_string($v) ? $v : '';
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})/', $s, $m) !== 1 || !checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
            return '';
        }
        $d = $m[1] . '-' . $m[2] . '-' . $m[3];
        return $d > gmdate('Y-m-d', time() + 86400) ? '' : $d; // a date in the future is a typo: treated as unknown
    }
}
