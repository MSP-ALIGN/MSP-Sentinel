<?php

declare(strict_types=1);

namespace Sentinel\Compliance;

/**
 * Reads compliance data from MSP Align's public API (v1), read-only. Sentinel never writes to MSP Align.
 *
 * API facts used (MSP Align src/Api/Routes.php, Resources/Clients.php and Resources/Compliance.php, docs/API.md):
 * - Base path /api/v1; "Authorization: Bearer msa_<8>_<32>"; lists are {"data":[...],"meta":{page,per_page,total,
 *   has_more}} with ?page and ?per_page (max 200).
 * - GET /api/v1/                                  key info: name, scopes, client_ids, api_version
 * - GET /api/v1/clients                           id, name, psa_id, url
 * - GET /api/v1/clients/{id}/compliance           assigned frameworks: framework_id, framework, slug, score{...}, url
 * - GET /api/v1/clients/{id}/compliance/{fw}/controls   id, ref, section, title, crosswalk_tags[], status, url-less
 * The key needs clients:read and compliance:read; a read-only key is recommended.
 *
 * Security assumptions:
 * - The address is MSP Align's, entered by an admin (it may be an internal host: both are self-hosted). Only https,
 *   with verified certificates and no redirects, so the API key is only ever sent to that address; plain http only
 *   in the test suite.
 * - Every answer is untrusted: sizes and page counts are capped, JSON is decoded defensively and every value is cast;
 *   views escape everything.
 * - The API key is never logged or put in an exception message.
 */
final class AlignClient
{
    private const PER_PAGE = 200;
    private const MAX_PAGES = 100;
    private const MAX_BYTES = 16777216;
    /** All answers of one AlignClient together may be at most this big. */
    private const MAX_TOTAL_BYTES = 33554432;

    private int $totalBytes = 0;

    /** @param bool $allowHttp Test suite only. */
    public function __construct(private readonly string $baseUrl, private readonly string $apiKey, private readonly bool $allowHttp = false)
    {
    }

    /** Whether an address is acceptable: https://host[:port][/path], no query, no credentials. */
    public static function validUrl(string $url, bool $allowHttp = false): bool
    {
        $p = parse_url($url);
        return is_array($p) && in_array($p['scheme'] ?? '', $allowHttp ? ['https', 'http'] : ['https'], true) && ($p['host'] ?? '') !== ''
            && !isset($p['user']) && !isset($p['pass']) && !isset($p['query']) && !isset($p['fragment'])
            && preg_match('/^[A-Za-z0-9.-]{1,253}$|^\[[0-9A-Fa-f:.]+\]$/', (string) $p['host']) === 1;
    }

    /** Whether an API key looks like an MSP Align key. */
    public static function validKey(string $key): bool
    {
        return preg_match('/^msa_[A-Za-z0-9]{8}_[A-Za-z0-9]{32}$/', $key) === 1;
    }

    /**
     * The key's own description (for "Test connection").
     *
     * @return array{name:string, scopes:list<string>, app_version:string}
     */
    public function whoami(): array
    {
        $d = $this->get('/api/v1/', [])['data'] ?? null;
        if (!is_array($d)) {
            throw new AlignException('MSP Align returned an unexpected answer. Check the address.');
        }
        return ['name' => self::str($d['name'] ?? ''), 'scopes' => array_values(array_filter(array_map([self::class, 'str'], is_array($d['scopes'] ?? null) ? $d['scopes'] : []))),
                'app_version' => self::str($d['app_version'] ?? '')];
    }

    /** @return list<array{id:int, name:string, psa_id:string}> psa_id: the client's PSA (e.g. ITFlow) ID in MSP Align, or ''. */
    public function clients(): array
    {
        return array_values(array_filter(array_map(static fn ($c): ?array => is_array($c) && is_int($c['id'] ?? null)
            ? ['id' => $c['id'], 'name' => self::str($c['name'] ?? ''), 'psa_id' => self::str($c['psa_id'] ?? '')] : null, $this->all('/api/v1/clients', ['include_excluded' => 'true']))));
    }

    /** @return list<array{framework_id:int, framework:string, slug:string, score:int, url:string}> */
    public function assessments(int $clientId): array
    {
        return array_values(array_filter(array_map(static fn ($a): ?array => is_array($a) && is_int($a['framework_id'] ?? null) ? [
            'framework_id' => $a['framework_id'], 'framework' => self::str($a['framework'] ?? ''), 'slug' => self::str($a['slug'] ?? ''),
            'score' => is_array($a['score'] ?? null) && is_int($a['score']['percent'] ?? null) ? $a['score']['percent'] : 0,
            'url' => self::str($a['url'] ?? ''),
        ] : null, $this->all('/api/v1/clients/' . $clientId . '/compliance'))));
    }

    /** @return list<array{id:int, ref:string, section:string, title:string, tags:list<string>, status:string}> */
    public function controls(int $clientId, int $frameworkId): array
    {
        return array_values(array_filter(array_map(static fn ($c): ?array => is_array($c) && is_int($c['id'] ?? null) ? [
            'id' => $c['id'], 'ref' => self::str($c['ref'] ?? ''), 'section' => self::str($c['section'] ?? ''), 'title' => self::str($c['title'] ?? ''),
            'tags' => array_values(array_filter(array_map(static fn ($t): string => preg_match('/^[a-z0-9_]{2,40}$/', (string) $t) === 1 ? (string) $t : '',
                is_array($c['crosswalk_tags'] ?? null) ? $c['crosswalk_tags'] : []))),
            'status' => in_array($c['status'] ?? '', ['not_assessed', 'met', 'partial', 'not_met', 'na'], true) ? (string) $c['status'] : 'not_assessed',
        ] : null, $this->all('/api/v1/clients/' . $clientId . '/compliance/' . $frameworkId . '/controls'))));
    }

    /**
     * Every page of a list.
     *
     * @param array<string,string> $query
     * @return list<mixed>
     */
    private function all(string $path, array $query = []): array
    {
        $out = [];
        for ($page = 1; $page <= self::MAX_PAGES; $page++) {
            $res = $this->get($path, $query + ['page' => $page, 'per_page' => self::PER_PAGE]);
            if (!is_array($res['data'] ?? null) || !array_is_list($res['data'])) {
                throw new AlignException('MSP Align returned an unexpected list for ' . $path . '.');
            }
            array_push($out, ...$res['data']);
            if (($res['meta']['has_more'] ?? false) !== true || $res['data'] === []) {
                return $out;
            }
        }
        throw new AlignException('MSP Align returned more pages than Sentinel reads for ' . $path . '.');
    }

    /**
     * One GET with the key.
     *
     * @param array<string,int|string> $query
     * @return array<mixed>
     */
    private function get(string $path, array $query): array
    {
        if (!self::validUrl($this->baseUrl, $this->allowHttp)) {
            throw new AlignException('The MSP Align address must be an https:// address (Administration, Integrations).');
        }
        $url = rtrim($this->baseUrl, '/') . $path . ($query === [] ? '' : '?' . http_build_query($query));
        $body = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'Authorization: Bearer ' . $this->apiKey],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 10,
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
            throw new AlignException('Could not reach MSP Align: ' . mb_substr($err, 0, 200));
        }
        $this->totalBytes += strlen($body);
        if ($this->totalBytes > self::MAX_TOTAL_BYTES) {
            throw new AlignException('MSP Align returned more data than Sentinel reads in one go.');
        }
        $data = json_decode($body, true);
        if ($status !== 200 || !is_array($data)) {
            $msg = is_array($data) && is_array($data['error'] ?? null) && is_string($data['error']['message'] ?? null) ? mb_substr((string) preg_replace('/[^\P{C}]/u', '', $data['error']['message']), 0, 200) : '';
            throw new AlignException(match ($status) {
                401 => 'MSP Align refused the API key (wrong, expired, or its admin was deactivated).',
                403 => 'The MSP Align API key is missing a permission (it needs clients:read and compliance:read), or the client is outside the key.',
                404 => 'MSP Align answered "not found" for ' . $path . ' (is the API turned on, is the client still active there, and is the framework still assigned?).',
                429 => 'MSP Align asked Sentinel to slow down. Try again in a minute.',
                default => 'MSP Align answered HTTP ' . $status . ($msg !== '' ? ': ' . $msg : '') . '.',
            });
        }
        return $data;
    }

    /** A scalar as a trimmed string ('' for anything else). */
    private static function str(mixed $v): string
    {
        return is_scalar($v) ? trim((string) $v) : '';
    }
}
