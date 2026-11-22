<?php

declare(strict_types=1);

namespace Sentinel\Itflow;

/**
 * Talks to ITFlow's API (v1). Phase 1 only reads clients; tickets follow in later phases (docs/ROADMAP-itflow.md).
 *
 * API facts used (ITFlow's own source: api/v1/validate_api_key.php, clients/read.php, read_output.php,
 * functions/api_keys.php):
 * - The key goes in the X-API-Key header (ITFlow keeps it out of web server logs that way). Keys are tied to an ITFlow
 *   user and follow that user's role and client access.
 * - GET /api/v1/clients/read.php?limit=&offset=  ->  {"success":"True","count":n,"data":[{client_id, client_name,
 *   client_archived_at, client_updated_at, ...}]}. Archived clients are included. No match answers
 *   {"success":"False","message":"No resource ..."} with HTTP 200, which is an empty page, not an error.
 * - A wrong or expired key answers HTTP 401.
 *
 * Security assumptions:
 * - The address is ITFlow's, entered by an admin (it may be an internal host: both are self-hosted). Only https,
 *   verified certificates and no redirects, so the key is only ever sent to that address; plain http only in the
 *   test suite.
 * - Every answer is untrusted: sizes and pages are capped, values are cast; Sentinel cleans names before storing.
 * - The key is never logged or put in an exception message.
 */
final class ItflowClient
{
    private const PAGE = 200;
    private const MAX_PAGES = 500;
    private const MAX_BYTES = 16777216;

    /** @param bool $allowHttp Test suite only. */
    public function __construct(private readonly string $baseUrl, private readonly string $apiKey, private readonly bool $allowHttp = false)
    {
    }

    /** Whether an address is acceptable: https://host[:port][/path], no credentials, query or fragment. */
    public static function validUrl(string $url, bool $allowHttp = false): bool
    {
        $p = parse_url($url);
        return is_array($p) && in_array($p['scheme'] ?? '', $allowHttp ? ['https', 'http'] : ['https'], true) && ($p['host'] ?? '') !== ''
            && !isset($p['user']) && !isset($p['pass']) && !isset($p['query']) && !isset($p['fragment'])
            && preg_match('/^[A-Za-z0-9.-]{1,253}$|^\[[0-9A-Fa-f:.]+\]$/', (string) $p['host']) === 1;
    }

    /** Whether a string can be an ITFlow API key (printable, no spaces; ITFlow's own format may change). */
    public static function validKey(string $key): bool
    {
        return preg_match('/^[A-Za-z0-9._~+\/=-]{16,200}$/', $key) === 1;
    }

    /**
     * Every client the key can see, archived ones included.
     *
     * @return list<array{id:int, name:string, archived:bool}>
     */
    public function clients(): array
    {
        $out = [];
        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            $rows = $this->read('/api/v1/clients/read.php', ['limit' => self::PAGE, 'offset' => $page * self::PAGE]);
            foreach ($rows as $r) {
                if (is_array($r) && is_numeric($r['client_id'] ?? null) && (int) $r['client_id'] > 0) {
                    $out[(int) $r['client_id']] = ['id' => (int) $r['client_id'], 'name' => is_scalar($r['client_name'] ?? null) ? trim((string) $r['client_name']) : '',
                        'archived' => is_string($r['client_archived_at'] ?? null) && $r['client_archived_at'] !== '' && !str_starts_with($r['client_archived_at'], '0000')];
                }
            }
            if (count($rows) < self::PAGE) {
                return array_values($out);
            }
        }
        throw new ItflowException('ITFlow returned more clients than Sentinel reads in one sync.');
    }

    /**
     * A read endpoint's rows ([] for ITFlow's "No resource" answer).
     *
     * @param array<string,int|string> $query
     * @return list<mixed>
     */
    private function read(string $path, array $query): array
    {
        if (!self::validUrl($this->baseUrl, $this->allowHttp)) {
            throw new ItflowException('The ITFlow address must be an https:// address (Administration, Integrations).');
        }
        $body = '';
        $ch = curl_init(rtrim($this->baseUrl, '/') . $path . '?' . http_build_query($query));
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'X-API-Key: ' . $this->apiKey],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 30,
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
            throw new ItflowException('Could not reach ITFlow: ' . mb_substr($err, 0, 200));
        }
        if ($status === 401) {
            throw new ItflowException('ITFlow refused the API key (wrong or expired).');
        }
        if ($status === 403) {
            throw new ItflowException('The ITFlow API key\'s user may not read clients (check the user\'s role in ITFlow).');
        }
        $data = json_decode($body, true);
        if ($status !== 200 || !is_array($data)) {
            throw new ItflowException('ITFlow answered HTTP ' . $status . ' for ' . $path . ' (is this the ITFlow address?).');
        }
        if (($data['success'] ?? '') === 'True') {
            return is_array($data['data'] ?? null) && array_is_list($data['data']) ? $data['data'] : [];
        }
        $msg = is_string($data['message'] ?? null) ? $data['message'] : '';
        if (str_starts_with($msg, 'No resource')) {
            return []; // ITFlow's way of saying "nothing (more) here"
        }
        throw new ItflowException('ITFlow refused the request: ' . mb_substr((string) preg_replace('/[^\P{C}]/u', '', $msg), 0, 200));
    }
}
