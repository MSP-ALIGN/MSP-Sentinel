<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

/**
 * NinjaOne as an inventory source, read-only, through the NinjaOne Public API 2.0.
 *
 * API facts used (from NinjaOne's published OpenAPI description, "NinjaRMM-API-v2" 2.0.9, and its
 * "Device Filters" article):
 * - Token: POST https://{instance}/ws/oauth/token, form fields grant_type=client_credentials, client_id,
 *   client_secret, scope=monitoring; answer {access_token, expires_in, token_type}. Calls send
 *   "Authorization: Bearer <token>".
 * - GET /v2/organizations?pageSize=&after= (after = last organisation ID): [{id, name, ...}].
 * - GET /v2/devices-detailed?df=org%20%3D%20{id}&pageSize=&after= (after = last device ID):
 *   [{id, systemName, displayName, dnsName, nodeClass, approvalStatus, os{name, buildNumber, releaseId},
 *   ipAddresses[], lastContact (Unix time)}].
 * - Reports with a cursor, all {cursor{name}, results[]} and filtered with df:
 *   /v2/queries/software (deviceId, name, publisher, version), /v2/queries/os-patches (pending, failed and
 *   rejected patches: id, deviceId, name, kbNumber, severity, status, timestamp),
 *   /v2/queries/antivirus-status (deviceId, productName, productState, definitionStatus),
 *   /v2/queries/volumes?include=bl (deviceId, driveLetter, bitLockerStatus{conversionStatus, protectionStatus}).
 *
 * Only the Monitoring scope is asked for (read-only). Sentinel never changes anything in NinjaOne.
 *
 * Grading is honest about unknowns: a value NinjaOne does not report stays '' (unknown), never "off" or
 * "missing". Antivirus is "missing" only for Windows workstations when the antivirus report worked and lists
 * nothing for that device (Windows servers have no Security Center, so no report there means unknown).
 * Network devices, phones and unmanaged devices are left out: their checks (antivirus, patches) don't apply.
 *
 * Security assumptions:
 * - The instance host is checked (a *.ninjarmm.com name) so the client secret is only ever sent to NinjaOne
 *   over verified HTTPS; redirects are not followed. The test suite may point it at a local mock (plain http).
 * - Every answer is untrusted: sizes are capped, JSON is decoded defensively and every value is cast;
 *   InventoryRepository cleans and shortens text before it is stored.
 * - Any failed page throws, so a sync never stores half the data as if it were everything (that would
 *   "resolve" findings that are still there). Hitting the page limit marks the snapshot incomplete instead.
 * - The client secret and token are never logged or put in an exception message.
 */
final class NinjaOneSource implements InventorySource
{
    /** Page size for every list (the API's pageSize parameter). */
    private const PAGE = 500;
    /** At most this many pages per list (500 x 200 = 100,000 rows), so a loop can never run away. */
    private const MAX_PAGES = 200;
    /** Largest answer accepted for one request. */
    private const MAX_BYTES = 33554432;

    private ?string $token = null;
    private int $tokenExpires = 0;

    /**
     * @param string $host     NinjaOne instance, e.g. app.ninjarmm.com (see validHost()).
     * @param string $baseUrl  Test suite only: a local mock base URL (plain http allowed); '' in production.
     * @param int    $pageSize Rows per page (tests use a small one to exercise paging).
     */
    public function __construct(private readonly string $host, private readonly string $clientId, private readonly string $clientSecret,
        private readonly string $baseUrl = '', private readonly int $pageSize = self::PAGE)
    {
    }

    /** Whether a host name looks like a NinjaOne instance (letters, digits and dashes, then .ninjarmm.com). */
    public static function validHost(string $host): bool
    {
        return preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.ninjarmm\.com$/', $host) === 1;
    }

    /** {@inheritDoc} */
    public function name(): string
    {
        return 'ninjaone';
    }

    /** {@inheritDoc} */
    public function label(): string
    {
        return 'NinjaOne';
    }

    /** {@inheritDoc} */
    public function organisations(): array
    {
        $out = [];
        $after = null;
        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            $rows = $this->getJson('/v2/organizations', ['pageSize' => $this->pageSize] + ($after === null ? [] : ['after' => $after]));
            if (!array_is_list($rows)) {
                throw new InventoryException('NinjaOne returned an unexpected organisation list.');
            }
            foreach ($rows as $o) {
                if (is_array($o) && is_int($o['id'] ?? null)) {
                    $out[] = ['id' => (string) $o['id'], 'name' => is_string($o['name'] ?? null) ? $o['name'] : ('#' . $o['id'])];
                    $after = $o['id'];
                }
            }
            if (count($rows) < $this->pageSize) {
                break;
            }
        }
        return $out;
    }

    /**
     * For "Test connection": signs in and lists organisations. Returns how many organisations the app can see;
     * throws InventoryException with NinjaOne's reason otherwise.
     */
    public function testConnection(): int
    {
        $this->accessToken();
        return count($this->organisations());
    }

    /** {@inheritDoc} */
    public function snapshot(string $orgId): array
    {
        if (!ctype_digit($orgId) || strlen($orgId) > 10) {
            throw new InventoryException('Not a NinjaOne organisation ID.');
        }
        $df = 'org = ' . $orgId;
        $complete = true;

        // Devices (only approved computers: workstations and servers).
        $devices = [];
        $after = null;
        for ($page = 0; ; $page++) {
            if ($page >= self::MAX_PAGES) {
                $complete = false;
                break;
            }
            $rows = $this->getJson('/v2/devices-detailed', ['df' => $df, 'pageSize' => $this->pageSize] + ($after === null ? [] : ['after' => $after]));
            if (!array_is_list($rows)) {
                throw new InventoryException('NinjaOne returned an unexpected device list.');
            }
            foreach ($rows as $d) {
                if (!is_array($d) || !is_int($d['id'] ?? null)) {
                    continue;
                }
                $after = $d['id'];
                $class = self::deviceClass((string) ($d['nodeClass'] ?? ''));
                if ($class === null || (string) ($d['approvalStatus'] ?? 'APPROVED') !== 'APPROVED') {
                    continue;
                }
                $os = is_array($d['os'] ?? null) ? $d['os'] : [];
                $devices[$d['id']] = [
                    'source_id' => (string) $d['id'],
                    'name' => self::str($d['systemName'] ?? '') ?: self::str($d['displayName'] ?? ''),
                    'dns_name' => self::str($d['dnsName'] ?? ''),
                    'device_class' => $class,
                    'node_class' => (string) ($d['nodeClass'] ?? ''),
                    'os_name' => self::str($os['name'] ?? ''),
                    'os_build' => self::str($os['buildNumber'] ?? ''),
                    'os_release' => self::str($os['releaseId'] ?? ''),
                    'ip_addresses' => array_values(array_filter(array_map([self::class, 'str'], is_array($d['ipAddresses'] ?? null) ? $d['ipAddresses'] : []))),
                    'last_contact' => is_numeric($d['lastContact'] ?? null) ? (int) $d['lastContact'] : null,
                    'av_product' => '', 'av_state' => '', 'av_definitions' => '', 'encryption' => '',
                    'software' => [], 'patches' => [],
                ];
            }
            if (count($rows) < $this->pageSize) {
                break;
            }
        }
        if ($devices === []) {
            return ['devices' => [], 'complete' => $complete];
        }

        // Installed software.
        $complete = $this->eachResult('/v2/queries/software', ['df' => $df], function (array $r) use (&$devices): void {
            $id = $r['deviceId'] ?? null;
            if (is_int($id) && isset($devices[$id]) && self::str($r['name'] ?? '') !== '') {
                $devices[$id]['software'][] = ['name' => self::str($r['name']), 'publisher' => self::str($r['publisher'] ?? ''), 'version' => self::str($r['version'] ?? '')];
            }
        }) && $complete;

        // Missing OS patches (the report lists pending, failed and rejected ones; rejected were declined on purpose).
        $complete = $this->eachResult('/v2/queries/os-patches', ['df' => $df], function (array $r) use (&$devices): void {
            $id = $r['deviceId'] ?? null;
            $status = strtoupper(self::str($r['status'] ?? ''));
            if (!is_int($id) || !isset($devices[$id]) || str_contains($status, 'REJECT')) {
                return;
            }
            $devices[$id]['patches'][] = [
                'patch_id' => self::str($r['id'] ?? '') ?: hash('sha256', self::str($r['name'] ?? '') . '|' . self::str($r['kbNumber'] ?? '')),
                'name' => self::str($r['name'] ?? ''), 'kb' => self::str($r['kbNumber'] ?? ''), 'severity' => self::str($r['severity'] ?? ''),
                'status' => str_contains($status, 'FAIL') ? 'failed' : 'pending',
                'detected_at' => is_numeric($r['timestamp'] ?? null) ? (int) $r['timestamp'] : null,
            ];
        }) && $complete;

        // Antivirus: on if any product reports on; definitions outdated if any reports out of date.
        $avSeen = [];
        $avOk = $this->eachResult('/v2/queries/antivirus-status', ['df' => $df], function (array $r) use (&$devices, &$avSeen): void {
            $id = $r['deviceId'] ?? null;
            if (!is_int($id) || !isset($devices[$id])) {
                return;
            }
            $avSeen[$id] = true;
            $state = strtoupper(self::str($r['productState'] ?? ''));
            $defs = strtoupper(self::str($r['definitionStatus'] ?? ''));
            $on = in_array($state, ['ON', 'ENABLED', 'ACTIVE', 'RUNNING'], true);
            $off = in_array($state, ['OFF', 'DISABLED', 'SNOOZED', 'EXPIRED', 'STOPPED'], true);
            $d = &$devices[$id];
            if ($on || $d['av_state'] === '') {
                $d['av_product'] = self::str($r['productName'] ?? '');
            }
            $d['av_state'] = $on ? 'on' : ($d['av_state'] === 'on' ? 'on' : ($off ? 'off' : $d['av_state']));
            if (str_contains($defs, 'OUT')) {
                $d['av_definitions'] = 'outdated';
            } elseif ($d['av_definitions'] === '' && (str_contains($defs, 'UP_TO_DATE') || str_contains($defs, 'UPTODATE') || $defs === 'CURRENT')) {
                $d['av_definitions'] = 'current';
            }
            unset($d);
        });
        if ($avOk) {
            foreach ($devices as $id => &$d) {
                if (!isset($avSeen[$id]) && $d['node_class'] === 'WINDOWS_WORKSTATION') {
                    $d['av_state'] = 'missing'; // the report worked and lists nothing for this Windows workstation
                }
            }
            unset($d);
        }
        $complete = $avOk && $complete;

        // Disk encryption from BitLocker on the system drive (C:); other systems stay unknown.
        $complete = $this->eachResult('/v2/queries/volumes', ['df' => $df, 'include' => 'bl'], function (array $r) use (&$devices): void {
            $id = $r['deviceId'] ?? null;
            if (!is_int($id) || !isset($devices[$id]) || strtoupper(rtrim(self::str($r['driveLetter'] ?? ''), ':\\')) !== 'C' || !is_array($r['bitLockerStatus'] ?? null)) {
                return;
            }
            $bl = $r['bitLockerStatus'];
            $conv = (string) ($bl['conversionStatus'] ?? '');
            $prot = (string) ($bl['protectionStatus'] ?? '');
            $devices[$id]['encryption'] = $prot === 'PROTECTED' || $conv === 'FULLY_ENCRYPTED' ? 'on'
                : ($prot === 'UNPROTECTED' && in_array($conv, ['FULLY_DECRYPTED', 'DECRYPTION_IN_PROGRESS', 'DECRYPTION_PAUSED'], true) ? 'off' : '');
        }) && $complete;

        foreach ($devices as &$d) {
            unset($d['node_class']);
        }
        unset($d);
        return ['devices' => array_values($devices), 'complete' => $complete];
    }

    /** Sentinel's device class for a NinjaOne nodeClass, or null for devices whose checks don't apply. */
    private static function deviceClass(string $nodeClass): ?string
    {
        return match ($nodeClass) {
            'WINDOWS_WORKSTATION', 'MAC', 'LINUX_WORKSTATION' => 'workstation',
            'WINDOWS_SERVER', 'LINUX_SERVER', 'MAC_SERVER', 'HYPERV_VMM_HOST' => 'server',
            default => null,
        };
    }

    /**
     * Walk a cursor report: first page with the filter, then the cursor name, until a short page.
     *
     * @param callable(array<string,mixed>):void $each
     * @return bool false when the page limit was hit (the data is incomplete)
     */
    private function eachResult(string $path, array $query, callable $each): bool
    {
        $cursor = null;
        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            $data = $this->getJson($path, $query + ['pageSize' => $this->pageSize] + ($cursor === null ? [] : ['cursor' => $cursor]));
            $results = is_array($data['results'] ?? null) ? $data['results'] : null;
            if ($results === null || !array_is_list($results)) {
                throw new InventoryException('NinjaOne returned an unexpected answer for ' . $path . '.');
            }
            foreach ($results as $r) {
                if (is_array($r)) {
                    $each($r);
                }
            }
            $next = is_array($data['cursor'] ?? null) && is_string($data['cursor']['name'] ?? null) ? $data['cursor']['name'] : '';
            if (count($results) < $this->pageSize || $next === '' || $next === $cursor) {
                return true;
            }
            $cursor = $next;
        }
        return false;
    }

    /** A bearer token (cached until a minute before it expires). */
    private function accessToken(): string
    {
        if ($this->token !== null && time() < $this->tokenExpires - 60) {
            return $this->token;
        }
        [$status, $body] = $this->request('POST', '/ws/oauth/token', null, http_build_query([
            'grant_type' => 'client_credentials', 'client_id' => $this->clientId, 'client_secret' => $this->clientSecret, 'scope' => 'monitoring',
        ]));
        $data = json_decode($body, true);
        if ($status !== 200 || !is_array($data) || !is_string($data['access_token'] ?? null) || $data['access_token'] === '') {
            $why = is_array($data) && is_string($data['error_description'] ?? null) ? $data['error_description'] : (is_array($data) && is_string($data['error'] ?? null) ? $data['error'] : 'HTTP ' . $status);
            throw new InventoryException('NinjaOne sign-in failed: ' . mb_substr(preg_replace('/[^\P{C}]/u', '', $why) ?? '', 0, 200) . '. Check the instance, client ID, secret, and that the app has the Monitoring scope and the Client credentials grant.');
        }
        $this->token = $data['access_token'];
        $this->tokenExpires = time() + max(60, min(86400, (int) ($data['expires_in'] ?? 3600)));
        return $this->token;
    }

    /**
     * GET a JSON answer with the bearer token.
     *
     * @param array<string,int|string> $query
     * @return array<mixed>
     */
    private function getJson(string $path, array $query): array
    {
        [$status, $body] = $this->request('GET', $path, $this->accessToken(), '', $query);
        if ($status === 401) {
            $this->token = null; // expired early: one fresh try
            [$status, $body] = $this->request('GET', $path, $this->accessToken(), '', $query);
        }
        if ($status === 429) {
            throw new InventoryException('NinjaOne asked Sentinel to slow down (rate limit). The next sync tries again.');
        }
        if ($status !== 200) {
            throw new InventoryException('NinjaOne answered HTTP ' . $status . ' for ' . $path . ($status === 403 ? ' (the API app needs the Monitoring scope)' : '') . '.');
        }
        $data = json_decode($body, true);
        if (!is_array($data)) {
            throw new InventoryException('NinjaOne returned something that is not JSON for ' . $path . '.');
        }
        return $data;
    }

    /**
     * One HTTPS request to the instance.
     *
     * @param array<string,int|string> $query
     * @return array{0:int,1:string} status and body
     */
    private function request(string $method, string $path, ?string $token, string $form, array $query = []): array
    {
        if ($this->baseUrl === '' && !self::validHost($this->host)) {
            throw new InventoryException('The NinjaOne instance must be a *.ninjarmm.com address (Administration, Integrations).');
        }
        $base = $this->baseUrl !== '' ? rtrim($this->baseUrl, '/') : 'https://' . $this->host;
        $url = $base . $path . ($query === [] ? '' : '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986));
        $body = '';
        $ch = curl_init($url);
        $headers = ['Accept: application/json'];
        if ($token !== null) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }
        $opts = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 120,
            CURLOPT_PROTOCOLS => $this->baseUrl !== '' ? (CURLPROTO_HTTP | CURLPROTO_HTTPS) : CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'MSP-Sentinel',
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$body): int {
                $body .= $chunk;
                return strlen($body) > self::MAX_BYTES ? 0 : strlen($chunk);
            },
        ];
        if ($method === 'POST') {
            $opts[CURLOPT_POSTFIELDS] = $form;
            $opts[CURLOPT_HTTPHEADER][] = 'Content-Type: application/x-www-form-urlencoded';
        }
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($ok === false) {
            throw new InventoryException(strlen($body) > self::MAX_BYTES ? 'NinjaOne sent more data than Sentinel accepts in one answer.' : 'Could not reach NinjaOne: ' . mb_substr($err, 0, 200));
        }
        return [$status, $body];
    }

    /** A scalar from the API as a trimmed string ('' for anything else). */
    private static function str(mixed $v): string
    {
        return is_scalar($v) ? trim((string) $v) : '';
    }
}
