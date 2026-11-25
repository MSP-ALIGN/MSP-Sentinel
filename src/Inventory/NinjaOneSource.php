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
 *   /v2/queries/software (deviceId, name, publisher, version), /v2/queries/os-patches (patches with no
 *   installation attempt: id, deviceId, name, kbNumber, severity, status), /v2/queries/os-patch-installs?status=FAILED
 *   (failed attempts: id, deviceId, kbNumber, installedAt),
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
 * - Any failed page, a page limit hit or a server that stops moving through pages throws, so a sync never stores
 *   half the data as if it were everything (that would "resolve" findings that are still there).
 * - The client secret and token are never logged or put in an exception message.
 */
final class NinjaOneSource implements InventorySource
{
    /** Page size for every list (the API's pageSize parameter). */
    private const PAGE = 500;
    /** At most this many pages per list (500 x 4,000 = 2 million rows); hitting it fails the sync, never truncates it. */
    private const MAX_PAGES = 4000;
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
        // Until an empty page (not a short one: the server may cap pageSize below what was asked).
        for ($page = 0; ; $page++) {
            if ($page >= self::MAX_PAGES) {
                throw new InventoryException('NinjaOne returned more organisations than Sentinel reads in one go.');
            }
            $rows = $this->getJson('/v2/organizations', ['pageSize' => $this->pageSize] + ($after === null ? [] : ['after' => $after]));
            if (!array_is_list($rows)) {
                throw new InventoryException('NinjaOne returned an unexpected organisation list.');
            }
            $before = $after;
            foreach ($rows as $o) {
                if (is_array($o) && is_int($o['id'] ?? null)) {
                    $out[$o['id']] = ['id' => (string) $o['id'], 'name' => is_string($o['name'] ?? null) ? $o['name'] : ('#' . $o['id'])];
                    $after = max($after ?? 0, $o['id']);
                }
            }
            if ($rows === [] || $after === $before) {
                break; // done (or the server ignored "after": stop rather than loop)
            }
        }
        return array_values($out);
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

        // Devices (only approved computers: workstations and servers).
        $devices = [];
        $after = null;
        for ($page = 0; ; $page++) {
            if ($page >= self::MAX_PAGES) {
                throw new InventoryException('NinjaOne returned more devices than Sentinel reads in one sync.');
            }
            $rows = $this->getJson('/v2/devices-detailed', ['df' => $df, 'pageSize' => $this->pageSize] + ($after === null ? [] : ['after' => $after]));
            if (!array_is_list($rows)) {
                throw new InventoryException('NinjaOne returned an unexpected device list.');
            }
            $before = $after;
            foreach ($rows as $d) {
                if (!is_array($d) || !is_int($d['id'] ?? null)) {
                    continue;
                }
                $after = max($after ?? 0, $d['id']);
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
                    // MAC addresses (1.50): matched against the agent's devices first. Normalised; anything else dropped.
                    'mac_addresses' => array_values(array_unique(array_filter(array_map([self::class, 'mac'],
                        is_array($d['macAddresses'] ?? null) ? array_slice($d['macAddresses'], 0, 20) : [])))),
                    'last_contact' => is_numeric($d['lastContact'] ?? null) ? (int) $d['lastContact'] : null,
                    'av_product' => '', 'av_state' => '', 'av_definitions' => '', 'encryption' => '',
                    'software' => [], 'patches' => [],
                ];
            }
            if ($rows === [] || $after === $before) {
                break; // an empty page ends the list (a short one may only mean the server caps pageSize)
            }
        }
        if ($devices === []) {
            return ['devices' => [], 'complete' => true];
        }

        // Installed software.
        $this->eachResult('/v2/queries/software', ['df' => $df], function (array $r) use (&$devices): void {
            $id = $r['deviceId'] ?? null;
            if (is_int($id) && isset($devices[$id]) && self::str($r['name'] ?? '') !== '') {
                $devices[$id]['software'][] = ['name' => self::str($r['name']), 'publisher' => self::str($r['publisher'] ?? ''), 'version' => self::str($r['version'] ?? '')];
            }
        });

        // Failed installation attempts in the last 30 days (os-patch-installs?status=FAILED), by device and patch.
        $failedInstalls = [];
        $this->eachResult('/v2/queries/os-patch-installs', ['df' => $df, 'status' => 'FAILED'], function (array $r) use (&$failedInstalls): void {
            $id = $r['deviceId'] ?? null;
            $at = is_numeric($r['installedAt'] ?? null) ? (int) $r['installedAt'] : 0;
            if (is_int($id) && $at > time() - 30 * 86400 && strtoupper(self::str($r['status'] ?? '')) === 'FAILED') {
                foreach ([self::str($r['id'] ?? ''), self::str($r['kbNumber'] ?? '')] as $key) {
                    if ($key !== '') {
                        $failedInstalls[$id][$key] = true;
                    }
                }
            }
        });
        // Missing OS patches: "patches for which there were no installation attempts" (pending, failed and rejected
        // states; rejected were declined on purpose). Its timestamp is when the data was collected, not when the patch
        // appeared, so no detection date is passed: Sentinel counts from when it first saw the patch.
        $this->eachResult('/v2/queries/os-patches', ['df' => $df], function (array $r) use (&$devices, $failedInstalls): void {
            $id = $r['deviceId'] ?? null;
            $status = strtoupper(self::str($r['status'] ?? ''));
            if (!is_int($id) || !isset($devices[$id]) || str_contains($status, 'REJECT')) {
                return;
            }
            $devices[$id]['patches'][] = [
                'patch_id' => self::str($r['id'] ?? '') ?: hash('sha256', self::str($r['name'] ?? '') . '|' . self::str($r['kbNumber'] ?? '')),
                'name' => self::str($r['name'] ?? ''), 'kb' => self::str($r['kbNumber'] ?? ''), 'severity' => self::str($r['severity'] ?? ''),
                'status' => str_contains($status, 'FAIL') || isset($failedInstalls[$id][self::str($r['id'] ?? '')]) || isset($failedInstalls[$id][self::str($r['kbNumber'] ?? '')])
                    ? 'failed' : 'pending',
                'detected_at' => null,
            ];
        });

        // Antivirus: on if any product reports on; definitions outdated if any reports out of date.
        $avSeen = [];
        $this->eachResult('/v2/queries/antivirus-status', ['df' => $df], function (array $r) use (&$devices, &$avSeen): void {
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
            if (in_array($defs, ['OUT_OF_DATE', 'OUTDATED'], true)) {
                $d['av_definitions'] = 'outdated';
            } elseif ($d['av_definitions'] === '' && (str_contains($defs, 'UP_TO_DATE') || str_contains($defs, 'UPTODATE') || $defs === 'CURRENT')) {
                $d['av_definitions'] = 'current';
            }
            unset($d);
        });
        // "Missing" only for a Windows workstation the report lists nothing for, that was online in the last week and
        // whose inventory has arrived (installed software): a new or long-offline device is unknown, not unprotected.
        // An antivirus report with no rows at all (1.49) is a gap in the data, not proof that nothing has antivirus.
        foreach ($devices as $id => &$d) {
            if ($avSeen !== [] && !isset($avSeen[$id]) && $d['node_class'] === 'WINDOWS_WORKSTATION' && $d['software'] !== []
                && $d['last_contact'] !== null && $d['last_contact'] > time() - 7 * 86400) {
                $d['av_state'] = 'missing';
            }
        }
        unset($d);

        // Disk encryption from BitLocker on the system drive (C:); other systems stay unknown.
        $this->eachResult('/v2/queries/volumes', ['df' => $df, 'include' => 'bl'], function (array $r) use (&$devices): void {
            $id = $r['deviceId'] ?? null;
            if (!is_int($id) || !isset($devices[$id]) || strtoupper(rtrim(self::str($r['driveLetter'] ?? ''), ':\\')) !== 'C' || !is_array($r['bitLockerStatus'] ?? null)) {
                return;
            }
            $bl = $r['bitLockerStatus'];
            $conv = (string) ($bl['conversionStatus'] ?? '');
            $prot = (string) ($bl['protectionStatus'] ?? '');
            // On only when protected (an encrypted drive with protection suspended is unknown, not on or off).
            $devices[$id]['encryption'] = $prot === 'PROTECTED' ? 'on'
                : ($prot === 'UNPROTECTED' && in_array($conv, ['FULLY_DECRYPTED', 'DECRYPTION_IN_PROGRESS', 'DECRYPTION_PAUSED'], true) ? 'off' : '');
        });

        foreach ($devices as &$d) {
            unset($d['node_class']);
        }
        unset($d);
        return ['devices' => array_values($devices), 'complete' => true]; // anything less has thrown above
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
     * Walk a cursor report: the first page with the filter, then each next page with the cursor name, until an empty
     * page. The API documents the cursor object but not how paging ends, so: an empty page ends it, the cursor name is
     * never taken as a sign of the end, a page identical to the one before is an error (the server isn't moving on),
     * and too many pages is an error. Any of these errors fails the sync instead of saving part of the data.
     *
     * @param callable(array<string,mixed>):void $each
     */
    private function eachResult(string $path, array $query, callable $each): void
    {
        $cursor = null;
        $previous = null;
        for ($page = 0; ; $page++) {
            if ($page >= self::MAX_PAGES) {
                throw new InventoryException('NinjaOne returned more data for ' . $path . ' than Sentinel reads in one sync.');
            }
            // The filter goes with every page (harmless if the cursor already carries it).
            $data = $this->getJson($path, $query + ['pageSize' => $this->pageSize] + ($cursor === null ? [] : ['cursor' => $cursor]));
            $results = is_array($data['results'] ?? null) ? $data['results'] : null;
            if ($results === null || !array_is_list($results)) {
                throw new InventoryException('NinjaOne returned an unexpected answer for ' . $path . '.');
            }
            if ($results === []) {
                return;
            }
            $fingerprint = hash('sha256', json_encode($results) ?: '');
            if ($fingerprint === $previous) {
                throw new InventoryException('NinjaOne returned the same page twice for ' . $path . '; the sync was stopped so nothing is saved half-read.');
            }
            $previous = $fingerprint;
            foreach ($results as $r) {
                if (is_array($r)) {
                    $each($r);
                }
            }
            $next = is_array($data['cursor'] ?? null) && is_string($data['cursor']['name'] ?? null) ? $data['cursor']['name'] : '';
            if ($next === '') {
                return; // no cursor to continue with: this was the only page
            }
            $cursor = $next;
        }
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
            CURLOPT_TIMEOUT => 60,
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

    /**
     * One MAC address from NinjaOne, normalised to lower case with colons, or '' (1.50; stricter in 1.50.1). Untrusted
     * input: only the usual written forms are accepted (six pairs with ':' or '-' or none, or Cisco's three dotted
     * groups), so a label that happens to contain twelve hex digits is not read as a MAC. All-zero and group
     * (multicast and broadcast) addresses identify no machine and are dropped.
     */
    private static function mac(mixed $m): string
    {
        $m = is_string($m) ? trim($m) : '';
        if (preg_match('/^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/i', $m) !== 1 && preg_match('/^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/i', $m) !== 1) {
            return '';
        }
        $hex = strtolower((string) preg_replace('/[^0-9a-f]/i', '', $m));
        if ($hex === '000000000000' || (hexdec($hex[1]) & 1) === 1) {
            return ''; // all zero, or the group bit (multicast; broadcast ff:ff:... included)
        }
        return implode(':', str_split($hex, 2));
    }

    /** A scalar from the API as a trimmed string ('' for anything else). */
    private static function str(mixed $v): string
    {
        return is_scalar($v) ? trim((string) $v) : '';
    }
}
