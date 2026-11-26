<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use Sentinel\Core\App;

/**
 * "Connect to Microsoft 365" (1.63): an Admin signs in to Microsoft in their browser and Sentinel creates the Entra app
 * registration for "Sign in with Microsoft" itself. It replaces the PowerShell setup script.
 *
 * How: OAuth 2.0 device authorization (RFC 8628) with Microsoft's own public client for Microsoft Graph command-line
 * tools, the same app identity Microsoft Graph PowerShell uses. Sentinel asks Microsoft for a short user code, the Admin
 * enters it at microsoft.com/devicelogin and signs in as an Entra admin, and Sentinel polls for the token. With it,
 * Sentinel (all through Microsoft Graph):
 * - reads the tenant (and stops, changing nothing, if it isn't the tenant Sentinel already uses and switching wasn't
 *   allowed);
 * - creates or updates the app registration tagged for this Sentinel (single tenant, Web redirect to Sentinel's
 *   callback, sign-in permissions openid/profile/email, the auth_time claim);
 * - creates its service principal and grants organization-wide consent for those sign-in permissions only;
 * - adds a 24-month client secret, saves the tenant ID, client ID and secret (in one transaction with the tenant check),
 *   then removes the older secrets it made. "Sign in with Microsoft" is never switched on here.
 *
 * Untrusted: every answer from Microsoft (token endpoint and Graph). IDs must be GUIDs, the secret must look like one,
 * the expiry must be a date within 25 months. Error texts are Sentinel's own (Microsoft's error descriptions are never
 * shown); the only Microsoft text shown is the tenant's display name, escaped like every other value.
 *
 * Security assumptions:
 * - Only an Admin who holds every permission, sees every client and typed their own password can start (the controller
 *   checks); only that same Admin can finish, and only while still such an Admin.
 * - The device code is stored encrypted (it could be exchanged for the Admin's Graph token until it expires, 15 minutes
 *   at most); the Graph access token is used in memory for this one request and never stored or logged.
 * - One pending connection at a time. Start, cancel and check all take one database lock, so a check can't bring back a
 *   canceled connection or overwrite a newer one, and two checks can't finish it twice.
 * - A finished check leaves a short-lived result (sso_connect_result, no secrets) for the starter's next poll, so a check
 *   that outlived the browser's request still reports success.
 * - Requests go only to Microsoft's fixed addresses over HTTPS (the test suite points them at its mock).
 */
final class EntraAppSetup
{
    /** Microsoft Graph command-line tools: Microsoft's public client (the app Microsoft Graph PowerShell signs in as). */
    public const CLIENT_ID = '14d82eec-204b-4c2f-b7e8-296a70dab67e';
    public const AUTHORITY = 'https://login.microsoftonline.com';
    public const GRAPH = 'https://graph.microsoft.com/v1.0';
    /** Delegated permissions the signing-in admin consents to, for this setup only. */
    private const SCOPES = 'openid https://graph.microsoft.com/User.Read https://graph.microsoft.com/Application.ReadWrite.All https://graph.microsoft.com/DelegatedPermissionGrant.ReadWrite.All';
    private const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
    /** openid, profile, email: Microsoft Graph's delegated permission IDs (the same in every tenant). */
    private const SIGN_IN_SCOPES = ['37f7f235-527c-4136-accd-4a02d197296e', '14dad69e-099b-42c9-810b-d002981feec1', '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'];
    public const SECRET_PREFIX = 'MSP Sentinel sign-in';
    public const SECRET_DAYS = 730;
    private const MAX_BYTES = 1_000_000;
    private const LOCK = 'sentinel_sso_connect';
    /** How long a finished check's result is kept for the starter's next poll (seconds). */
    private const RESULT_TTL = 600;

    /**
     * @param string $authority Microsoft's sign-in address (the test suite: its mock)
     * @param string $graph     Microsoft Graph's address (the test suite: its mock)
     * @param bool   $allowHttp only the test suite (its mocks speak plain HTTP on 127.0.0.1)
     */
    public function __construct(
        private readonly string $authority = self::AUTHORITY,
        private readonly string $graph = self::GRAPH,
        private readonly bool $allowHttp = false,
    ) {
    }

    /**
     * Start: ask Microsoft for a user code for $userId (replacing any pending connection).
     * $newTenant: the Admin allowed switching to another tenant (every user's Microsoft link is then cleared).
     *
     * @return array{user_code:string, verification_uri:string, expires:int}
     * @throws SsoException with a message safe to show
     */
    public function start(int $userId, bool $newTenant): array
    {
        if (!self::lock(10)) {
            throw new SsoException(__('A Microsoft 365 connection is being finished right now. Try again in a minute.'));
        }
        try {
            return $this->startLocked($userId, $newTenant);
        } finally {
            self::unlock();
        }
    }

    /**
     * @return array{user_code:string, verification_uri:string, expires:int}
     * @throws SsoException
     */
    private function startLocked(int $userId, bool $newTenant): array
    {
        $r = $this->form($this->authority . '/organizations/oauth2/v2.0/devicecode', ['client_id' => self::CLIENT_ID, 'scope' => self::SCOPES]);
        $code = is_string($r['device_code'] ?? null) ? $r['device_code'] : '';
        $user = is_string($r['user_code'] ?? null) ? $r['user_code'] : '';
        $uri = is_string($r['verification_uri'] ?? null) ? $r['verification_uri'] : '';
        if ($code === '' || strlen($code) > 2000 || preg_match('/^[A-Z0-9-]{4,20}$/i', $user) !== 1
            || preg_match('#^https://(login\.microsoft\.com|microsoft\.com|www\.microsoft\.com|login\.microsoftonline\.com)/[a-z/]*$#', $uri) !== 1 && !$this->allowHttp) {
            throw new SsoException('Microsoft did not start the sign-in. Try again in a minute.');
        }
        $expires = time() + max(60, min(900, (int) ($r['expires_in'] ?? 900)));
        $state = ['device_code' => $code, 'user_code' => $user, 'verification_uri' => $uri, 'user' => $userId, 'expires' => $expires,
                  'interval' => max(1, min(30, (int) ($r['interval'] ?? 5))), 'next' => time(), 'new_tenant' => $newTenant];
        App::settings()->setSecret('sso_connect', (string) json_encode($state));
        App::settings()->set('sso_connect_result', '');
        return ['user_code' => $user, 'verification_uri' => $uri, 'expires' => $expires];
    }

    /**
     * The pending connection as the page shows it (no device code), or null when there is none or it expired.
     *
     * @return array{user_code:string, verification_uri:string, expires:int, user:int}|null
     */
    public static function pending(): ?array
    {
        $s = self::state();
        return $s === null ? null : ['user_code' => $s['user_code'], 'verification_uri' => $s['verification_uri'], 'expires' => $s['expires'], 'user' => $s['user']];
    }

    /** Forget the pending connection (waits for a running check). False when a check is still busy. */
    public static function cancel(): bool
    {
        if (!self::lock(10)) {
            return false;
        }
        try {
            App::settings()->setSecret('sso_connect', '');
            return true;
        } finally {
            self::unlock();
        }
    }

    /** The connection lock (MySQL GET_LOCK), waiting up to $wait seconds. */
    private static function lock(int $wait): bool
    {
        return (int) App::db()->query("SELECT GET_LOCK('" . self::LOCK . "', " . max(0, $wait) . ')')->fetchColumn() === 1;
    }

    private static function unlock(): void
    {
        App::db()->query("SELECT RELEASE_LOCK('" . self::LOCK . "')");
    }

    /**
     * Check the pending connection for $userId: still waiting, finished (the app is created and its details saved), or
     * failed (the connection is then cleared).
     *
     * 'quiet' marks answers that report nothing new (another tab after the connection ended): not audited or flashed.
     *
     * @return array{status:string, message:string, changed?:array<string,mixed>, quiet?:bool}
     */
    public function check(int $userId): array
    {
        $state = self::state();
        if ($state === null) {
            // Finished by a check that outlived its request (or another tab): report that once to the starter.
            $res = json_decode(App::settings()->fresh('sso_connect_result'), true);
            if (is_array($res) && (int) ($res['user'] ?? 0) === $userId && (int) ($res['at'] ?? 0) > time() - self::RESULT_TTL) {
                App::settings()->set('sso_connect_result', '');
                return ['status' => (string) $res['status'], 'message' => (string) $res['message'], 'quiet' => true];
            }
            return ['status' => 'failed', 'message' => __('The Microsoft sign-in expired or was canceled. Click "Connect to Microsoft 365" to start again.'), 'quiet' => true];
        }
        if ((int) $state['user'] !== $userId) {
            return ['status' => 'failed', 'message' => __('Another admin started this connection. Only they can finish it, or start a new one.')];
        }
        if (time() < (int) $state['next']) {
            return ['status' => 'pending', 'message' => __('Waiting for you to sign in at Microsoft…')];
        }
        if (!self::lock(0)) {
            return ['status' => 'pending', 'message' => __('Waiting for you to sign in at Microsoft…')]; // another check is running
        }
        try {
            $r = $this->checkLocked($state);
            if ($r['status'] !== 'pending') {
                // Kept briefly for the starter's next poll, in case this request outlived the browser's.
                App::settings()->set('sso_connect_result', (string) json_encode(['user' => $userId, 'status' => $r['status'], 'message' => $r['message'], 'at' => time()]));
            }
            return $r;
        } finally {
            self::unlock();
        }
    }

    /**
     * @param array<string,mixed> $state
     * @return array{status:string, message:string, changed?:array<string,mixed>}
     */
    private function checkLocked(array $state): array
    {
        $fresh = self::state(); // the connection may have been finished or canceled while we waited
        if ($fresh === null || $fresh['device_code'] !== $state['device_code']) {
            return ['status' => 'failed', 'message' => __('This Microsoft sign-in was already used or canceled.'), 'quiet' => true];
        }
        $fail = static function (string $message): array {
            App::settings()->setSecret('sso_connect', ''); // the lock is already held
            return ['status' => 'failed', 'message' => $message];
        };
        try {
            $r = $this->form($this->authority . '/organizations/oauth2/v2.0/token', [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code', 'client_id' => self::CLIENT_ID, 'device_code' => $state['device_code'],
            ]);
        } catch (SsoException $ex) {
            return ['status' => 'pending', 'message' => $ex->getMessage()]; // network trouble: try again next time
        }
        $error = is_string($r['error'] ?? null) ? $r['error'] : '';
        if ($error === 'authorization_pending' || $error === 'slow_down') {
            $state['interval'] = $error === 'slow_down' ? min(30, (int) $state['interval'] + 5) : (int) $state['interval'];
            $state['next'] = time() + (int) $state['interval'];
            App::settings()->setSecret('sso_connect', (string) json_encode($state));
            return ['status' => 'pending', 'message' => __('Waiting for you to sign in at Microsoft…')];
        }
        if ($error === 'authorization_declined') {
            return $fail(__('The sign-in was declined at Microsoft. Nothing was changed.'));
        }
        if ($error !== '') {
            // expired_token, bad_verification_code, a blocked device-code sign-in (Conditional Access), ...
            return $fail(__('Microsoft did not complete the sign-in ({e}). Nothing was changed. If your tenant blocks sign-in with a code (Conditional Access), set the app up by hand.', ['e' => mb_substr((string) preg_replace('/[^a-z_]/', '', $error), 0, 40)]));
        }
        $token = is_string($r['access_token'] ?? null) ? $r['access_token'] : '';
        if ($token === '' || strlen($token) > 20000) {
            return $fail(__('Microsoft returned an unexpected answer. Nothing was changed.'));
        }
        try {
            $result = $this->createApp($token, (bool) $state['new_tenant']);
        } catch (SsoException $ex) {
            return $fail($ex->getMessage());
        }
        $result['changed']['secret_expires'] = $result['expires'];
        return ['status' => 'done', 'message' => $result['message'], 'changed' => $result['changed']];
    }

    /**
     * Everything after sign-in: tenant check, app, service principal, consent, secret, save, clean-up.
     *
     * @return array{message:string, expires:string, changed:array<string,mixed>}
     * @throws SsoException
     */
    private function createApp(string $token, bool $newTenant): array
    {
        $s = App::settings();
        $redirect = App::ssoRedirectUri();
        if ($redirect === '') {
            throw new SsoException(__('Set Sentinel\'s public address first (app.public_url in the config file): the Entra app is registered for it.'));
        }
        $org = $this->first($token, '/organization?$select=id,displayName');
        $tenant = strtolower(is_string($org['id'] ?? null) ? $org['id'] : '');
        if (!EntraSso::validGuid($tenant)) {
            throw new SsoException(__('Microsoft did not say which tenant you signed in to. Nothing was changed.'));
        }
        $orgName = mb_substr(is_string($org['displayName'] ?? null) ? $org['displayName'] : '', 0, 200);
        $current = $s->fresh('sso_entra_tenant');
        if ($current !== '' && $current !== $tenant && !$newTenant) {
            throw new SsoException(__('You signed in to tenant {t} ({n}), but Sentinel uses tenant {c}. Nothing was changed. Sign in to that tenant, or tick "Switch to another Microsoft tenant".', ['t' => $tenant, 'n' => $orgName, 'c' => $current]));
        }

        // The app: the one made before for this Sentinel (by its tag; the old setup script used the same tag), else new.
        $p = parse_url($redirect);
        // As the old setup script built it (.NET Uri.Authority leaves out the default port 443), so its apps are found.
        $port = isset($p['port']) && (int) $p['port'] !== 443 ? ':' . $p['port'] : '';
        $hostName = strtolower(($p['host'] ?? '') . $port . rtrim(substr((string) ($p['path'] ?? ''), 0, -strlen('/login/sso/callback')), '/'));
        $tag = 'msp-sentinel-sso:' . $hostName;
        $access = ['resourceAppId' => self::GRAPH_APP_ID, 'resourceAccess' => array_map(static fn (string $id): array => ['id' => $id, 'type' => 'Scope'], self::SIGN_IN_SCOPES)];
        $app = $this->first($token, '/applications?$filter=' . rawurlencode("tags/any(t:t eq '" . str_replace("'", "''", $tag) . "')") . '&$select=id,appId,displayName,web,optionalClaims,requiredResourceAccess');
        if ($app === null) {
            $app = $this->graph('POST', $token, '/applications', [
                'displayName' => 'MSP Sentinel (' . $hostName . ')', 'signInAudience' => 'AzureADMyOrg', 'tags' => [$tag],
                'web' => ['redirectUris' => [$redirect], 'implicitGrantSettings' => ['enableIdTokenIssuance' => false, 'enableAccessTokenIssuance' => false]],
                'requiredResourceAccess' => [$access],
                'optionalClaims' => ['idToken' => [['name' => 'auth_time', 'essential' => false]]],
            ]);
        } else {
            // PATCH replaces the whole "web" object: keep what is there, add Sentinel's redirect address.
            $web = is_array($app['web'] ?? null) ? $app['web'] : [];
            unset($web['redirectUriSettings']); // read-only, follows redirectUris
            $uris = array_values(array_filter((array) ($web['redirectUris'] ?? []), 'is_string'));
            if (!in_array($redirect, $uris, true)) {
                $uris[] = $redirect;
            }
            $web['redirectUris'] = $uris;
            $claims = is_array($app['optionalClaims'] ?? null) ? $app['optionalClaims'] : [];
            $idClaims = array_values(array_filter((array) ($claims['idToken'] ?? []), 'is_array'));
            if (!in_array('auth_time', array_column($idClaims, 'name'), true)) {
                $idClaims[] = ['name' => 'auth_time', 'essential' => false];
            }
            $claims['idToken'] = $idClaims;
            $this->graph('PATCH', $token, '/applications/' . rawurlencode((string) $app['id']), ['web' => $web, 'requiredResourceAccess' => self::mergeAccess($app['requiredResourceAccess'] ?? null, $access), 'optionalClaims' => $claims]);
        }
        $objectId = is_string($app['id'] ?? null) ? $app['id'] : '';
        $client = strtolower(is_string($app['appId'] ?? null) ? $app['appId'] : '');
        if (!EntraSso::validGuid($client) || $objectId === '' || strlen($objectId) > 64) {
            throw new SsoException(__('Microsoft returned an unexpected answer while creating the app. Nothing was saved in Sentinel.'));
        }

        // Its service principal (the app's presence in the tenant). A brand-new app takes a few seconds to reach every
        // Microsoft server, so creating it is retried for about 10 seconds.
        $sp = $this->first($token, '/servicePrincipals?$filter=' . rawurlencode("appId eq '{$client}'") . '&$select=id');
        for ($try = 1; $sp === null; $try++) {
            try {
                $sp = $this->graph('POST', $token, '/servicePrincipals', ['appId' => $client, 'tags' => ['WindowsAzureActiveDirectoryIntegratedApp']]);
            } catch (SsoException $ex) {
                if ($try >= 5) {
                    throw $ex;
                }
                sleep($this->allowHttp ? 0 : $try);
            }
        }

        // Organization-wide consent for the sign-in permissions only (otherwise each user is asked, or blocked by policy).
        $consentNote = '';
        try {
            $spId = strtolower((string) ($sp['id'] ?? ''));
            $graphSp = $this->first($token, '/servicePrincipals?$filter=' . rawurlencode("appId eq '" . self::GRAPH_APP_ID . "'") . '&$select=id');
            $graphSpId = strtolower((string) ($graphSp['id'] ?? ''));
            if (!EntraSso::validGuid($spId) || !EntraSso::validGuid($graphSpId)) {
                throw new SsoException('unexpected IDs'); // only Graph's own GUIDs go into the filter below
            }
            $grant = $this->first($token, '/oauth2PermissionGrants?$filter=' . rawurlencode("clientId eq '{$spId}' and consentType eq 'AllPrincipals' and resourceId eq '{$graphSpId}'"));
            if ($grant === null) {
                $this->graph('POST', $token, '/oauth2PermissionGrants', ['clientId' => $spId, 'consentType' => 'AllPrincipals', 'resourceId' => $graphSpId, 'scope' => 'openid profile email']);
            } else {
                // Keep scopes someone granted by hand; add the sign-in ones.
                $have = array_values(array_filter(explode(' ', (string) ($grant['scope'] ?? '')), static fn (string $x): bool => $x !== ''));
                $want = array_values(array_unique(array_merge($have, ['openid', 'profile', 'email'])));
                if (count($want) !== count($have)) {
                    $this->graph('PATCH', $token, '/oauth2PermissionGrants/' . rawurlencode((string) $grant['id']), ['scope' => implode(' ', $want)]);
                }
            }
        } catch (SsoException) {
            $consentNote = ' ' . __('Consent for the organization could not be granted: in the Entra admin center, open the app\'s API permissions and click "Grant admin consent", or each user is asked the first time.');
        }

        // A new client secret.
        $pw = $this->graph('POST', $token, '/applications/' . rawurlencode($objectId) . '/addPassword', ['passwordCredential' => [
            'displayName' => self::SECRET_PREFIX . ' ' . gmdate('Y-m-d'), 'endDateTime' => gmdate('Y-m-d\TH:i:s\Z', time() + self::SECRET_DAYS * 86400),
        ]]);
        $secret = is_string($pw['secretText'] ?? null) ? $pw['secretText'] : '';
        $keyId = is_string($pw['keyId'] ?? null) ? $pw['keyId'] : '';
        if ($secret === '' || strlen($secret) > 200 || preg_match('/[\x00-\x20\x7F-\xFF]/', $secret) === 1) {
            throw new SsoException(__('Microsoft returned an unexpected client secret. Nothing was saved in Sentinel.'));
        }
        $expTs = is_string($pw['endDateTime'] ?? null) ? strtotime($pw['endDateTime']) : false;
        $expires = $expTs !== false && $expTs > time() && $expTs < time() + 25 * 31 * 86400 ? gmdate('Y-m-d H:i:s', $expTs) : '';

        // Save, with the tenant checked again inside the transaction; a failure changes nothing in Sentinel.
        $db = App::db();
        $changed = [];
        $db->beginTransaction();
        try {
            $now = (string) $db->query("SELECT value FROM settings WHERE name = 'sso_entra_tenant' FOR UPDATE")->fetchColumn();
            if ($now !== '' && $now !== $tenant) {
                if (!$newTenant) {
                    throw new SsoException(__('Sentinel\'s tenant changed while you were signing in. Nothing was saved; start again.'));
                }
                $changed['links_cleared'] = SsoSetup::clearAllLinks();
            }
            foreach (['sso_entra_tenant' => $tenant, 'sso_entra_client' => $client] as $name => $value) {
                if ($s->fresh($name) !== $value) {
                    $s->set($name, $value);
                    $changed[$name] = $value;
                }
            }
            $s->setSecret('sso_entra_secret', $secret);
            $s->set('sso_entra_secret_expires', $expires);
            $s->set('sso_secret_warned', '');
            $s->setSecret('sso_connect', '');
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            if ($ex instanceof SsoException) {
                throw $ex;
            }
            error_log('[msp-sentinel] Connect to Microsoft 365: ' . $ex->getMessage());
            throw new SsoException(__('Sentinel could not save the app details (see its PHP error log). Nothing was changed in Sentinel; start again.'));
        }
        $changed['sso_entra_secret'] = 'changed (connect)';

        // Renewal: remove the older secrets Sentinel made (other secrets are left alone). Best effort.
        try {
            $current = $this->graph('GET', $token, '/applications/' . rawurlencode($objectId) . '?$select=passwordCredentials');
            foreach ((array) ($current['passwordCredentials'] ?? []) as $c) {
                if (is_array($c) && ($c['keyId'] ?? '') !== $keyId && str_starts_with((string) ($c['displayName'] ?? ''), self::SECRET_PREFIX)) {
                    $this->graph('POST', $token, '/applications/' . rawurlencode($objectId) . '/removePassword', ['keyId' => (string) $c['keyId']]);
                    $changed['old_secrets_removed'] = (int) ($changed['old_secrets_removed'] ?? 0) + 1;
                }
            }
        } catch (SsoException) {
            $consentNote .= ' ' . __('An older client secret could not be removed: remove it in the Entra admin center.');
        }
        $on = $s->fresh('sso_entra_enabled') === '1';
        $message = ($orgName !== '' ? __('Connected to {n}.', ['n' => $orgName]) . ' ' : '')
            . ($on ? __('The app details are saved; Sign in with Microsoft keeps working with them.') : __('The app is ready. Link your own Microsoft account under My profile, test it, then turn on Sign in with Microsoft below.'))
            . $consentNote;
        return ['message' => $message, 'expires' => $expires, 'changed' => $changed];
    }

    /**
     * The app's requiredResourceAccess with the sign-in permissions added to Microsoft Graph's entry: permissions an
     * admin added by hand (to Graph or other APIs) are kept.
     *
     * @param mixed $current what Graph returned for the app
     * @param array{resourceAppId:string, resourceAccess:list<array{id:string, type:string}>} $signIn
     * @return list<array<string,mixed>>
     */
    public static function mergeAccess(mixed $current, array $signIn): array
    {
        $out = [];
        $merged = false;
        foreach (is_array($current) ? $current : [] as $r) {
            if (!is_array($r) || !is_string($r['resourceAppId'] ?? null)) {
                continue;
            }
            if ($r['resourceAppId'] === $signIn['resourceAppId']) {
                $have = array_values(array_filter((array) ($r['resourceAccess'] ?? []), 'is_array'));
                foreach ($signIn['resourceAccess'] as $want) {
                    if (!in_array($want['id'], array_column($have, 'id'), true)) {
                        $have[] = $want;
                    }
                }
                $r['resourceAccess'] = $have;
                $merged = true;
            }
            $out[] = $r;
        }
        if (!$merged) {
            $out[] = $signIn;
        }
        return $out;
    }

    /**
     * The pending state, or null (none, unreadable or expired).
     *
     * @return array<string,mixed>|null
     */
    private static function state(): ?array
    {
        $raw = App::settings()->getSecret('sso_connect');
        $s = $raw === '' ? null : json_decode($raw, true);
        if (!is_array($s) || !is_string($s['device_code'] ?? null) || (int) ($s['expires'] ?? 0) <= time()) {
            return null;
        }
        return $s;
    }

    /**
     * The first item of a Graph list, or null.
     *
     * @return array<string,mixed>|null
     */
    private function first(string $token, string $path): ?array
    {
        $r = $this->graph('GET', $token, $path);
        $v = $r['value'] ?? null;
        return is_array($v) && isset($v[0]) && is_array($v[0]) ? $v[0] : null;
    }

    /**
     * One Microsoft Graph request with the admin's token; the JSON answer.
     *
     * @param array<string,mixed>|null $json
     * @return array<string,mixed>
     * @throws SsoException
     */
    private function graph(string $method, string $token, string $path, ?array $json = null): array
    {
        [$status, $data] = $this->send($method, $this->graph . $path, $json === null ? null : (string) json_encode($json, JSON_UNESCAPED_SLASHES),
            ['Authorization: Bearer ' . $token, 'Content-Type: application/json']);
        if ($status === 401 || $status === 403) {
            throw new SsoException(__('Your Microsoft account can\'t register apps. Sign in as a Global Administrator, Application Administrator or Cloud Application Administrator. Nothing was saved in Sentinel.'));
        }
        if ($status < 200 || $status >= 300) {
            throw new SsoException(__('Microsoft Graph refused a request (HTTP {s}). Nothing was saved in Sentinel; try again.', ['s' => $status]));
        }
        return $data;
    }

    /**
     * POST a form to Microsoft's sign-in service; the JSON answer (also for errors, which come as JSON).
     *
     * @param array<string,string> $fields
     * @return array<string,mixed>
     * @throws SsoException
     */
    private function form(string $url, array $fields): array
    {
        return $this->send('POST', $url, http_build_query($fields, '', '&'), ['Content-Type: application/x-www-form-urlencoded'])[1];
    }

    /**
     * @param list<string> $headers
     * @return array{0:int, 1:array<string,mixed>}
     * @throws SsoException
     */
    private function send(string $method, string $url, ?string $body, array $headers): array
    {
        $p = parse_url($url);
        if (!is_array($p) || !in_array($p['scheme'] ?? '', $this->allowHttp ? ['https', 'http'] : ['https'], true) || ($p['host'] ?? '') === '') {
            throw new SsoException(__('The Microsoft address is not valid.'));
        }
        $out = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => array_merge(['Accept: application/json'], $headers),
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 25,
            CURLOPT_PROTOCOLS => $this->allowHttp ? (CURLPROTO_HTTP | CURLPROTO_HTTPS) : CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'MSP-Sentinel',
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$out): int {
                $out .= $chunk;
                return strlen($out) > self::MAX_BYTES ? 0 : strlen($chunk);
            },
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($ok === false) {
            error_log('[msp-sentinel] Connect to Microsoft 365: ' . mb_substr($err, 0, 200));
            throw new SsoException(__('Could not reach Microsoft. Check that the server can reach login.microsoftonline.com and graph.microsoft.com.'));
        }
        $data = $out === '' ? [] : json_decode($out, true);
        if (!is_array($data)) {
            throw new SsoException(__('Microsoft returned an unexpected answer.'));
        }
        return [$status, $data];
    }
}
