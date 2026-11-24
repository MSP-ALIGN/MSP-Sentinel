<?php

declare(strict_types=1);

namespace Sentinel\Auth;

/**
 * "Sign in with Microsoft" (1.43): OpenID Connect against one Microsoft Entra ID tenant, authorization code flow with
 * PKCE and a client secret, run by the server.
 *
 * Only the ID token is used (no access token is kept, no Microsoft Graph call). It is accepted only when:
 * - it came from the token endpoint over HTTPS, in exchange for the one-time code and the PKCE verifier;
 * - its signature is RS256 with a key from the tenant's published key set (no "none", no HMAC, no key in the token);
 * - iss is exactly https://login.microsoftonline.com/{tenant}/v2.0, aud is this app's client ID, tid is the tenant;
 * - it is current (exp, nbf, iat with 2 minutes of clock skew) and carries the nonce this browser's session made;
 * - it is a member of the tenant, not a guest from another directory (idp, 1.43.1).
 * MFA counts only when amr lists "mfa" and auth_time is at most an hour old.
 *
 * Untrusted: everything from Microsoft's endpoints and the browser (code, state). Claims are only read after all
 * checks pass, and are cut to length. Errors never contain tokens or the secret.
 */
final class EntraSso
{
    public const DEFAULT_AUTHORITY = 'https://login.microsoftonline.com';
    private const SKEW = 120;
    /** Microsoft's MFA counts for skipping Sentinel's code only when the sign-in is at most this old (seconds). */
    public const MFA_MAX_AGE = 3600;
    private const MAX_BYTES = 1_000_000;
    private const GUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/';

    /**
     * @param string $tenantId  the directory (tenant) ID, a GUID (a domain name can't be checked against tid)
     * @param string $clientId  the app registration's application (client) ID, a GUID
     * @param string $secret    the client secret (from the encrypted settings; never logged)
     * @param string $authority Microsoft's sign-in address; the test suite points it at its mock
     */
    public function __construct(
        private readonly string $tenantId,
        private readonly string $clientId,
        private readonly string $secret,
        private readonly string $authority = self::DEFAULT_AUTHORITY,
        private readonly bool $allowHttp = false,
    ) {
    }

    /** True for a GUID as Entra writes tenant and client IDs (lower case). */
    public static function validGuid(string $v): bool
    {
        return preg_match(self::GUID, $v) === 1;
    }

    /** A random URL-safe value (state, nonce, PKCE verifier). */
    public static function random(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /** The PKCE S256 challenge for a verifier. */
    public static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    /** The address to send the browser to. */
    public function authorizeUrl(string $redirectUri, string $state, string $nonce, string $verifier): string
    {
        return $this->base() . '/oauth2/v2.0/authorize?' . http_build_query([
            'client_id' => $this->clientId, 'response_type' => 'code', 'redirect_uri' => $redirectUri, 'response_mode' => 'query',
            'scope' => 'openid profile email', 'state' => $state, 'nonce' => $nonce,
            'code_challenge' => self::challenge($verifier), 'code_challenge_method' => 'S256', 'prompt' => 'select_account',
            // Ask Microsoft for a sign-in at most an hour old, and say when it happened (auth_time), 1.43.1.
            'max_age' => (string) self::MFA_MAX_AGE,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchange the code for an ID token and check it. Returns the claims Sentinel uses.
     *
     * @return array{oid:string, tid:string, email:string, name:string, mfa:bool}
     * @throws SsoException with a message safe to show and log
     */
    public function signIn(string $code, string $redirectUri, string $verifier, string $nonce): array
    {
        if ($code === '' || strlen($code) > 4000) {
            throw new SsoException('Microsoft did not return a sign-in code.');
        }
        $res = $this->request($this->base() . '/oauth2/v2.0/token', http_build_query([
            'client_id' => $this->clientId, 'client_secret' => $this->secret, 'grant_type' => 'authorization_code', 'code' => $code,
            'redirect_uri' => $redirectUri, 'code_verifier' => $verifier, 'scope' => 'openid profile email',
        ]));
        $idToken = is_string($res['id_token'] ?? null) ? $res['id_token'] : '';
        if ($idToken === '') {
            throw new SsoException(is_string($res['error'] ?? null) ? 'Microsoft refused the sign-in (' . mb_substr(preg_replace('/[^a-z_]/', '', $res['error']) ?? '', 0, 40) . ').' : 'Microsoft returned no ID token.');
        }
        return $this->verify($idToken, $nonce);
    }

    /**
     * Check an ID token and read its claims (public for the tests).
     *
     * @return array{oid:string, tid:string, email:string, name:string, mfa:bool}
     */
    public function verify(string $jwt, string $nonce, ?int $now = null): array
    {
        $now ??= time();
        $parts = explode('.', $jwt);
        if (count($parts) !== 3 || strlen($jwt) > 20000) {
            throw new SsoException('The ID token is malformed.');
        }
        $header = json_decode(self::b64($parts[0]), true);
        $claims = json_decode(self::b64($parts[1]), true);
        $sig = self::b64($parts[2]);
        if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? '') !== 'RS256' || !is_string($header['kid'] ?? null) || $sig === '') {
            throw new SsoException('The ID token is not signed the way Microsoft signs them.');
        }
        $pem = $this->keyPem($header['kid']);
        if (openssl_verify($parts[0] . '.' . $parts[1], $sig, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new SsoException('The ID token signature is not valid.');
        }
        $expectIss = self::DEFAULT_AUTHORITY . '/' . $this->tenantId . '/v2.0';
        $checks = [
            'issuer' => ($claims['iss'] ?? null) === $expectIss,
            'audience' => ($claims['aud'] ?? null) === $this->clientId,
            'tenant' => ($claims['tid'] ?? null) === $this->tenantId,
            'expiry' => is_int($claims['exp'] ?? null) && $claims['exp'] > $now - self::SKEW,
            'not before' => !isset($claims['nbf']) || (is_int($claims['nbf']) && $claims['nbf'] <= $now + self::SKEW),
            'issued at' => is_int($claims['iat'] ?? null) && $claims['iat'] <= $now + self::SKEW && $claims['iat'] > $now - 3600,
            'nonce' => is_string($claims['nonce'] ?? null) && $nonce !== '' && hash_equals($nonce, $claims['nonce']),
            'account' => is_string($claims['oid'] ?? null) && self::validGuid(strtolower($claims['oid'])),
            // A guest (B2B) account gets this tenant's iss and tid; only idp shows its home directory. Guests are
            // refused: only the tenant's own members may sign in (1.43.1).
            'member account' => !isset($claims['idp']) || $claims['idp'] === $claims['iss'],
        ];
        foreach ($checks as $what => $ok) {
            if (!$ok) {
                throw new SsoException('The ID token failed the ' . $what . ' check.');
            }
        }
        // Shown in the audit log only; never used to decide who signs in (1.43.1: accounts are linked from My profile).
        $email = is_string($claims['email'] ?? null) && filter_var($claims['email'], FILTER_VALIDATE_EMAIL) !== false ? strtolower(mb_substr($claims['email'], 0, 190)) : '';
        $amr = is_array($claims['amr'] ?? null) ? $claims['amr'] : [];
        // MFA counts only for a fresh sign-in: auth_time within MFA_MAX_AGE (an old Entra session's MFA doesn't).
        $fresh = is_int($claims['auth_time'] ?? null) && $claims['auth_time'] > $now - self::MFA_MAX_AGE - self::SKEW && $claims['auth_time'] <= $now + self::SKEW;
        return ['oid' => strtolower((string) $claims['oid']), 'tid' => $this->tenantId, 'email' => $email,
                'name' => is_string($claims['name'] ?? null) ? mb_substr((string) preg_replace('/[\p{Cc}\p{Cf}]/u', '', $claims['name']), 0, 100) : '',
                // Microsoft says MFA was done when amr lists "mfa" (some flows don't send amr: then Sentinel asks its own code).
                'mfa' => in_array('mfa', $amr, true) && $fresh];
    }

    /** The tenant's signing key with this key ID, as PEM. */
    private function keyPem(string $kid): string
    {
        $jwks = $this->request($this->base() . '/discovery/v2.0/keys', null);
        foreach ((array) ($jwks['keys'] ?? []) as $k) {
            if (is_array($k) && ($k['kid'] ?? null) === $kid && ($k['kty'] ?? null) === 'RSA' && is_string($k['n'] ?? null) && is_string($k['e'] ?? null)
                && (($k['use'] ?? 'sig') === 'sig')) {
                return self::rsaPem(self::b64($k['n']), self::b64($k['e']));
            }
        }
        throw new SsoException('The ID token was signed with a key the tenant does not publish.');
    }

    /** A DER/PEM SubjectPublicKeyInfo for an RSA modulus and exponent. */
    private static function rsaPem(string $n, string $e): string
    {
        if (strlen($n) < 256 || strlen($e) < 1 || strlen($e) > 8) {
            throw new SsoException('The tenant published an unusable signing key.');
        }
        $int = static fn (string $b): string => "\x02" . self::len(strlen(ord($b[0]) > 0x7f ? "\x00" . $b : $b)) . (ord($b[0]) > 0x7f ? "\x00" . $b : $b);
        $seq = static fn (string $b): string => "\x30" . self::len(strlen($b)) . $b;
        $rsa = $seq($int($n) . $int($e));
        $algo = $seq("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");
        $spki = $seq($algo . "\x03" . self::len(strlen($rsa) + 1) . "\x00" . $rsa);
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** A DER length. */
    private static function len(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $b = ltrim(pack('N', $n), "\x00");
        return chr(0x80 | strlen($b)) . $b;
    }

    private static function b64(string $s): string
    {
        return (string) base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
    }

    private function base(): string
    {
        return rtrim($this->authority, '/') . '/' . rawurlencode($this->tenantId);
    }

    /**
     * GET (no body) or POST a form to Microsoft; the JSON answer.
     *
     * @return array<string,mixed>
     */
    private function request(string $url, ?string $form): array
    {
        $p = parse_url($url);
        if (!is_array($p) || !in_array($p['scheme'] ?? '', $this->allowHttp ? ['https', 'http'] : ['https'], true) || ($p['host'] ?? '') === '') {
            throw new SsoException('The Microsoft sign-in address is not valid.');
        }
        $body = '';
        $ch = curl_init($url);
        if ($form !== null) {
            curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $form]);
        }
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => $form !== null ? ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'] : ['Accept: application/json'],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 20,
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
        $err = curl_error($ch);
        curl_close($ch);
        if ($ok === false) {
            error_log('[msp-sentinel] Sign in with Microsoft: ' . mb_substr($err, 0, 200)); // network details for the admin only
            throw new SsoException('Could not reach Microsoft. Try again later.');
        }
        $data = json_decode($body, true);
        if (!is_array($data)) {
            throw new SsoException('Microsoft returned an unexpected answer.');
        }
        return $data;
    }
}
