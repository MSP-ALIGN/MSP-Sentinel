<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;

/**
 * Automatic setup of "Sign in with Microsoft" (1.46): an Admin creates a one-time setup code on the Integrations page,
 * runs entra-sso-setup.ps1 (which creates the Entra app registration through Microsoft Graph, signed in as an Entra
 * admin), and the script sends the app's tenant ID, client ID and client secret here with the code:
 * POST /sso-setup/v1/receive (JSON). The secret is never shown or copied by hand.
 *
 * Untrusted: the whole request body (code, IDs, secret, expiry date, redirect address) and the caller's address.
 *
 * Security assumptions:
 * - The code is random (100 bits), only its HMAC is stored, it lasts 30 minutes and is used once (claimed with one
 *   atomic UPDATE, so two requests can't both use it). Only an Admin who holds every permission, sees every client and
 *   typed their own password can create one (IntegrationsController::ssoSetupCode); a new code replaces the old one.
 * - Whoever holds the code can only point sign-in at an Entra app: signing in still needs a Microsoft account each
 *   user linked themselves (with their password and Sentinel's code), and a new tenant clears every link (as in
 *   IntegrationsController::saveSso). The on/off switch is never changed here: an Admin turns it on and tests it.
 * - Failures are rate limited per address and audited; the secret is never logged or echoed.
 */
final class SsoSetup
{
    public const TTL = 1800;
    private const MAX_FAILS = 10;
    private const WINDOW = 900;

    /** Create a one-time setup code for user $userId (replacing any earlier one). Returns the code, shown once. */
    public static function issue(int $userId): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $raw = '';
        for ($i = 0; $i < 20; $i++) {
            $raw .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        $code = 'SSO-' . implode('-', str_split($raw, 5));
        $s = App::settings();
        $s->set('sso_setup_code', App::crypto()->hmac('sso-setup|' . $code));
        $s->set('sso_setup_expires', (string) (time() + self::TTL));
        $s->set('sso_setup_by', (string) $userId);
        return $code;
    }

    /** True when a setup code is waiting to be used (for the Integrations page). */
    public static function pending(): bool
    {
        $s = App::settings();
        return $s->get('sso_setup_code') !== '' && (int) $s->get('sso_setup_expires') > time();
    }

    /**
     * Days until the saved client secret expires (negative when it has), or null when the date is unknown (a secret
     * typed in by hand).
     */
    public static function secretDaysLeft(): ?int
    {
        $at = App::settings()->get('sso_entra_secret_expires');
        $ts = $at === '' ? false : strtotime($at . ' UTC');
        return $ts === false ? null : (int) floor(($ts - time()) / 86400);
    }

    /** POST /sso-setup/v1/receive: the setup script hands over the new app's details. JSON in, JSON out. */
    public static function handle(Request $request): Response
    {
        if ($request->method !== 'POST' || $request->path !== '/sso-setup/v1/receive') {
            return self::json(404, false, 'Not found.');
        }
        $limiter = App::limiter();
        $bucket = 'sso-setup:' . Auth::ipBucketKey($request->ip());
        if ($limiter->tooMany($bucket, self::MAX_FAILS, self::WINDOW)) {
            return self::json(429, false, 'Too many attempts. Wait 15 minutes, create a new setup code in Sentinel and run the script again.');
        }
        $fail = static function (int $status, string $reason, string $shown) use ($request, $limiter, $bucket): Response {
            $limiter->hit($bucket);
            App::audit()->log('settings.sso_setup_failed', null, null, null, null, ['reason' => $reason], $request->ip());
            return self::json($status, false, $shown);
        };
        $body = $request->jsonBody() ?? [];
        $str = static fn (string $k): string => is_string($body[$k] ?? null) ? trim($body[$k]) : '';
        $code = strtoupper($str('code'));
        if (preg_match('/^SSO(-[A-HJ-NP-Z2-9]{5}){4}$/', $code) !== 1) {
            return $fail(403, 'bad_code', 'That setup code is not valid. Create a new one on Sentinel\'s Integrations page.');
        }
        $s = App::settings();
        $hash = App::crypto()->hmac('sso-setup|' . $code);
        $stored = $s->fresh('sso_setup_code');
        if ($stored === '' || !hash_equals($stored, $hash) || (int) $s->fresh('sso_setup_expires') <= time()) {
            return $fail(403, 'wrong_or_expired', 'That setup code is wrong, used or expired. Create a new one on Sentinel\'s Integrations page.');
        }
        // Check everything before the code is used, so a typo in the script's input doesn't burn it.
        $tenant = strtolower($str('tenant_id'));
        $client = strtolower($str('client_id'));
        $secret = is_string($body['client_secret'] ?? null) ? (string) $body['client_secret'] : '';
        if (!EntraSso::validGuid($tenant) || !EntraSso::validGuid($client)) {
            return $fail(422, 'bad_ids', 'The tenant ID and client ID must be GUIDs.');
        }
        if ($secret === '' || strlen($secret) > 200 || preg_match('/[\x00-\x20\x7F-\xFF]/', $secret) === 1) {
            return $fail(422, 'bad_secret', 'The client secret is not valid.');
        }
        if ($str('redirect_uri') !== App::ssoRedirectUri() || App::ssoRedirectUri() === '') {
            return $fail(422, 'redirect_mismatch', 'The app was registered for ' . mb_substr((string) preg_replace('/[^\x21-\x7E]/', '', $str('redirect_uri')), 0, 200)
                . ', but Sentinel expects ' . App::ssoRedirectUri() . '. Run the script with -Server set to Sentinel\'s address exactly as on its Integrations page.');
        }
        // Expiry: a date within the next 25 months, else unknown (no warning rather than a wrong one).
        $expTs = $str('secret_expires') === '' ? false : strtotime($str('secret_expires'));
        $expires = $expTs !== false && $expTs > time() && $expTs < time() + 25 * 31 * 86400 ? gmdate('Y-m-d H:i:s', $expTs) : '';

        // Use the code: one atomic claim, so only one request can.
        $claim = App::db()->prepare("UPDATE settings SET value = '' WHERE name = 'sso_setup_code' AND value = :h");
        $claim->execute(['h' => $hash]);
        if ($claim->rowCount() !== 1) {
            return $fail(403, 'raced', 'That setup code was just used. Create a new one on Sentinel\'s Integrations page.');
        }
        $byId = (int) $s->fresh('sso_setup_by');
        $by = App::users()->find($byId);
        $changed = [];
        if ($s->fresh('sso_entra_tenant') !== $tenant && $s->fresh('sso_entra_tenant') !== '') {
            $changed['links_cleared'] = (int) App::db()->exec('UPDATE users SET sso_subject = NULL WHERE sso_subject IS NOT NULL');
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
        $changed['sso_entra_secret'] = 'changed (setup script)';
        $changed['secret_expires'] = $expires;
        $limiter->clear($bucket);
        App::audit()->log('settings.sso_setup_received', $by === null ? null : $byId, $by === null ? null : (string) $by['username'], null, null, ['changed' => $changed], $request->ip());
        if ($by !== null) {
            App::db()->prepare("INSERT INTO notifications (user_id, kind, severity, title, body, link, created_at) VALUES (:u, 'security', 'info', :t, :b, '/admin/integrations#sso', UTC_TIMESTAMP())")
                ->execute(['u' => $byId, 't' => mb_substr(__('Sign in with Microsoft: the setup script sent the app details'), 0, 300),
                           'b' => mb_substr(__('The Entra app\'s IDs and client secret are saved. Turn on "Sign in with Microsoft" on the Integrations page when you are ready. If you didn\'t run the setup script, check the audit log.'), 0, 2000)]);
        }
        $on = $s->fresh('sso_entra_enabled') === '1';
        return self::json(200, true, $on ? 'Saved. Sign in with Microsoft is on and now uses this app.'
            : 'Saved. In Sentinel, open Administration > Integrations and turn on "Sign in with Microsoft".');
    }

    private static function json(int $status, bool $ok, string $message): Response
    {
        return \Sentinel\Api\ApiKernel::json(['ok' => $ok, 'message' => $message], $status);
    }
}
