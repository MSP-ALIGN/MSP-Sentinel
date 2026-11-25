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
 *   user linked themselves (with their password and Sentinel's code). Another tenant is refused (409) unless the Admin
 *   allowed it when creating the code (1.46.1); switching clears every link and turns password sign-in back on for
 *   everyone, so nobody is locked out. The on/off switch is never changed here: an Admin turns it on and tests it.
 * - The code works only while the Admin who made it is still an active Admin with every client (1.46.1).
 * - Using the code and every change are one transaction: a failure leaves the code and the settings as they were.
 * - Wrong codes are rate limited per address and audited; the secret is never logged or echoed.
 */
final class SsoSetup
{
    public const TTL = 1800;
    private const MAX_FAILS = 10;
    private const WINDOW = 900;

    /**
     * Forget every user's Microsoft link (another tenant means other accounts) and turn password sign-in back on for
     * them, signing them out, so nobody whose password sign-in was off is locked out (1.46.1). Returns how many.
     */
    public static function clearAllLinks(): int
    {
        return (int) App::db()->exec("UPDATE users SET sso_subject = NULL, sso_name = '', password_login = 1, session_version = session_version + 1,
                                      updated_at = UTC_TIMESTAMP() WHERE sso_subject IS NOT NULL");
    }

    /**
     * Create a one-time setup code for user $userId (replacing any earlier one). Returns the code, shown once.
     * $allowNewTenant: the details may be for another tenant than the one saved (clears every link).
     */
    public static function issue(int $userId, bool $allowNewTenant = false): string
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
        $s->set('sso_setup_new_tenant', $allowNewTenant ? '1' : '0');
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
        // Wrong codes count toward the limit; wrong details sent with the right code don't (1.46.1: the code already proved
        // who is calling, and an office's typo retries shouldn't block everyone behind the same address).
        $fail = static function (int $status, string $reason, string $shown, bool $count = true) use ($request, $limiter, $bucket): Response {
            if ($count) {
                $limiter->hit($bucket);
            }
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
            return $fail(422, 'bad_ids', 'The tenant ID and client ID must be GUIDs.', false);
        }
        if ($secret === '' || strlen($secret) > 200 || preg_match('/[\x00-\x20\x7F-\xFF]/', $secret) === 1) {
            return $fail(422, 'bad_secret', 'The client secret is not valid.', false);
        }
        $current = $s->fresh('sso_entra_tenant');
        if ($current !== '' && $current !== $tenant && $s->fresh('sso_setup_new_tenant') !== '1') {
            // Probably signed in to the wrong tenant (an MSP has several): switching would clear every user's link.
            return $fail(409, 'other_tenant', 'You signed in to Microsoft tenant ' . $tenant . ', but Sentinel uses tenant ' . $current
                . '. Run the script again and sign in to that tenant. To really switch tenants (every user\'s Microsoft link is cleared), create a new setup code with "Switch to another tenant" ticked.', false);
        }
        if (!self::issuerOk((int) $s->fresh('sso_setup_by'))) {
            return $fail(403, 'issuer_gone', 'The admin who created this setup code can no longer change sign-in settings. Create a new code.');
        }
        if ($str('redirect_uri') !== App::ssoRedirectUri() || App::ssoRedirectUri() === '') {
            return $fail(422, 'redirect_mismatch', 'The app was registered for ' . mb_substr((string) preg_replace('/[^\x21-\x7E]/', '', $str('redirect_uri')), 0, 200)
                . ', but Sentinel expects ' . App::ssoRedirectUri() . '. Run the script with -Server set to Sentinel\'s address exactly as on its Integrations page.', false);
        }
        // Expiry: a date within the next 25 months, else unknown (no warning rather than a wrong one).
        $expTs = $str('secret_expires') === '' ? false : strtotime($str('secret_expires'));
        $expires = $expTs !== false && $expTs > time() && $expTs < time() + 25 * 31 * 86400 ? gmdate('Y-m-d H:i:s', $expTs) : '';

        // Use the code and save, all in one transaction: the code rows are locked, checked again (still this code, still
        // valid), cleared, and the settings written; any failure rolls everything back, code included.
        $db = App::db();
        $byId = (int) $s->fresh('sso_setup_by');
        $by = App::users()->find($byId);
        $changed = [];
        $db->beginTransaction();
        try {
            $rows = $db->query("SELECT name, value FROM settings WHERE name IN ('sso_setup_code', 'sso_setup_expires') FOR UPDATE")->fetchAll(\PDO::FETCH_KEY_PAIR);
            if (!hash_equals((string) ($rows['sso_setup_code'] ?? ''), $hash) || (int) ($rows['sso_setup_expires'] ?? 0) <= time()) {
                $db->rollBack();
                return $fail(403, 'raced', 'That setup code was just used. Create a new one on Sentinel\'s Integrations page.');
            }
            $s->set('sso_setup_code', '');
            if ($current !== '' && $current !== $tenant) {
                $changed['links_cleared'] = self::clearAllLinks();
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
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            error_log('[msp-sentinel] SSO setup: ' . $ex->getMessage());
            return self::json(500, false, 'Sentinel could not save the app details (see its PHP error log). Nothing was changed; run the script again with the same code.');
        }
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
            : 'Saved. In Sentinel, open Administration → Integrations and turn on "Sign in with Microsoft".');
    }

    /** The Admin who made the code may still change sign-in: active, every permission, every client. */
    private static function issuerOk(int $userId): bool
    {
        $stmt = App::db()->prepare('SELECT u.is_active, u.all_clients, r.* FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = :id');
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch();
        return $row !== false && (int) $row['is_active'] === 1 && (int) $row['all_clients'] === 1
            && Permissions::isComplete(App::roles()->permissionsOf($row));
    }

    private static function json(int $status, bool $ok, string $message): Response
    {
        return \Sentinel\Api\ApiKernel::json(['ok' => $ok, 'message' => $message], $status);
    }
}
