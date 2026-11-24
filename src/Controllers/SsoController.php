<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\EntraSso;
use Sentinel\Auth\SsoException;
use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * "Sign in with Microsoft" (1.43): the two public steps of the OpenID Connect sign-in (EntraSso does the protocol).
 *
 * Untrusted: the query string Microsoft sends the browser back with (state, code, error), and every claim, which
 * EntraSso checks first.
 *
 * Security assumptions:
 * - state, nonce and the PKCE verifier are random, kept in this browser's session only, and used once; a callback
 *   without the matching state is refused (no sign-in started here, or a forged link).
 * - Only users who already exist sign in (no account is ever created): matched by the linked Microsoft account
 *   (tenant + object ID), else, the first time, by the account's email address equal to exactly one active user's
 *   email, and then linked. The tenant check means only your own directory's accounts can match.
 * - Sentinel's own two-factor step is skipped only when Microsoft says MFA was done (amr "mfa"); otherwise the user
 *   goes through Sentinel's code exactly as after a password. Permissions and clients come from Sentinel as always.
 * - Failures are rate limited per address and audited, without tokens.
 */
final class SsoController extends Controller
{
    private const MAX_FAILS = 20;
    private const WINDOW = 900;
    private const STATE_TTL = 600;

    /** GET /login/sso: send the browser to Microsoft. */
    public function start(Request $request): Response
    {
        if (App::auth()->user() !== null) {
            return Response::redirect('/');
        }
        $sso = App::entraSso();
        $redirect = App::ssoRedirectUri();
        if ($sso === null || $redirect === '') {
            Session::flash('warning', __('Sign in with Microsoft is not set up. Sign in with your password, or ask an admin.'));
            return Response::redirect('/login');
        }
        $flow = ['state' => EntraSso::random(), 'nonce' => EntraSso::random(), 'verifier' => EntraSso::random(), 'at' => time()];
        Session::set('sso_flow', $flow);
        return Response::redirectExternal($sso->authorizeUrl($redirect, $flow['state'], $flow['nonce'], $flow['verifier']));
    }

    /** GET /login/sso/callback: Microsoft sends the browser back here with a one-time code. */
    public function callback(Request $request): Response
    {
        $flow = Session::get('sso_flow');
        Session::remove('sso_flow'); // one use, whatever happens next
        $limiter = App::limiter();
        $bucket = 'sso-ip:' . \Sentinel\Auth\Auth::ipBucketKey($request->ip());
        $fail = function (string $reason, string $shown) use ($request, $limiter, $bucket): Response {
            $limiter->hit($bucket);
            App::audit()->log('auth.sso_failed', null, null, null, null, ['reason' => mb_substr($reason, 0, 200)], $request->ip());
            Session::flash('danger', $shown);
            return Response::redirect('/login');
        };
        if ($limiter->tooMany($bucket, self::MAX_FAILS, self::WINDOW)) {
            Session::flash('danger', __('Too many sign-in attempts. Try again in 15 minutes.'));
            return Response::redirect('/login');
        }
        if (!is_array($flow) || !is_string($flow['state'] ?? null) || !is_int($flow['at'] ?? null) || time() - $flow['at'] > self::STATE_TTL
            || !hash_equals($flow['state'], $request->query('state'))) {
            return $fail('state', __('That sign-in link has expired or was not started here. Try "Sign in with Microsoft" again.'));
        }
        if ($request->query('error') !== '') {
            return $fail('microsoft:' . preg_replace('/[^a-z_]/', '', $request->query('error')), __('Microsoft sign-in was cancelled or refused.'));
        }
        $sso = App::entraSso();
        if ($sso === null || App::ssoRedirectUri() === '') {
            return $fail('not_configured', __('Sign in with Microsoft is not set up.'));
        }
        try {
            $who = $sso->signIn($request->query('code'), App::ssoRedirectUri(), (string) $flow['verifier'], (string) $flow['nonce']);
        } catch (SsoException $ex) {
            return $fail($ex->getMessage(), __('Microsoft sign-in did not work: {why}', ['why' => $ex->getMessage()]));
        }
        $subject = $who['tid'] . ':' . $who['oid'];
        $db = App::db();
        $find = $db->prepare('SELECT id FROM users WHERE sso_subject = :s');
        $find->execute(['s' => $subject]);
        $id = $find->fetchColumn();
        if ($id === false) {
            // First sign-in: exactly one active, not yet linked user with this email address.
            $byEmail = $who['email'] === '' ? [] : (function () use ($db, $who): array {
                $q = $db->prepare('SELECT id, sso_subject FROM users WHERE LOWER(email) = :e AND is_active = 1');
                $q->execute(['e' => $who['email']]);
                return $q->fetchAll();
            })();
            if (count($byEmail) !== 1 || $byEmail[0]['sso_subject'] !== null) {
                return $fail('no_account', __('No Sentinel account matches this Microsoft account. Ask an admin to add you with the same email address.'));
            }
            $id = (int) $byEmail[0]['id'];
            $db->prepare('UPDATE users SET sso_subject = :s, updated_at = UTC_TIMESTAMP() WHERE id = :id AND sso_subject IS NULL')->execute(['s' => $subject, 'id' => $id]);
            App::audit()->log('user.sso_linked', $id, null, 'user', $id, ['email' => $who['email']], $request->ip());
        }
        $user = App::users()->find((int) $id);
        if ($user === null || (int) $user['is_active'] !== 1) {
            return $fail('inactive', __('This account is disabled.'));
        }
        $limiter->clear($bucket);
        if ($who['mfa']) {
            App::auth()->completeLogin($user, $request, 'sso');
            return Response::redirect('/');
        }
        // Microsoft didn't confirm MFA: Sentinel's own code, as after a password.
        App::audit()->log('auth.sso_verified', (int) $user['id'], (string) $user['username'], null, null, ['mfa' => false], $request->ip());
        App::auth()->beginPending($user);
        return Response::redirect($user['totp_enabled_at'] === null ? '/2fa/setup' : '/login/2fa');
    }
}
