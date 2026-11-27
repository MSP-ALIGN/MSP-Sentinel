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
 * "Sign in with Microsoft" (1.43): the OpenID Connect steps (EntraSso does the protocol), for signing in and for
 * linking a Microsoft account to your own Sentinel user.
 *
 * Untrusted: the query string Microsoft sends the browser back with (state, code, error), and every claim, which
 * EntraSso checks first.
 *
 * Security assumptions:
 * - state, nonce and the PKCE verifier are random, kept in this browser's session only, and used once; a callback
 *   without the matching state is refused (no sign-in started here, or a forged link).
 * - Signing in only works for a Microsoft account already linked to a user (tenant + object ID). Linking happens only
 *   from My profile, by a user who is signed in with their password and Sentinel's two-factor (1.43.1): both
 *   identities are proven, so nobody can claim another person's account through an email address an Entra admin, a
 *   helpdesk or a guest invitation can set. No account is ever created.
 * - Guests from other directories are refused (EntraSso). Sentinel's own two-factor step is skipped only when
 *   Microsoft says MFA was done within the last hour; otherwise it is asked exactly as after a password.
 * - Failures are rate limited per address and audited, without tokens.
 */
final class SsoController extends Controller
{
    private const MAX_FAILS = 20;
    private const WINDOW = 900;
    private const STATE_TTL = 600;

    /** GET /login/sso: send the browser to Microsoft to sign in. */
    public function start(Request $request): Response
    {
        if (App::auth()->user() !== null) {
            return Response::redirect('/');
        }
        return $this->toMicrosoft('signin', null, '/login');
    }

    /**
     * POST /profile/sso-link: link a Microsoft account to the signed-in user (they prove it at Microsoft next).
     * Needs their own password now (1.43.2: a stolen session alone can't plant a lasting Microsoft sign-in), and no
     * existing link (unlink first, so a link is never replaced quietly).
     */
    public function link(Request $request): Response
    {
        $me = $this->user();
        if (($me['sso_subject'] ?? null) !== null) {
            Session::flash('warning', __('A Microsoft account is already linked. Unlink it first.'));
            return Response::redirect('/profile');
        }
        if (($why = $this->confirmWithOwnPassword($request)) !== null) {
            Session::flash('danger', $why);
            return Response::redirect('/profile');
        }
        return $this->toMicrosoft('link', (int) $me['id'], '/profile');
    }

    /** POST /profile/sso-unlink: forget your own Microsoft link (not while password sign-in is off: you'd be locked out). */
    public function unlink(Request $request): Response
    {
        $me = $this->user();
        if ((int) ($me['password_login'] ?? 1) === 0) {
            Session::flash('warning', __('Password sign-in is turned off for your account, so your Microsoft link must stay. Ask an admin.'));
            return Response::redirect('/profile');
        }
        App::db()->prepare("UPDATE users SET sso_subject = NULL, sso_name = '', updated_at = UTC_TIMESTAMP() WHERE id = :id")->execute(['id' => (int) $me['id']]);
        $this->audit($request, 'user.sso_unlinked', 'user', (int) $me['id']);
        Session::flash('success', __('Your Microsoft account is no longer linked.'));
        return Response::redirect('/profile');
    }

    /** GET /login/sso/callback: Microsoft sends the browser back here with a one-time code. */
    public function callback(Request $request): Response
    {
        $flow = Session::get('sso_flow');
        Session::remove('sso_flow'); // one use, whatever happens next
        $mode = is_array($flow) && ($flow['mode'] ?? '') === 'link' ? 'link' : 'signin';
        $back = $mode === 'link' ? '/profile' : '/login';
        $limiter = App::limiter();
        $bucket = 'sso-ip:' . \Sentinel\Auth\Auth::ipBucketKey($request->ip());
        $fail = function (string $reason, string $shown) use ($request, $limiter, $bucket, $back): Response {
            $limiter->hit($bucket);
            App::audit()->log('auth.sso_failed', null, null, null, null, ['reason' => mb_substr($reason, 0, 200)], $request->ip());
            Session::flash('danger', $shown);
            return Response::redirect($back);
        };
        if ($limiter->tooMany($bucket, self::MAX_FAILS, self::WINDOW)) {
            Session::flash('danger', __('Too many sign-in attempts. Try again in 15 minutes.'));
            return Response::redirect($back);
        }
        if (!is_array($flow) || !is_string($flow['state'] ?? null) || !is_int($flow['at'] ?? null) || time() - $flow['at'] > self::STATE_TTL
            || !hash_equals($flow['state'], $request->query('state'))) {
            return $fail('state', __('That sign-in link has expired or was not started here. Try again.'));
        }
        if ($request->query('error') !== '') {
            return $fail('microsoft:' . preg_replace('/[^a-z_]/', '', $request->query('error')), __('Microsoft sign-in was canceled or refused.'));
        }
        $sso = App::entraSso($mode === 'link'); // linking works before the sign-in button is switched on (1.63.1)
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
        $owner = $find->fetchColumn();

        if ($mode === 'link') {
            // The signed-in user who started it, still the same session.
            $me = App::auth()->user();
            if ($me === null || (int) $me['id'] !== (int) ($flow['uid'] ?? 0)) {
                return $fail('link_session', __('Sign in again, then link your Microsoft account.'));
            }
            if ($owner !== false && (int) $owner !== (int) $me['id']) {
                return $fail('link_taken', __('This Microsoft account is already linked to another Sentinel user.'));
            }
            // Which account it is, shown on My profile and the user's page (display only).
            $label = mb_substr(trim($who['name'] . ($who['email'] !== '' ? ' <' . $who['email'] . '>' : '')), 0, 300);
            $set = $db->prepare('UPDATE users SET sso_subject = :s, sso_name = :n, updated_at = UTC_TIMESTAMP() WHERE id = :id AND sso_subject IS NULL');
            try {
                $set->execute(['s' => $subject, 'n' => $label, 'id' => (int) $me['id']]);
            } catch (\PDOException $ex) {
                if ((string) $ex->getCode() !== '23000') {
                    throw $ex; // only the unique key (a race lost) means "taken"
                }
                return $fail('link_taken', __('This Microsoft account is already linked to another Sentinel user.'));
            }
            if ($set->rowCount() !== 1) {
                return $fail('link_exists', __('A Microsoft account is already linked. Unlink it first.'));
            }
            App::audit()->log('user.sso_linked', (int) $me['id'], (string) $me['username'], 'user', (int) $me['id'], ['email' => $who['email']], $request->ip());
            // Tell the user in-app too, so a link they didn't make is noticed.
            $db->prepare("INSERT INTO notifications (user_id, kind, severity, title, body, link, created_at) VALUES (:u, 'security', 'warn', :t, :b, '/profile', UTC_TIMESTAMP())")
                ->execute(['u' => (int) $me['id'], 't' => mb_substr(__('A Microsoft account was linked to your Sentinel user'), 0, 300),
                           'b' => mb_substr(__('{who} can now sign in as you. If this wasn\'t you, unlink it under My profile and tell an admin.', ['who' => $label]), 0, 2000)]);
            $limiter->clear($bucket);
            // 1.63.1: linking works before the sign-in button is on; say which it is.
            Session::flash('success', App::entraSso() !== null ? __('Your Microsoft account is linked. You can now use "Sign in with Microsoft".')
                : __('Your Microsoft account is linked. "Sign in with Microsoft" works once an admin turns it on under Integrations; until then, sign in with your password.'));
            return Response::redirect('/profile');
        }

        if ($owner === false) {
            return $fail('not_linked', __('This Microsoft account is not linked to a Sentinel user. Sign in with your password once, then link it under My profile.'));
        }
        $user = App::users()->find((int) $owner);
        if ($user === null || (int) $user['is_active'] !== 1) {
            return $fail('inactive', __('This account is disabled.'));
        }
        $limiter->clear($bucket);
        // 1.64: the admin may trust Microsoft's sign-in for the second step (they confirmed Entra enforces MFA).
        $trusted = App::settings()->fresh('sso_trust_mfa') === '1';
        if ($who['mfa'] || $trusted) {
            if (!$who['mfa']) {
                App::audit()->log('auth.sso_trusted', (int) $user['id'], (string) $user['username'], null, null, ['mfa' => 'trusted (admin setting)'], $request->ip());
            }
            App::auth()->completeLogin($user, $request, 'sso');
            return Response::redirect('/');
        }
        // Microsoft didn't confirm a recent MFA: Sentinel's own code, as after a password.
        App::audit()->log('auth.sso_verified', (int) $user['id'], (string) $user['username'], null, null, ['mfa' => false], $request->ip());
        App::auth()->beginPending($user);
        return Response::redirect($user['totp_enabled_at'] === null ? '/2fa/setup' : '/login/2fa');
    }

    /** Start a flow: remember state, nonce and verifier in this session, then send the browser to Microsoft. */
    private function toMicrosoft(string $mode, ?int $uid, string $back): Response
    {
        $sso = App::entraSso($mode === 'link');
        $redirect = App::ssoRedirectUri();
        if ($sso === null || $redirect === '') {
            Session::flash('warning', __('Sign in with Microsoft is not set up. Ask an admin.'));
            return Response::redirect($back);
        }
        $flow = ['mode' => $mode, 'uid' => $uid, 'state' => EntraSso::random(), 'nonce' => EntraSso::random(), 'verifier' => EntraSso::random(), 'at' => time()];
        Session::set('sso_flow', $flow);
        return Response::redirectExternal($sso->authorizeUrl($redirect, $flow['state'], $flow['nonce'], $flow['verifier']));
    }
}
