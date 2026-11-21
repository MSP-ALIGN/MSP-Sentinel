<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\Totp;
use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * Sign-in, second factor, 2FA enrolment and sign-out.
 *
 * Untrusted: every form field. Usernames, passwords and codes are only
 * compared, never echoed back except the username on a failed login
 * (escaped in the view).
 *
 * Security assumptions: see {@see \Sentinel\Auth\Auth} for the state machine,
 * throttling and session handling. The enrolment secret is kept server-side
 * in the session until the user proves they've saved it by entering a valid
 * code. Only then is it encrypted and stored.
 */
final class AuthController extends Controller
{
    /** GET /login */
    public function showLogin(Request $request): Response
    {
        if (App::auth()->user() !== null) {
            return Response::redirect('/');
        }
        return $this->authPage('auth/login', __('Sign in'), ['username' => '']);
    }

    /** POST /login */
    public function login(Request $request): Response
    {
        $username = $request->input('username');
        $result = App::auth()->attemptPassword($request, $username, $request->raw('password'));
        if (is_string($result)) {
            return $this->authPage('auth/login', __('Sign in'), ['username' => $username, 'error' => $result], 422);
        }
        App::auth()->beginPending($result);
        return Response::redirect($result['totp_enabled_at'] === null ? '/2fa/setup' : '/login/2fa');
    }

    /** GET /login/2fa */
    public function showSecondFactor(Request $request): Response
    {
        $user = App::auth()->pendingUser();
        if ($user === null) {
            return Response::redirect('/login');
        }
        if ($user['totp_enabled_at'] === null) {
            return Response::redirect('/2fa/setup');
        }
        return $this->authPage('auth/second_factor', __('Two-factor authentication'));
    }

    /** POST /login/2fa: a 6-digit app code or a recovery code. */
    public function verifySecondFactor(Request $request): Response
    {
        $auth = App::auth();
        $user = $auth->pendingUser();
        if ($user === null || $user['totp_enabled_at'] === null) {
            return Response::redirect('/login');
        }
        $id = (int) $user['id'];
        if ($auth->secondFactorLocked($id)) {
            Session::reset();
            Session::flash('danger', __('Too many incorrect codes. Please wait 15 minutes and sign in again.'));
            return Response::redirect('/login');
        }

        $code = $request->input('code');
        $method = null;
        if (preg_match('/^\d{3}\s?\d{3}$/', $code)) {
            $secret = App::crypto()->decrypt((string) $user['totp_secret_enc']);
            $step = Totp::verify($secret, $code, $user['totp_last_step'] === null ? null : (int) $user['totp_last_step']);
            if ($step !== null && App::users()->claimTotpStep($id, $step)) {
                $method = 'totp';
            }
        } elseif ($code !== '' && App::recoveryCodes()->consume($id, $code)) {
            $method = 'recovery_code';
        }

        if ($method === null) {
            $auth->secondFactorFailed($id, (string) $user['username'], $request);
            return $this->authPage('auth/second_factor', __('Two-factor authentication'),
                ['error' => __('That code is not valid. Codes can only be used once.')], 422);
        }

        $auth->completeLogin($user, $request, $method);
        if ($method === 'recovery_code') {
            $left = App::recoveryCodes()->remaining($id);
            Session::flash('warning', __('You signed in with a recovery code. {n} codes left. Create new ones from your profile if you are running low.', ['n' => $left]));
        }
        return Response::redirect('/');
    }

    /** GET /2fa/setup: forced enrolment for users without 2FA. */
    public function showEnrol(Request $request): Response
    {
        $user = App::auth()->pendingUser();
        if ($user === null) {
            return Response::redirect('/login');
        }
        if ($user['totp_enabled_at'] !== null) {
            return Response::redirect('/login/2fa');
        }
        return $this->renderEnrol($user);
    }

    /** POST /2fa/setup: confirm the first code, then save the secret. */
    public function enrol(Request $request): Response
    {
        $auth = App::auth();
        $user = $auth->pendingUser();
        if ($user === null || $user['totp_enabled_at'] !== null) {
            return Response::redirect('/login');
        }
        $id = (int) $user['id'];
        if ($auth->secondFactorLocked($id)) {
            Session::reset();
            Session::flash('danger', __('Too many incorrect codes. Please wait 15 minutes and sign in again.'));
            return Response::redirect('/login');
        }
        $secret = $this->enrolSecret($id);
        $step = Totp::verify($secret, $request->input('code'), null);
        if ($step === null) {
            $auth->secondFactorFailed($id, (string) $user['username'], $request);
            return $this->renderEnrol($user, __('That code is not valid. Check the time on your phone is correct and try again.'), 422);
        }

        $db = App::db();
        $db->beginTransaction();
        try {
            if (!App::users()->enableTotp($id, App::crypto()->encrypt($secret), $step)) {
                // A parallel request finished enrolment first. Use the normal 2FA prompt instead.
                $db->rollBack();
                return Response::redirect('/login/2fa');
            }
            $codes = App::recoveryCodes()->regenerate($id);
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $ex;
        }
        Session::remove('enrol_secret');
        App::audit()->log('auth.2fa_enrolled', $id, (string) $user['username'], 'user', $id, [], $request->ip());
        $auth->completeLogin($user, $request, 'totp_enrolment');
        // Shown once on the next page, then gone.
        Session::set('show_recovery_codes', $codes);
        return Response::redirect('/recovery-codes');
    }

    /** GET /recovery-codes: shows new codes once after enrolment or regeneration. */
    public function showRecoveryCodes(Request $request): Response
    {
        $codes = Session::get('show_recovery_codes');
        Session::remove('show_recovery_codes');
        if (!is_array($codes) || $codes === []) {
            return Response::redirect('/profile');
        }
        return $this->page('auth/recovery_codes', __('Your recovery codes'), ['codes' => $codes]);
    }

    /** POST /logout */
    public function logout(Request $request): Response
    {
        App::auth()->logout($request);
        Session::flash('success', __('You have been signed out.'));
        return Response::redirect('/login');
    }

    /** @param array<string,mixed> $user */
    private function renderEnrol(array $user, ?string $error = null, int $status = 200): Response
    {
        $secret = $this->enrolSecret((int) $user['id']);
        return $this->authPage('auth/enrol', __('Set up two-factor authentication'), [
            'secret' => $secret,
            'otpauth' => Totp::provisioningUri(App::productName(), (string) $user['username'], $secret),
            'error' => $error,
        ], $status);
    }

    /** The secret being enrolled, kept in the session for this user only. */
    private function enrolSecret(int $userId): string
    {
        $stored = Session::get('enrol_secret');
        if (is_array($stored) && ($stored['uid'] ?? null) === $userId && is_string($stored['secret'] ?? null)) {
            return $stored['secret'];
        }
        $secret = Totp::generateSecret();
        Session::set('enrol_secret', ['uid' => $userId, 'secret' => $secret]);
        return $secret;
    }
}
