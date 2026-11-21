<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\Passwords;
use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * The signed-in user's own profile: password change and recovery codes.
 *
 * Untrusted: all form fields.
 *
 * Security assumptions:
 * - Sensitive changes need the current password (re-authentication), so a
 *   session left open on a desk can't be used to take the account over.
 * - Wrong current passwords are throttled (5 in 15 minutes per user).
 * - Changing the password ends all of the user's other sessions.
 */
final class ProfileController extends Controller
{
    private const REAUTH_MAX_FAILS = 5;
    private const REAUTH_WINDOW = 900;

    /** GET /profile */
    public function index(Request $request): Response
    {
        $user = $this->user();
        return $this->page('profile/index', __('My profile'), [
            'recoveryLeft' => App::recoveryCodes()->remaining((int) $user['id']),
        ]);
    }

    /** GET /profile/password */
    public function showPassword(Request $request): Response
    {
        return $this->page('profile/password', __('Change password'), ['errors' => []]);
    }

    /** POST /profile/password */
    public function changePassword(Request $request): Response
    {
        $user = $this->user();
        $id = (int) $user['id'];
        $errors = [];
        $current = $request->raw('current_password');
        $new = $request->raw('new_password');

        if (($reauthError = $this->checkCurrentPassword($request, $user, $current)) !== null) {
            $errors['current_password'] = $reauthError;
        }
        if (($policy = Passwords::policyError($new, (string) $user['username'])) !== null) {
            $errors['new_password'] = $policy;
        } elseif (!hash_equals($new, $request->raw('confirm_password'))) {
            $errors['confirm_password'] = __('The two new passwords do not match.');
        } elseif ($errors === [] && Passwords::verify($new, (string) $user['password_hash'])) {
            $errors['new_password'] = __('Choose a password different from the current one.');
        }
        if ($errors !== []) {
            return $this->page('profile/password', __('Change password'), ['errors' => $errors], 422);
        }

        App::users()->setPassword($id, Passwords::hash($new), false);
        App::auth()->refreshSessionVersion();
        $this->audit($request, 'user.password_changed', 'user', $id);
        Session::flash('success', __('Your password has been changed. Other sessions have been signed out.'));
        return Response::redirect('/');
    }

    /** POST /profile/recovery-codes: replace recovery codes (needs the current password). */
    public function regenerateRecoveryCodes(Request $request): Response
    {
        $user = $this->user();
        $id = (int) $user['id'];
        if (($error = $this->checkCurrentPassword($request, $user, $request->raw('current_password'))) !== null) {
            Session::flash('danger', $error);
            return Response::redirect('/profile');
        }
        $codes = App::recoveryCodes()->regenerate($id);
        $this->audit($request, 'user.recovery_codes_regenerated', 'user', $id);
        Session::set('show_recovery_codes', $codes);
        return Response::redirect('/recovery-codes');
    }

    /**
     * Re-authenticate with the current password, with throttling.
     *
     * @param array<string,mixed> $user
     * @return string|null Error message, or null when the password is right.
     */
    private function checkCurrentPassword(Request $request, array $user, string $password): ?string
    {
        $bucket = 'reauth-user:' . (int) $user['id'];
        $limiter = App::limiter();
        if ($limiter->tooMany($bucket, self::REAUTH_MAX_FAILS, self::REAUTH_WINDOW)) {
            return __('Too many failed attempts. Please wait 15 minutes and try again.');
        }
        if ($password === '' || !Passwords::verify($password, (string) $user['password_hash'])) {
            $limiter->hit($bucket);
            $this->audit($request, 'auth.reauth_failed', 'user', (int) $user['id']);
            return __('Your current password is not correct.');
        }
        $limiter->clear($bucket);
        return null;
    }
}
