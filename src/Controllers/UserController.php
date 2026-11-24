<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\Auth;
use Sentinel\Auth\Passwords;
use Sentinel\Auth\Role;
use Sentinel\Auth\UserRepository;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * User management (admin only: enforced by the routes).
 *
 * Untrusted: all form fields and the {id} path parameter (digits only,
 * but the user may not exist).
 *
 * Security assumptions:
 * - New users and password resets set a temporary password that must be
 *   changed at next sign-in. Every user must enrol 2FA at first sign-in.
 * - Admins can't change their own role or disable themselves, and the last
 *   active admin can't be demoted or disabled, so nobody gets locked out.
 * - Every change is written to the audit log, without passwords.
 */
final class UserController extends Controller
{
    /** GET /users */
    public function index(Request $request): Response
    {
        return $this->page('users/index', __('Users'), ['users' => App::users()->all()]);
    }

    /** GET /users/new */
    public function create(Request $request): Response
    {
        return $this->page('users/form', __('Add user'), [
            'mode' => 'create',
            'values' => ['username' => '', 'display_name' => '', 'email' => '', 'role' => Role::VIEWER, 'is_active' => 1],
            'errors' => [],
        ]);
    }

    /** POST /users */
    public function store(Request $request): Response
    {
        $values = [
            'username' => $request->input('username'),
            'display_name' => $request->input('display_name'),
            'email' => $request->input('email'),
            'role' => $request->input('role'),
            'is_active' => 1,
        ];
        $password = $request->raw('password');
        $errors = $this->validateAccount($values);
        if (!Auth::isValidUsername($values['username'])) {
            $errors['username'] = __('Use 3 to 50 letters, digits, dots, dashes or underscores.');
        } elseif (App::users()->findByUsername($values['username']) !== null) {
            $errors['username'] = __('That username is already taken.');
        }
        if (($policy = Passwords::policyError($password, $values['username'])) !== null) {
            $errors['password'] = $policy;
        }
        // A new account is as powerful as its role: your own password confirms it (1.34 audit: a stolen session must
        // not be able to make itself a permanent account). Checked last, so a typo elsewhere doesn't count as a failure.
        if ($errors === [] && ($why = $this->confirmWithOwnPassword($request)) !== null) {
            $errors['my_password'] = $why;
        }
        if ($errors !== []) {
            return $this->page('users/form', __('Add user'), ['mode' => 'create', 'values' => $values, 'errors' => $errors], 422);
        }

        $id = App::users()->create($values['username'], $values['display_name'], $values['email'], $values['role'], Passwords::hash($password), true);
        $this->audit($request, 'user.created', 'user', $id, ['username' => $values['username'], 'role' => $values['role']]);
        Session::flash('success', __('User {name} created. They must change the temporary password and set up two-factor authentication at first sign-in.', ['name' => $values['username']]));
        return Response::redirect('/users');
    }

    /** GET /users/{id} */
    public function edit(Request $request, array $params): Response
    {
        $target = $this->findOr404($params);
        return $this->page('users/form', __('Edit user'), [
            'mode' => 'edit',
            'target' => UserRepository::publicFields($target),
            'values' => UserRepository::publicFields($target),
            'errors' => [],
            'isSelf' => (int) $target['id'] === (int) $this->user()['id'],
        ]);
    }

    /** POST /users/{id} */
    public function update(Request $request, array $params): Response
    {
        $target = $this->findOr404($params);
        $id = (int) $target['id'];
        $isSelf = $id === (int) $this->user()['id'];
        $values = [
            'username' => $target['username'],
            'display_name' => $request->input('display_name'),
            'email' => $request->input('email'),
            // Admins can't change their own role or active flag.
            'role' => $isSelf ? (string) $target['role'] : $request->input('role'),
            'is_active' => $isSelf ? 1 : ($request->input('is_active') === '1' ? 1 : 0),
        ];
        $errors = $this->validateAccount($values);
        // Changing someone's role or access is confirmed with the admin's own password.
        if (($values['role'] !== (string) $target['role'] || $values['is_active'] !== (int) $target['is_active']) && ($why = $this->confirmWithOwnPassword($request)) !== null) {
            $errors['my_password'] = $why;
        }
        $losesAdmin = $target['role'] === Role::ADMIN && (int) $target['is_active'] === 1
            && ($values['role'] !== Role::ADMIN || $values['is_active'] !== 1);
        $accessChanged = $values['role'] !== (string) $target['role'] || $values['is_active'] !== (int) $target['is_active'];
        $renderErrors = fn (array $errs): Response => $this->page('users/form', __('Edit user'), [
            'mode' => 'edit', 'target' => UserRepository::publicFields($target), 'values' => $values, 'errors' => $errs, 'isSelf' => $isSelf,
        ], 422);
        if ($errors !== []) {
            return $renderErrors($errors);
        }

        // The last-admin check and the update run in one transaction with the admin rows
        // locked, so two admins demoting each other at once can't leave zero admins.
        $db = App::db();
        $db->beginTransaction();
        try {
            if ($losesAdmin && App::users()->countActiveAdminsForUpdate() <= 1) {
                $db->rollBack();
                return $renderErrors(['role' => __('This is the last active admin. Make another user an admin first.')]);
            }
            App::users()->updateAccount($id, $values['display_name'], $values['email'], $values['role'], $values['is_active'] === 1, $accessChanged);
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $ex;
        }
        $changes = [];
        foreach (['display_name', 'email', 'role', 'is_active'] as $field) {
            if ((string) $target[$field] !== (string) $values[$field]) {
                $changes[$field] = ['from' => $target[$field], 'to' => $values[$field]];
            }
        }
        $this->audit($request, 'user.updated', 'user', $id, ['changes' => $changes]);
        if ($isSelf && $accessChanged) {
            // Not reachable today (admins can't change their own access), but keep this session valid if it ever is.
            App::auth()->refreshSessionVersion();
        }
        Session::flash('success', __('User {name} updated.', ['name' => $target['username']]));
        return Response::redirect('/users');
    }

    /** POST /users/{id}/password: set a temporary password. */
    public function resetPassword(Request $request, array $params): Response
    {
        $target = $this->findOr404($params);
        $id = (int) $target['id'];
        if ($id === (int) $this->user()['id']) {
            Session::flash('warning', __('Change your own password from your profile.'));
            return Response::redirect('/users/' . $id);
        }
        if (($why = $this->confirmWithOwnPassword($request)) !== null) {
            Session::flash('danger', $why);
            return Response::redirect('/users/' . $id);
        }
        $password = $request->raw('password');
        if (($policy = Passwords::policyError($password, (string) $target['username'])) !== null) {
            Session::flash('danger', $policy);
            return Response::redirect('/users/' . $id);
        }
        App::users()->setPassword($id, Passwords::hash($password), true);
        $this->audit($request, 'user.password_reset', 'user', $id);
        Session::flash('success', __('Temporary password set for {name}. They must change it at next sign-in.', ['name' => $target['username']]));
        return Response::redirect('/users/' . $id);
    }

    /** POST /users/{id}/2fa-reset: needs a new temporary password; the user must enrol again at next sign-in. */
    public function resetTwoFactor(Request $request, array $params): Response
    {
        $target = $this->findOr404($params);
        $id = (int) $target['id'];
        if ($id === (int) $this->user()['id']) {
            Session::flash('warning', __('You cannot reset your own two-factor authentication. Ask another admin.'));
            return Response::redirect('/users/' . $id);
        }
        if (($why = $this->confirmWithOwnPassword($request)) !== null) {
            Session::flash('danger', $why);
            return Response::redirect('/users/' . $id);
        }
        $password = $request->raw('password');
        if (($policy = Passwords::policyError($password, (string) $target['username'])) !== null) {
            Session::flash('danger', __('A new temporary password is required when resetting two-factor authentication.') . ' ' . $policy);
            return Response::redirect('/users/' . $id);
        }
        App::users()->resetTotp($id, Passwords::hash($password));
        $this->audit($request, 'user.2fa_reset', 'user', $id, ['password_reset' => true]);
        Session::flash('success', __('Two-factor authentication reset for {name}. Give them the new temporary password directly. They will change it and set up 2FA again at next sign-in.', ['name' => $target['username']]));
        return Response::redirect('/users/' . $id);
    }

    /**
     * Validate the editable account fields.
     *
     * @param array<string,mixed> $values Untrusted form values.
     * @return array<string,string> field => error message
     */
    private function validateAccount(array $values): array
    {
        $errors = [];
        $name = (string) $values['display_name'];
        if ($name === '' || mb_strlen($name) > 100 || preg_match('/[\x00-\x1F\x7F]/u', $name)) {
            $errors['display_name'] = __('Enter a name of up to 100 characters.');
        }
        $email = (string) $values['email'];
        if ($email !== '' && (mb_strlen($email) > 190 || filter_var($email, FILTER_VALIDATE_EMAIL) === false)) {
            $errors['email'] = __('Enter a valid email address, or leave it empty.');
        }
        if (!Role::isValid((string) $values['role'])) {
            $errors['role'] = __('Choose a role.');
        }
        return $errors;
    }

    /** @return array<string,mixed> */
    private function findOr404(array $params): array
    {
        return App::users()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }
}
