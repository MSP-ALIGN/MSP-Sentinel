<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\Auth;
use Sentinel\Auth\Passwords;
use Sentinel\Auth\Permissions;
use Sentinel\Auth\UserRepository;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * User management (the 'users.manage' permission: enforced by the routes).
 *
 * Untrusted: all form fields and the {id} path parameter (digits only,
 * but the user may not exist).
 *
 * Security assumptions:
 * - New users and password resets set a temporary password that must be
 *   changed at next sign-in. Every user must enrol 2FA at first sign-in.
 * - Never more than you hold (1.40): you can only give a role whose permissions you all hold yourself, and only edit,
 *   reset or disable a user whose role you could give. So someone allowed to manage users can't make anyone, or
 *   take over anyone, more powerful than themselves.
 * - Nobody changes their own role or disables themselves, and at least one active user always has the built-in Admin
 *   role (which holds every permission, now and in later releases; checked with the rows locked, so two people can't
 *   race it), so nobody gets locked out.
 * - Who may manage whom, and which role may be given, is checked again with the rows locked (1.40.1), so a role
 *   changed meanwhile by someone more powerful can't slip through.
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
            'values' => ['username' => '', 'display_name' => '', 'email' => '', 'role_id' => (int) App::roles()->idForKey('viewer'), 'is_active' => 1],
            'errors' => [],
            'roles' => $this->roleChoices(),
        ]);
    }

    /** POST /users */
    public function store(Request $request): Response
    {
        $values = [
            'username' => $request->input('username'),
            'display_name' => $request->input('display_name'),
            'email' => $request->input('email'),
            'role_id' => $this->roleIdFrom($request),
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
            return $this->page('users/form', __('Add user'), ['mode' => 'create', 'values' => $values, 'errors' => $errors, 'roles' => $this->roleChoices()], 422);
        }

        // The role is checked again with the role rows locked (1.40.1): it may have been changed or deleted meanwhile.
        $db = App::db();
        $db->beginTransaction();
        try {
            App::roles()->lockForUpdate();
            if (($again = $this->validateAccount($values)) !== []) {
                $db->rollBack();
                return $this->page('users/form', __('Add user'), ['mode' => 'create', 'values' => $values, 'errors' => $again, 'roles' => $this->roleChoices()], 422);
            }
            $id = App::users()->create($values['username'], $values['display_name'], $values['email'], (int) $values['role_id'], Passwords::hash($password), true);
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $ex;
        }
        $this->audit($request, 'user.created', 'user', $id, ['username' => $values['username'], 'role' => $this->roleName((int) $values['role_id'])]);
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
            'roles' => $this->roleChoices(),
            'outranks' => !$this->mayManage($target),
        ]);
    }

    /** POST /users/{id} */
    public function update(Request $request, array $params): Response
    {
        $target = $this->findOr404($params);
        $id = (int) $target['id'];
        $isSelf = $id === (int) $this->user()['id'];
        // Someone more powerful than you can't be edited by you at all (not even their name).
        if (!$isSelf && !$this->mayManage($target)) {
            throw new HttpException(403, __('This user\'s role has permissions you don\'t hold, so you can\'t change their account.'));
        }
        $values = [
            'username' => $target['username'],
            'display_name' => $request->input('display_name'),
            'email' => $request->input('email'),
            // Nobody changes their own role or active flag.
            'role_id' => $isSelf ? (int) $target['role_id'] : $this->roleIdFrom($request),
            'is_active' => $isSelf ? 1 : ($request->input('is_active') === '1' ? 1 : 0),
        ];
        $roleChanged = (int) $values['role_id'] !== (int) $target['role_id'];
        $accessChanged = $roleChanged || $values['is_active'] !== (int) $target['is_active'];
        $errors = $this->validateAccount($values, $roleChanged);
        // Changing someone's role or access is confirmed with your own password.
        if ($errors === [] && $accessChanged && ($why = $this->confirmWithOwnPassword($request)) !== null) {
            $errors['my_password'] = $why;
        }
        $renderErrors = fn (array $errs): Response => $this->page('users/form', __('Edit user'), [
            'mode' => 'edit', 'target' => UserRepository::publicFields($target), 'values' => $values, 'errors' => $errs, 'isSelf' => $isSelf,
            'roles' => $this->roleChoices(), 'outranks' => false,
        ], 422);
        if ($errors !== []) {
            return $renderErrors($errors);
        }

        // The "one active Admin always stays" check and the update run in one transaction with the role and
        // user rows locked, so two people demoting each other at once can't leave nobody able to do everything.
        $db = App::db();
        $db->beginTransaction();
        try {
            App::roles()->lockForUpdate();
            $fresh = App::users()->find($id) ?? throw new HttpException(404);
            if (!$isSelf && !$this->mayManage($fresh)) {
                $db->rollBack();
                throw new HttpException(403, __('This user\'s role has permissions you don\'t hold, so you can\'t change their account.'));
            }
            if ($roleChanged && ($again = $this->validateAccount($values)) !== []) {
                $db->rollBack();
                return $renderErrors($again);
            }
            if ($accessChanged && App::roles()->completeHoldersAfter($id, (int) $values['role_id'], $values['is_active'] === 1) < 1) {
                $db->rollBack();
                return $renderErrors(['role_id' => __('This is the last active Admin. Make another user an Admin first.')]);
            }
            App::users()->updateAccount($id, $values['display_name'], $values['email'], (int) $values['role_id'], $values['is_active'] === 1, $accessChanged);
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $ex;
        }
        $changes = [];
        foreach (['display_name', 'email', 'is_active'] as $field) {
            if ((string) $target[$field] !== (string) $values[$field]) {
                $changes[$field] = ['from' => $target[$field], 'to' => $values[$field]];
            }
        }
        if ($roleChanged) {
            $changes['role'] = ['from' => (string) ($target['role_name'] ?? ''), 'to' => $this->roleName((int) $values['role_id'])];
        }
        $this->audit($request, 'user.updated', 'user', $id, ['changes' => $changes]);
        if ($isSelf && $accessChanged) {
            // Not reachable today (nobody can change their own access), but keep this session valid if it ever is.
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
        if (!$this->mayManage($target)) {
            throw new HttpException(403, __('This user\'s role has permissions you don\'t hold, so you can\'t reset their password.'));
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
        if (!$this->mayManage($target)) {
            throw new HttpException(403, __('This user\'s role has permissions you don\'t hold, so you can\'t reset their two-factor authentication.'));
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
     * Validate the editable account fields. The role must exist and be one you may give (all its permissions held by
     * you), unless $checkRole is false (an unchanged role on an edit: you may already be unable to give it, e.g. a
     * name fix on a peer).
     *
     * @param array<string,mixed> $values Untrusted form values.
     * @return array<string,string> field => error message
     */
    private function validateAccount(array $values, bool $checkRole = true): array
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
        if ($checkRole) {
            $role = $values['role_id'] > 0 ? App::roles()->find((int) $values['role_id']) : null;
            if ($role === null) {
                $errors['role_id'] = __('Choose a role.');
            } elseif (!$this->holdsAll($role['permissions'])) {
                $errors['role_id'] = __('You can only give a role whose permissions you hold yourself.');
            }
        }
        return $errors;
    }

    /** The role field: a role ID, or a built-in role's key (viewer, technician, admin). 0 when neither. */
    private function roleIdFrom(Request $request): int
    {
        $raw = $request->input('role_id') !== '' ? $request->input('role_id') : $request->input('role');
        if (ctype_digit($raw) && strlen($raw) < 10) {
            return (int) $raw;
        }
        return in_array($raw, Permissions::BUILTIN, true) ? (int) App::roles()->idForKey($raw) : 0;
    }

    /** @param list<string> $permissions True when the signed-in user holds every one of them. */
    private function holdsAll(array $permissions): bool
    {
        return array_diff($permissions, (array) ($this->user()['permissions'] ?? [])) === [];
    }

    /** True when the signed-in user may manage this user: they hold every permission of the user's role. */
    private function mayManage(array $target): bool
    {
        return $this->holdsAll(App::users()->permissions($target));
    }

    /**
     * Every role for the role picker, marking those you may give.
     *
     * @return list<array{id:int, name:string, description:string, allowed:bool, builtin:bool}>
     */
    private function roleChoices(): array
    {
        return array_map(fn (array $r): array => ['id' => (int) $r['id'], 'name' => (string) $r['name'], 'description' => (string) $r['description'],
            'allowed' => $this->holdsAll($r['permissions']), 'builtin' => $r['role_key'] !== null], App::roles()->all());
    }

    private function roleName(int $roleId): string
    {
        return (string) (App::roles()->find($roleId)['name'] ?? '');
    }

    /** @return array<string,mixed> */
    private function findOr404(array $params): array
    {
        return App::users()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }
}
