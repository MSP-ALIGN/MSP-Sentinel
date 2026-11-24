<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\Permissions;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;

/**
 * Roles (1.40): the built-in Viewer, Technician and Admin (read-only) and custom roles made from the fixed permission
 * list (Sentinel\Auth\Permissions). Reached with the 'users.manage' permission (enforced by the routes).
 *
 * Untrusted: every form field (name, description, the permission list) and the {id} path parameter.
 *
 * Security assumptions (never more than you hold):
 * - A role can only be given permissions you hold yourself, and you can only change or delete a role whose
 *   current permissions you all hold, so nobody can raise anyone (or themselves, through a role) above their own
 *   rights, nor strip rights from someone more powerful.
 * - You can't change the role you have yourself (that would change your own rights).
 * - Built-in roles never change: what they hold is defined in code.
 * - Custom roles never affect the "one active Admin is always left" rule (UserController): only the built-in Admin
 *   counts, since it also holds every permission a later release adds.
 * - The checks run again inside the transaction with the role rows locked, so a role changed meanwhile by someone
 *   more powerful isn't saved over.
 * - Creating or changing a role is confirmed with your own password, and audited with what was added and removed.
 *   Everyone who has a changed role is signed out, so the change applies at once.
 */
final class RoleController extends Controller
{
    /** GET /admin/roles: every role, and a table of who can do what. */
    public function index(Request $request): Response
    {
        return $this->page('roles/index', __('Roles'), ['roles' => App::roles()->all(), 'groups' => Permissions::grouped()]);
    }

    /** GET /admin/roles/new (optionally ?copy={id}: start from that role's permissions). */
    public function create(Request $request): Response
    {
        $copy = ctype_digit($request->query('copy')) && strlen($request->query('copy')) < 10 ? App::roles()->find((int) $request->query('copy')) : null;
        return $this->form(null, [
            'name' => $copy !== null ? __('Copy of {name}', ['name' => role_label($copy)]) : '',
            'description' => (string) ($copy['description'] ?? ''),
            // Only what you hold is copied: the rest couldn't be saved anyway.
            'permissions' => array_values(array_intersect($copy['permissions'] ?? [], $this->held())),
        ], []);
    }

    /** POST /admin/roles */
    public function store(Request $request): Response
    {
        $values = $this->values($request);
        $errors = $this->validate($values, null);
        if ($errors === [] && ($why = $this->confirmWithOwnPassword($request)) !== null) {
            $errors['my_password'] = $why;
        }
        if ($errors !== []) {
            return $this->form(null, $values, $errors, 422);
        }
        $id = App::roles()->create($values['name'], $values['description'], $values['permissions'], (int) $this->user()['id']);
        $this->audit($request, 'role.created', 'role', $id, ['name' => $values['name'], 'permissions' => $values['permissions']]);
        Session::flash('success', __('Role {name} created. Give it to users on their account page.', ['name' => $values['name']]));
        return Response::redirect('/admin/roles');
    }

    /** GET /admin/roles/{id}: edit a custom role, or see what a built-in role holds. */
    public function edit(Request $request, array $params): Response
    {
        $role = $this->findOr404($params);
        return $this->form($role, ['name' => (string) $role['name'], 'description' => (string) $role['description'], 'permissions' => $role['permissions']], []);
    }

    /** POST /admin/roles/{id} */
    public function update(Request $request, array $params): Response
    {
        $role = $this->findOr404($params);
        $id = (int) $role['id'];
        if (($why = $this->whyLocked($role)) !== null) {
            throw new HttpException(403, $why);
        }
        $values = $this->values($request);
        $errors = $this->validate($values, $id);
        if ($errors === [] && ($why = $this->confirmWithOwnPassword($request)) !== null) {
            $errors['my_password'] = $why;
        }
        if ($errors !== []) {
            return $this->form($role, $values, $errors, 422);
        }
        $db = App::db();
        $db->beginTransaction();
        try {
            // Checked again with the rows locked (1.40.1): the role may have changed since the form was read, e.g.
            // someone more powerful added a permission you don't hold.
            App::roles()->lockForUpdate();
            $role = App::roles()->find($id) ?? throw new HttpException(404);
            $why = $this->whyLocked($role) ?? ($this->validate($values, $id)['permissions'] ?? null);
            if ($why !== null) {
                $db->rollBack();
                return $this->form($role, $values, ['permissions' => $why], 422);
            }
            App::roles()->update($id, $values['name'], $values['description'], $values['permissions']);
            $db->commit();
        } catch (\Throwable $ex) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $ex;
        }
        $this->audit($request, 'role.updated', 'role', $id, ['name' => $values['name'], 'renamed_from' => $role['name'] !== $values['name'] ? $role['name'] : null,
            'added' => array_values(array_diff($values['permissions'], $role['permissions'])), 'removed' => array_values(array_diff($role['permissions'], $values['permissions']))]);
        Session::flash('success', __('Role {name} saved. Users with this role were signed out so the change applies at once.', ['name' => $values['name']]));
        return Response::redirect('/admin/roles');
    }

    /** POST /admin/roles/{id}/delete: only a custom role nobody has. */
    public function delete(Request $request, array $params): Response
    {
        $role = $this->findOr404($params);
        if (($why = $this->whyLocked($role)) !== null) {
            throw new HttpException(403, $why);
        }
        if (!App::roles()->delete((int) $role['id'])) {
            Session::flash('danger', __('This role is still given to users (active or not). Give them another role first.'));
            return Response::redirect('/admin/roles/' . (int) $role['id']);
        }
        $this->audit($request, 'role.deleted', 'role', (int) $role['id'], ['name' => $role['name'], 'permissions' => $role['permissions']]);
        Session::flash('success', __('Role {name} deleted.', ['name' => $role['name']]));
        return Response::redirect('/admin/roles');
    }

    /**
     * Why the signed-in user can't change or delete this role, or null when they can: built-in roles never change,
     * your own role is off limits, and so is a role with permissions you don't hold.
     *
     * @param array<string,mixed> $role
     */
    private function whyLocked(array $role): ?string
    {
        if ($role['role_key'] !== null) {
            return __('Built-in roles can\'t be changed. Copy it to make a role of your own.');
        }
        if ((int) $role['id'] === (int) ($this->user()['role_id'] ?? 0)) {
            return __('This is your own role: someone else must change it.');
        }
        if (array_diff($role['permissions'], $this->held()) !== []) {
            return __('This role has permissions you don\'t hold, so you can\'t change it.');
        }
        return null;
    }

    /** @return array{name:string, description:string, permissions:list<string>} untrusted form values, cleaned */
    private function values(Request $request): array
    {
        return ['name' => trim($request->input('name')), 'description' => trim($request->input('description')),
                'permissions' => Permissions::clean($request->postList('permissions'))];
    }

    /**
     * @param array{name:string, description:string, permissions:list<string>} $values
     * @return array<string,string> field => message
     */
    private function validate(array $values, ?int $id): array
    {
        $errors = [];
        if (mb_strlen($values['name']) < 2 || mb_strlen($values['name']) > 80 || preg_match('/[\x00-\x1F\x7F]/u', $values['name']) === 1) {
            $errors['name'] = __('Enter a name of 2 to 80 characters.');
        } elseif (!App::roles()->nameFree($values['name'], $id)) {
            $errors['name'] = __('Another role already has this name.');
        }
        if (mb_strlen($values['description']) > 300 || preg_match('/[\x00-\x08\x0B-\x1F\x7F]/u', $values['description']) === 1) {
            $errors['description'] = __('Up to 300 characters.');
        }
        $beyond = array_diff($values['permissions'], $this->held());
        if ($beyond !== []) {
            $errors['permissions'] = __('You can only give permissions you hold yourself.');
        }
        return $errors;
    }

    /** @return list<string> what the signed-in user holds */
    private function held(): array
    {
        return (array) ($this->user()['permissions'] ?? []);
    }

    /**
     * @param array<string,mixed>|null $role null: a new role
     * @param array{name:string, description:string, permissions:list<string>} $values
     * @param array<string,string> $errors
     */
    private function form(?array $role, array $values, array $errors, int $status = 200): Response
    {
        $title = $role === null ? __('New role') : ($role['role_key'] !== null ? __('Built-in role: {name}', ['name' => role_label($role)]) : __('Edit role'));
        return $this->page('roles/form', $title, ['role' => $role, 'values' => $values, 'errors' => $errors, 'groups' => Permissions::grouped(),
            'held' => $this->held(), 'locked' => $role === null ? null : $this->whyLocked($role)], $status);
    }

    /** @return array<string,mixed> */
    private function findOr404(array $params): array
    {
        return App::roles()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }
}
