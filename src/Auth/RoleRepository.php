<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use PDO;

/**
 * Roles and what they hold (1.40). Built-in roles (role_key 'viewer', 'technician', 'admin') take their permissions
 * from code (Permissions::builtin) and can't be edited or deleted; custom roles keep theirs in role_permissions.
 *
 * Untrusted: names, descriptions and permission lists from the Roles form (cleaned here: permissions through
 * Permissions::clean, texts trimmed and cut to length). Who may change what (never more than they hold, never their
 * own role, someone always holds everything) is decided by the caller (RoleController, UserController) inside a
 * transaction that locks the rows with forUpdate().
 */
final class RoleRepository
{
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Every role with its permissions and the number of users who have it (built-ins first, then by name).
     *
     * @return list<array<string,mixed>> with 'permissions' (list) and 'users' (active users)
     */
    public function all(): array
    {
        $rows = $this->db->query("SELECT r.*, (SELECT COUNT(*) FROM users u WHERE u.role_id = r.id AND u.is_active = 1) AS users,
                                         (SELECT COUNT(*) FROM users u WHERE u.role_id = r.id) AS all_users
                                  FROM roles r ORDER BY r.role_key IS NULL, FIELD(r.role_key, 'viewer', 'technician', 'admin'), r.name")->fetchAll();
        return array_map(fn (array $r): array => $r + ['permissions' => $this->permissionsOf($r)], $rows);
    }

    /** @return array<string,mixed>|null one role with its 'permissions' */
    public function find(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM roles WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $r = $stmt->fetch();
        return $r === false ? null : $r + ['permissions' => $this->permissionsOf($r)];
    }

    /** The ID of a built-in role ('viewer', 'technician', 'admin'), or null. */
    public function idForKey(string $key): ?int
    {
        $stmt = $this->db->prepare('SELECT id FROM roles WHERE role_key = :k');
        $stmt->execute(['k' => $key]);
        $id = $stmt->fetchColumn();
        return $id === false ? null : (int) $id;
    }

    /**
     * What a role holds: from code for a built-in role, else its stored permissions (unknown names dropped).
     *
     * @param array<string,mixed> $role a roles row
     * @return list<string>
     */
    public function permissionsOf(array $role): array
    {
        if (($role['role_key'] ?? null) !== null) {
            return Permissions::builtin((string) $role['role_key']);
        }
        $stmt = $this->db->prepare('SELECT permission FROM role_permissions WHERE role_id = :r');
        $stmt->execute(['r' => (int) $role['id']]);
        return Permissions::clean($stmt->fetchAll(PDO::FETCH_COLUMN));
    }

    /** True when a role name is free (case-insensitive, the column collation), apart from role $exceptId. */
    public function nameFree(string $name, ?int $exceptId = null): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM roles WHERE name = :n AND id <> :x');
        $stmt->execute(['n' => $name, 'x' => $exceptId ?? 0]);
        return (int) $stmt->fetchColumn() === 0;
    }

    /**
     * Create a custom role. Returns its ID.
     *
     * @param list<string> $permissions cleaned again here
     */
    public function create(string $name, string $description, array $permissions, int $createdBy): int
    {
        $this->db->prepare('INSERT INTO roles (role_key, name, description, created_by, created_at, updated_at) VALUES (NULL, :n, :d, :u, UTC_TIMESTAMP(), UTC_TIMESTAMP())')
            ->execute(['n' => mb_substr(trim($name), 0, 80), 'd' => mb_substr(trim($description), 0, 300), 'u' => $createdBy]);
        $id = (int) $this->db->lastInsertId();
        $this->setPermissions($id, $permissions);
        return $id;
    }

    /**
     * Change a custom role (built-in roles are never changed: the WHERE leaves them out). Everyone who has it is
     * signed out, so the change applies at once.
     *
     * @param list<string> $permissions cleaned again here
     */
    public function update(int $id, string $name, string $description, array $permissions): void
    {
        $role = $this->find($id);
        if ($role === null || $role['role_key'] !== null) {
            return; // unknown or built-in: never changed
        }
        $stmt = $this->db->prepare('UPDATE roles SET name = :n, description = :d, updated_at = UTC_TIMESTAMP() WHERE id = :id AND role_key IS NULL');
        $stmt->execute(['n' => mb_substr(trim($name), 0, 80), 'd' => mb_substr(trim($description), 0, 300), 'id' => $id]);
        $this->setPermissions($id, $permissions);
        $this->db->prepare('UPDATE users SET session_version = session_version + 1, updated_at = UTC_TIMESTAMP() WHERE role_id = :r')->execute(['r' => $id]);
    }

    /** Delete a custom role nobody has (built-in roles and roles in use are kept). Returns whether it was deleted. */
    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM roles WHERE id = :id AND role_key IS NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.role_id = :id2)');
        $stmt->execute(['id' => $id, 'id2' => $id]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Lock every role and active user row for the length of the caller's transaction, so two people changing roles
     * or users at once can't together leave nobody holding every permission.
     */
    public function lockForUpdate(): void
    {
        $this->db->query('SELECT id FROM roles FOR UPDATE')->fetchAll();
        $this->db->query('SELECT id FROM users WHERE is_active = 1 FOR UPDATE')->fetchAll();
    }

    /**
     * How many active users would have the built-in Admin role if user $userId had role $userRoleId (and active flag
     * $userActive). Null arguments mean "as it is now". Call inside the transaction after lockForUpdate().
     *
     * Only the built-in Admin counts (1.40.1): it holds every permission now and any permission a later release adds,
     * so as long as one active Admin is left, someone can always give any right. A custom role that happens to hold
     * every permission today would fall short the day a new permission appears, and nobody could give it then.
     */
    public function completeHoldersAfter(?int $userId = null, ?int $userRoleId = null, ?bool $userActive = null, ?bool $userAllClients = null): int
    {
        // An Admin limited to some clients (1.41) doesn't count either: full control means every client too.
        $complete = [];
        foreach ($this->db->query('SELECT id, role_key FROM roles')->fetchAll() as $r) {
            $complete[(int) $r['id']] = $r['role_key'] === 'admin';
        }
        $n = 0;
        foreach ($this->db->query('SELECT id, role_id, is_active, all_clients FROM users')->fetchAll() as $u) {
            $role = (int) $u['role_id'];
            $active = (int) $u['is_active'] === 1;
            $all = (int) $u['all_clients'] === 1;
            if ($userId !== null && (int) $u['id'] === $userId) {
                $role = $userRoleId ?? $role;
                $active = $userActive ?? $active;
                $all = $userAllClients ?? $all;
            }
            if ($active && $all && ($complete[$role] ?? false)) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * How many active Admins who see every client would keep password sign-in (1.43 break-glass) if user $userId had
     * this role, active flag, client scope and password flag.
     */
    public function passwordAdminsAfter(int $userId, int $roleId, bool $active, bool $allClients, bool $passwordLogin): int
    {
        $admin = (int) $this->db->query("SELECT id FROM roles WHERE role_key = 'admin'")->fetchColumn();
        $n = 0;
        foreach ($this->db->query('SELECT id, role_id, is_active, all_clients, password_login FROM users')->fetchAll() as $u) {
            [$r, $a, $c, $p] = (int) $u['id'] === $userId ? [$roleId, $active, $allClients, $passwordLogin]
                : [(int) $u['role_id'], (int) $u['is_active'] === 1, (int) $u['all_clients'] === 1, (int) $u['password_login'] === 1];
            if ($r === $admin && $a && $c && $p) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * Active users whose role holds a permission (for alerts, assignment lists and the two-person rule).
     *
     * @return list<array{id:int, username:string, display_name:string}>
     */
    public function usersWith(string $permission, ?int $clientId = null): array
    {
        $out = [];
        // Given a client, only users who see it (1.42.1).
        $seeing = null;
        if ($clientId !== null) {
            $stmt = $this->db->prepare('SELECT u.id FROM users u WHERE u.all_clients = 1 OR EXISTS (SELECT 1 FROM user_clients uc WHERE uc.user_id = u.id AND uc.client_id = :c)');
            $stmt->execute(['c' => $clientId]);
            $seeing = array_flip(array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN)));
        }
        $roles = [];
        foreach ($this->db->query('SELECT * FROM roles')->fetchAll() as $r) {
            $roles[(int) $r['id']] = in_array($permission, $this->permissionsOf($r), true);
        }
        foreach ($this->db->query('SELECT id, username, display_name, role_id FROM users WHERE is_active = 1 ORDER BY COALESCE(NULLIF(display_name, \'\'), username)')->fetchAll() as $u) {
            if (($roles[(int) $u['role_id']] ?? false) && ($seeing === null || isset($seeing[(int) $u['id']]))) {
                $out[] = ['id' => (int) $u['id'], 'username' => (string) $u['username'], 'display_name' => (string) $u['display_name']];
            }
        }
        return $out;
    }

    /** @param list<string> $permissions */
    private function setPermissions(int $roleId, array $permissions): void
    {
        $this->db->prepare('DELETE FROM role_permissions WHERE role_id = :r')->execute(['r' => $roleId]);
        $ins = $this->db->prepare('INSERT INTO role_permissions (role_id, permission) VALUES (:r, :p)');
        foreach (Permissions::clean($permissions) as $p) {
            $ins->execute(['r' => $roleId, 'p' => $p]);
        }
    }
}
