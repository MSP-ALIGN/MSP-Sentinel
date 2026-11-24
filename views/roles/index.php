<?php
/**
 * Roles (1.40): every role with its users, and a table of which role may do what.
 * Expects: $roles (RoleRepository::all), $groups (Permissions::grouped). Every value is escaped.
 */
?>
<div class="card mb-3">
    <div class="card-header d-flex align-items-center">
        <h2 class="card-title h5 mb-0"><?= e(__('Roles')) ?></h2>
        <a href="<?= e(url('/admin/roles/new')) ?>" class="btn btn-primary btn-sm ms-auto"><i class="bi bi-plus-lg me-1" aria-hidden="true"></i><?= e(__('New role')) ?></a>
    </div>
    <div class="card-body pb-0">
        <p class="small text-body-secondary"><?= e(__('A role is a set of permissions; each user has one role. Viewer, Technician and Admin are built in and can\'t be changed: copy one to start your own. Everyone can see clients and their findings; permissions decide what they may change. You can only give permissions you hold yourself. Permissions marked "Near full control" reach the whole system (agent releases, updates, the API, integrations, users): give them only to people you would make Admin.')) ?></p>
    </div>
    <div class="card-body p-0 table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead><tr>
                <th scope="col"><?= e(__('Role')) ?></th>
                <th scope="col"><?= e(__('What it is for')) ?></th>
                <th scope="col" class="text-end"><?= e(__('Permissions')) ?></th>
                <th scope="col" class="text-end"><?= e(__('Active users')) ?></th>
                <th scope="col"><span class="visually-hidden"><?= e(__('Actions')) ?></span></th>
            </tr></thead>
            <tbody>
            <?php foreach ($roles as $r): ?>
            <tr>
                <td><a href="<?= e(url('/admin/roles/' . (int) $r['id'])) ?>"><?= e(role_label($r)) ?></a>
                    <?php if ($r['role_key'] !== null): ?><span class="badge text-bg-secondary ms-1"><?= e(__('Built in')) ?></span><?php endif; ?></td>
                <td class="small"><?= e($r['role_key'] !== null ? __((string) $r['description']) : (string) $r['description']) ?></td>
                <td class="text-end"><?= e(count($r['permissions'])) ?> / <?= e(count(\Sentinel\Auth\Permissions::ALL)) ?></td>
                <td class="text-end"><?= e($r['users']) ?></td>
                <td class="text-end"><a class="btn btn-sm btn-outline-secondary" href="<?= e(url('/admin/roles/new', ['copy' => (int) $r['id']])) ?>"><i class="bi bi-copy me-1" aria-hidden="true"></i><?= e(__('Copy')) ?></a></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Who can do what')) ?></h2></div>
    <div class="card-body p-0 table-responsive">
        <table class="table table-sm align-middle mb-0">
            <thead><tr>
                <th scope="col"><?= e(__('Permission')) ?></th>
                <?php foreach ($roles as $r): ?><th scope="col" class="text-center"><?= e(role_label($r)) ?></th><?php endforeach; ?>
            </tr></thead>
            <tbody>
            <?php foreach ($groups as $group => $perms): ?>
            <tr class="table-active"><th scope="rowgroup" colspan="<?= e(count($roles) + 1) ?>"><?= e(\Sentinel\Auth\Permissions::groupLabel($group)) ?></th></tr>
            <?php foreach ($perms as $p): ?>
            <tr>
                <th scope="row" class="fw-normal"><?= e($p['label']) ?><?php if ($p['powerful']): ?> <span class="badge text-bg-warning"><?= e(__('Near full control')) ?></span><?php endif; ?><div class="small text-body-secondary"><?= e($p['help']) ?></div></th>
                <?php foreach ($roles as $r): ?>
                <td class="text-center"><?php if (in_array($p['name'], $r['permissions'], true)): ?><i class="bi bi-check-lg text-success" aria-hidden="true"></i><span class="visually-hidden"><?= e(__('Yes')) ?></span><?php else: ?><span class="text-body-secondary" aria-hidden="true">–</span><span class="visually-hidden"><?= e(__('No')) ?></span><?php endif; ?></td>
                <?php endforeach; ?>
            </tr>
            <?php endforeach; ?>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
