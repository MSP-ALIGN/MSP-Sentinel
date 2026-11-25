<?php
/** User list. Expects: $users (safe fields only, with role_name and role_key). */
?>
<div class="card">
    <div class="card-header d-flex align-items-center">
        <h2 class="card-title h5 mb-0"><?= e(__('All users')) ?></h2>
        <a href="<?= e(url('/admin/roles')) ?>" class="btn btn-outline-secondary btn-sm ms-auto me-2"><i class="bi bi-shield-lock me-1" aria-hidden="true"></i><?= e(__('Roles')) ?></a>
        <a href="<?= e(url('/users/new')) ?>" class="btn btn-primary btn-sm"><i class="bi bi-person-plus me-1" aria-hidden="true"></i><?= e(__('Add user')) ?></a>
    </div>
    <div class="card-body p-0 table-responsive">
        <div class="p-2"><div class="d-flex align-items-center gap-2 mb-2"><label class="visually-hidden" for="users-filter"><?= e(__('Filter this list')) ?></label><input class="form-control form-control-sm sn-w-20" type="search" id="users-filter" maxlength="100" data-filter-list="#users-table" data-filter-count="#users-filter-count" placeholder="<?= e(__('Filter users…')) ?>"><span class="small text-body-secondary" id="users-filter-count" aria-live="polite"></span></div></div>
        <table class="table table-hover align-middle mb-0" id="users-table">
            <thead>
            <tr>
                <th scope="col"><?= e(__('Username')) ?></th>
                <th scope="col"><?= e(__('Name')) ?></th>
                <th scope="col"><?= e(__('Role')) ?></th>
                <th scope="col"><?= e(__('Clients')) ?></th>
                <th scope="col"><?= e(__('Status')) ?></th>
                <th scope="col"><?= e(__('Two-factor')) ?></th>
                <th scope="col"><?= e(__('Last sign-in')) ?></th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td><a href="<?= e(url('/users/' . (int) $u['id'])) ?>"><?= e($u['username']) ?></a></td>
                <td><?= e($u['display_name']) ?></td>
                <td><?= e(role_label($u)) ?></td>
                <td><?= e((int) ($u['all_clients'] ?? 1) === 1 ? __('All') : __('{n} client(s)', ['n' => (int) ($u['client_count'] ?? 0)])) ?></td>
                <td>
                    <?php if ((int) $u['is_active'] === 1): ?>
                    <span class="badge text-bg-success"><i class="bi bi-check-circle me-1" aria-hidden="true"></i><?= e(__('Active')) ?></span>
                    <?php else: ?>
                    <span class="badge text-bg-secondary"><i class="bi bi-slash-circle me-1" aria-hidden="true"></i><?= e(__('Disabled')) ?></span>
                    <?php endif; ?>
                </td>
                <td><?= $u['totp_enabled_at'] !== null
                        ? '<span class="badge text-bg-success"><i class="bi bi-shield-lock me-1" aria-hidden="true"></i>' . e(__('On')) . '</span>'
                        : '<span class="badge text-bg-warning"><i class="bi bi-hourglass me-1" aria-hidden="true"></i>' . e(__('At next sign-in')) . '</span>' ?></td>
                <td><?= e(when($u['last_login_at'], null, __('Never'))) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
