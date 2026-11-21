<?php
/** User list. Expects: $users (safe fields only). */
use Sentinel\Auth\Role;
$labels = Role::labels();
?>
<div class="card">
    <div class="card-header d-flex align-items-center">
        <h2 class="card-title h5 mb-0"><?= e(__('All users')) ?></h2>
        <a href="<?= e(url('/users/new')) ?>" class="btn btn-primary btn-sm ms-auto"><i class="bi bi-person-plus me-1" aria-hidden="true"></i><?= e(__('Add user')) ?></a>
    </div>
    <div class="card-body p-0 table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead>
            <tr>
                <th scope="col"><?= e(__('Username')) ?></th>
                <th scope="col"><?= e(__('Name')) ?></th>
                <th scope="col"><?= e(__('Role')) ?></th>
                <th scope="col"><?= e(__('Status')) ?></th>
                <th scope="col"><?= e(__('2FA')) ?></th>
                <th scope="col"><?= e(__('Last sign-in (UTC)')) ?></th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td><a href="<?= e(url('/users/' . (int) $u['id'])) ?>"><?= e($u['username']) ?></a></td>
                <td><?= e($u['display_name']) ?></td>
                <td><?= e($labels[$u['role']] ?? $u['role']) ?></td>
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
                <td><?= e($u['last_login_at'] ?? __('Never')) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
