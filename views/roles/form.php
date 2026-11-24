<?php
/**
 * Create or edit a custom role, or see a built-in one (1.40).
 * Expects: $role (null for a new role), $values (name, description, permissions: untrusted on a re-shown form),
 *          $errors (field => message), $groups (Permissions::grouped), $held (the signed-in user's permissions),
 *          $locked (why this role can't be changed by this user, or null). Every value is escaped.
 * Permissions the user doesn't hold are shown but can't be ticked (the controller refuses them too).
 */
use Sentinel\Core\Csrf;

$isNew = $role === null;
$readOnly = !$isNew && $locked !== null;
$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<?php if ($readOnly): ?>
<div class="alert alert-info"><?= e($locked) ?><?php if ($role['role_key'] !== null): ?> <a href="<?= e(url('/admin/roles/new', ['copy' => (int) $role['id']])) ?>"><?= e(__('Copy this role')) ?></a><?php endif; ?></div>
<?php endif; ?>
<form method="post" action="<?= e(url($isNew ? '/admin/roles' : '/admin/roles/' . (int) $role['id'])) ?>" novalidate>
<?= Csrf::field() ?>
<div class="card mb-3">
    <div class="card-body">
        <div class="row g-3">
            <div class="col-md-5">
                <label for="name" class="form-label"><?= e(__('Name')) ?></label>
                <input type="text" class="form-control<?= $invalid('name') ?>" id="name" name="name" value="<?= e($readOnly && $role['role_key'] !== null ? role_label($role) : $values['name']) ?>" maxlength="80" required <?= $readOnly ? 'disabled' : '' ?>>
                <?php $field = 'name'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
            <div class="col-md-7">
                <label for="description" class="form-label"><?= e(__('What it is for (optional)')) ?></label>
                <input type="text" class="form-control<?= $invalid('description') ?>" id="description" name="description" value="<?= e($readOnly && $role['role_key'] !== null ? __((string) $role['description']) : $values['description']) ?>" maxlength="300" <?= $readOnly ? 'disabled' : '' ?>>
                <?php $field = 'description'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
        </div>
    </div>
</div>
<?php if (!empty($errors['permissions'])): ?><div class="alert alert-danger"><?= e($errors['permissions']) ?></div><?php endif; ?>
<div class="row g-3">
    <?php foreach ($groups as $group => $perms): ?>
    <div class="col-lg-6">
        <fieldset class="card h-100">
            <legend class="card-header h6 mb-0"><?= e(\Sentinel\Auth\Permissions::groupLabel($group)) ?></legend>
            <div class="card-body">
                <?php foreach ($perms as $p): ?>
                <?php $mine = in_array($p['name'], $held, true); $on = in_array($p['name'], $values['permissions'], true); ?>
                <div class="form-check mb-2">
                    <input class="form-check-input" type="checkbox" name="permissions[]" value="<?= e($p['name']) ?>" id="perm-<?= e($p['name']) ?>" <?= $on ? 'checked' : '' ?> <?= $readOnly || !$mine ? 'disabled' : '' ?>>
                    <label class="form-check-label" for="perm-<?= e($p['name']) ?>"><?= e($p['label']) ?><?php if (!$mine && !$readOnly): ?> <span class="badge text-bg-secondary"><?= e(__('You don\'t hold this')) ?></span><?php endif; ?></label>
                    <div class="form-text mt-0"><?= e($p['help']) ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </fieldset>
    </div>
    <?php endforeach; ?>
</div>
<?php if (!$readOnly): ?>
<div class="card mt-3">
    <div class="card-body">
        <label for="my_password" class="form-label"><?= e(__('Your own password (to confirm)')) ?></label>
        <input type="password" class="form-control sn-w-20<?= $invalid('my_password') ?>" id="my_password" name="my_password" required autocomplete="current-password">
        <?php $field = 'my_password'; require __DIR__ . '/../partials/field_error.php'; ?>
        <div class="form-text"><?= e(__('Everyone with this role is signed out when it changes, so the change applies at once.')) ?></div>
    </div>
    <div class="card-footer">
        <button type="submit" class="btn btn-primary"><?= e($isNew ? __('Create role') : __('Save role')) ?></button>
        <a href="<?= e(url('/admin/roles')) ?>" class="btn btn-outline-secondary"><?= e(__('Cancel')) ?></a>
    </div>
</div>
<?php endif; ?>
</form>
<?php if (!$isNew && !$readOnly): ?>
<form method="post" action="<?= e(url('/admin/roles/' . (int) $role['id'] . '/delete')) ?>" class="mt-3" data-confirm="<?= e(__('Delete this role? Only possible when no user has it.')) ?>">
    <?= Csrf::field() ?>
    <button type="submit" class="btn btn-outline-danger btn-sm"><i class="bi bi-trash me-1" aria-hidden="true"></i><?= e(__('Delete role')) ?></button>
</form>
<?php endif; ?>
