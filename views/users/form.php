<?php
/**
 * Add or edit a user.
 * Expects: $mode ('create'|'edit'), $values (untrusted form values or public user fields),
 *          $errors (field => message), and in edit mode $target (public fields) and $isSelf.
 */
use Sentinel\Auth\Passwords;
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

$isEdit = $mode === 'edit';
$isSelf = $isSelf ?? false;
$action = $isEdit ? url('/users/' . (int) $target['id']) : url('/users');
$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<div class="row g-3">
<div class="col-lg-7">
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e($isEdit ? __('Account details') : __('New user')) ?></h2></div>
    <form method="post" action="<?= e($action) ?>" novalidate>
    <div class="card-body">
        <?= Csrf::field() ?>
        <div class="mb-3">
            <label for="username" class="form-label"><?= e(__('Username')) ?></label>
            <?php if ($isEdit): ?>
            <input type="text" class="form-control" id="username" value="<?= e($values['username']) ?>" disabled>
            <?php else: ?>
            <input type="text" class="form-control<?= $invalid('username') ?>" id="username" name="username" value="<?= e($values['username']) ?>" required maxlength="50" autocapitalize="none" spellcheck="false">
            <?php $field = 'username'; require __DIR__ . '/../partials/field_error.php'; ?>
            <?php endif; ?>
        </div>
        <div class="mb-3">
            <label for="display_name" class="form-label"><?= e(__('Full name')) ?></label>
            <input type="text" class="form-control<?= $invalid('display_name') ?>" id="display_name" name="display_name" value="<?= e($values['display_name']) ?>" required maxlength="100">
            <?php $field = 'display_name'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="mb-3">
            <label for="email" class="form-label"><?= e(__('Email (optional)')) ?></label>
            <input type="email" class="form-control<?= $invalid('email') ?>" id="email" name="email" value="<?= e($values['email']) ?>" maxlength="190">
            <?php $field = 'email'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="mb-3">
            <label for="role" class="form-label"><?= e(__('Role')) ?></label>
            <select class="form-select<?= $invalid('role') ?>" id="role" name="role" <?= $isSelf ? 'disabled' : '' ?>>
                <?php foreach (Role::labels() as $value => $label): ?>
                <option value="<?= e($value) ?>" <?= $values['role'] === $value ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
            <div class="form-text"><?= e(__('Viewer: read-only. Technician: runs scans and triages findings. Admin: everything, including users and scan authorisations.')) ?></div>
            <?php $field = 'role'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <?php if ($isEdit): ?>
        <div class="form-check mb-3">
            <input type="checkbox" class="form-check-input" id="is_active" name="is_active" value="1" <?= (int) $values['is_active'] === 1 ? 'checked' : '' ?> <?= $isSelf ? 'disabled' : '' ?>>
            <label class="form-check-label" for="is_active"><?= e(__('Account is active')) ?></label>
        </div>
        <?php if ($isSelf): ?>
        <p class="form-text"><?= e(__('You cannot change your own role or disable your own account.')) ?></p>
        <?php else: ?>
        <div class="mb-3">
            <label for="my_password" class="form-label"><?= e(__('Your own password (only needed when changing the role or access)')) ?></label>
            <input type="password" class="form-control<?= $invalid('my_password') ?>" id="my_password" name="my_password" autocomplete="current-password">
            <?php $field = 'my_password'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <?php endif; ?>
        <?php else: ?>
        <div class="mb-3">
            <label for="password" class="form-label"><?= e(__('Temporary password')) ?></label>
            <input type="password" class="form-control<?= $invalid('password') ?>" id="password" name="password" required autocomplete="new-password" minlength="<?= e(Passwords::MIN_LENGTH) ?>">
            <div class="form-text"><?= e(__('At least {n} characters. The user must change it, and set up two-factor authentication, at first sign-in.', ['n' => Passwords::MIN_LENGTH])) ?></div>
            <?php $field = 'password'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="mb-3">
            <label for="my_password_new" class="form-label"><?= e(__('Your own password (to confirm)')) ?></label>
            <input type="password" class="form-control<?= $invalid('my_password') ?>" id="my_password_new" name="my_password" required autocomplete="current-password">
            <?php $field = 'my_password'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <?php endif; ?>
    </div>
    <div class="card-footer">
        <button type="submit" class="btn btn-primary"><?= e($isEdit ? __('Save changes') : __('Create user')) ?></button>
        <a href="<?= e(url('/users')) ?>" class="btn btn-outline-secondary"><?= e(__('Cancel')) ?></a>
    </div>
    </form>
</div>
</div>

<?php if ($isEdit && !$isSelf): ?>
<div class="col-lg-5">
    <div class="card mb-3">
        <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('Reset password')) ?></h2></div>
        <form method="post" data-confirm="<?= e(__('Set a temporary password for this user? Their current password stops working and they must change it at the next sign-in.')) ?>" action="<?= e(url('/users/' . (int) $target['id'] . '/password')) ?>" novalidate>
        <div class="card-body">
            <?= Csrf::field() ?>
            <label for="reset_password" class="form-label"><?= e(__('New temporary password')) ?></label>
            <input type="password" class="form-control" id="reset_password" name="password" required autocomplete="new-password" minlength="<?= e(Passwords::MIN_LENGTH) ?>">
            <div class="form-text"><?= e(__('Signs the user out everywhere. They must change it at next sign-in.')) ?></div>
            <label for="reset_password_mine" class="form-label small mt-2"><?= e(__('Your own password (to confirm)')) ?></label>
            <input type="password" class="form-control form-control-sm" id="reset_password_mine" name="my_password" required autocomplete="current-password">
        </div>
        <div class="card-footer"><button type="submit" class="btn btn-warning btn-sm"><?= e(__('Set temporary password')) ?></button></div>
        </form>
    </div>
    <div class="card">
        <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('Two-factor authentication')) ?></h2></div>
        <div class="card-body">
            <p class="mb-2"><?= e($target['totp_enabled_at'] !== null ? __('Turned on since {date} (UTC).', ['date' => $target['totp_enabled_at']]) : __('Not set up yet. The user will be asked at next sign-in.')) ?></p>
            <?php if ($target['totp_enabled_at'] !== null): ?>
            <form method="post" action="<?= e(url('/users/' . (int) $target['id'] . '/2fa-reset')) ?>" data-confirm="<?= e(__('Reset two-factor authentication for this user? They will be signed out and must set it up again.')) ?>" novalidate>
                <?= Csrf::field() ?>
                <label for="reset_2fa_password" class="form-label small"><?= e(__('New temporary password (required)')) ?></label>
                <input type="password" class="form-control form-control-sm mb-2" id="reset_2fa_password" name="password" required autocomplete="new-password" minlength="<?= e(Passwords::MIN_LENGTH) ?>">
                <div class="form-text mb-2"><?= e(__('The password is replaced too, so nobody who knows the old one can set up 2FA in the user\'s place. Give it to the user directly.')) ?></div>
                <label for="reset_2fa_mine" class="form-label small "><?= e(__('Your own password (to confirm)')) ?></label>
            <input type="password" class="form-control form-control-sm" id="reset_2fa_mine" name="my_password" required autocomplete="current-password"><div class="mb-2"></div>
                <button type="submit" class="btn btn-outline-danger btn-sm"><?= e(__('Reset two-factor authentication')) ?></button>
            </form>
            <?php endif; ?>
        </div>
    </div>
</div>
<?php endif; ?>
</div>
