<?php
/** Change own password. Expects: $currentUser, $errors (field => message). */
use Sentinel\Auth\Passwords;
use Sentinel\Core\Csrf;

$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<?php if ((int) $currentUser['must_change_password'] === 1): ?>
<div class="alert alert-warning"><i class="bi bi-info-circle me-1" aria-hidden="true"></i><?= e(__('You are using a temporary password. Choose your own password to continue.')) ?></div>
<?php endif; ?>
<div class="row"><div class="col-lg-6">
<div class="card">
    <form method="post" action="<?= e(url('/profile/password')) ?>" novalidate>
    <div class="card-body">
        <?= Csrf::field() ?>
        <div class="mb-3">
            <label for="current_password" class="form-label"><?= e(__('Current password')) ?></label>
            <input type="password" class="form-control<?= $invalid('current_password') ?>" id="current_password" name="current_password" required autocomplete="current-password">
            <?php $field = 'current_password'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="mb-3">
            <label for="new_password" class="form-label"><?= e(__('New password')) ?></label>
            <input type="password" class="form-control<?= $invalid('new_password') ?>" id="new_password" name="new_password" required autocomplete="new-password" minlength="<?= e(Passwords::MIN_LENGTH) ?>">
            <div class="form-text"><?= e(__('At least {n} characters. A passphrase of several words is easy to remember and hard to guess.', ['n' => Passwords::MIN_LENGTH])) ?></div>
            <?php $field = 'new_password'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="mb-3">
            <label for="confirm_password" class="form-label"><?= e(__('Repeat new password')) ?></label>
            <input type="password" class="form-control<?= $invalid('confirm_password') ?>" id="confirm_password" name="confirm_password" required autocomplete="new-password">
            <?php $field = 'confirm_password'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
    </div>
    <div class="card-footer"><button type="submit" class="btn btn-primary"><?= e(__('Change password')) ?></button></div>
    </form>
</div>
</div></div>
