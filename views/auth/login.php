<?php
/** Sign-in form. Expects: $username (untrusted, echoed back), optional $error, $flashes. */
use Sentinel\Core\Csrf;
?>
<p class="login-box-msg"><?= e(__('Sign in to continue')) ?></p>
<?php require __DIR__ . '/../partials/flashes.php'; ?>
<form method="post" action="<?= e(url('/login')) ?>" novalidate>
    <?= Csrf::field() ?>
    <div class="mb-3">
        <label for="username" class="form-label"><?= e(__('Username')) ?></label>
        <input type="text" class="form-control" id="username" name="username" value="<?= e($username ?? '') ?>" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus maxlength="100">
    </div>
    <div class="mb-3">
        <label for="password" class="form-label"><?= e(__('Password')) ?></label>
        <input type="password" class="form-control" id="password" name="password" autocomplete="current-password" required maxlength="1024">
    </div>
    <button type="submit" class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right me-1" aria-hidden="true"></i><?= e(__('Sign in')) ?></button>
</form>
