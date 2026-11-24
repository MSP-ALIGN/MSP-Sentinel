<?php
/** Second-factor prompt. Expects: optional $error, $flashes. */
use Sentinel\Core\Csrf;
?>
<p class="login-box-msg"><?= e(__('Enter the 6-digit code from your authenticator app.')) ?></p>
<?php require __DIR__ . '/../partials/flashes.php'; ?>
<form method="post" action="<?= e(url('/login/2fa')) ?>" novalidate>
    <?= Csrf::field() ?>
    <div class="mb-3">
        <label for="code" class="form-label"><?= e(__('Code')) ?></label>
        <input type="text" class="form-control form-control-lg text-center code-input" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus maxlength="20">
        <div class="form-text"><?= e(__('Lost your phone? Enter one of your recovery codes instead.')) ?></div>
    </div>
    <button type="submit" class="btn btn-primary w-100"><?= e(__('Verify')) ?></button>
</form>
<form method="post" action="<?= e(url('/logout')) ?>" class="mt-3 text-center">
    <?= Csrf::field() ?>
    <button type="submit" class="btn btn-link btn-sm"><?= e(__('Cancel and sign in as someone else')) ?></button>
</form>
