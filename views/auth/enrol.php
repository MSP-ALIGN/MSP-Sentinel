<?php
/**
 * Forced 2FA enrolment.
 * Expects: $secret (Base32 TOTP seed for THIS user, shown so they can type it in),
 *          $otpauth (URI rendered as a QR code by sentinel.js, from a data attribute),
 *          optional $error.
 * Security: the page is served with Cache-Control: no-store. The QR code is drawn
 * in the browser, so the seed is never sent to a third-party QR service.
 */
use Sentinel\Core\Csrf;
?>
<p class="login-box-msg"><?= e(__('Two-factor authentication is required for every account.')) ?></p>
<?php require __DIR__ . '/../partials/flashes.php'; ?>
<ol class="small ps-3">
    <li><?= e(__('Open an authenticator app on your phone.')) ?></li>
    <li><?= e(__('Scan this QR code, or type the key below.')) ?></li>
    <li><?= e(__('Enter the 6-digit code the app shows.')) ?></li>
</ol>
<div class="text-center my-3">
    <div id="totp-qr" class="totp-qr d-inline-block" data-otpauth="<?= e($otpauth) ?>" role="img" aria-label="<?= e(__('QR code for your authenticator app')) ?>"></div>
</div>
<div class="mb-3">
    <div class="form-label small mb-1"><?= e(__('Key (if you cannot scan)')) ?></div>
    <code class="d-block text-center p-2 bg-body-tertiary rounded totp-secret" data-testid="totp-secret"><?= e(trim(chunk_split($secret, 4, ' '))) ?></code>
</div>
<form method="post" action="<?= e(url('/2fa/setup')) ?>" novalidate>
    <?= Csrf::field() ?>
    <div class="mb-3">
        <label for="code" class="form-label"><?= e(__('Code from the app')) ?></label>
        <input type="text" class="form-control form-control-lg text-center code-input" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="10">
    </div>
    <button type="submit" class="btn btn-primary w-100"><?= e(__('Turn on two-factor authentication')) ?></button>
</form>
