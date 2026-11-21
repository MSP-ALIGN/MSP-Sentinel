<?php
/** Own profile. Expects: $currentUser (public fields), $recoveryLeft (int). */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;
?>
<div class="row g-3">
    <div class="col-lg-6">
        <div class="card">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Account')) ?></h2></div>
            <div class="card-body">
                <dl class="row mb-0">
                    <dt class="col-sm-4"><?= e(__('Username')) ?></dt><dd class="col-sm-8"><?= e($currentUser['username']) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Name')) ?></dt><dd class="col-sm-8"><?= e($currentUser['display_name']) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Email')) ?></dt><dd class="col-sm-8"><?= e($currentUser['email'] !== '' ? $currentUser['email'] : '—') ?></dd>
                    <dt class="col-sm-4"><?= e(__('Role')) ?></dt><dd class="col-sm-8"><?= e(Role::labels()[$currentUser['role']] ?? '') ?></dd>
                </dl>
            </div>
            <div class="card-footer"><a href="<?= e(url('/profile/password')) ?>" class="btn btn-outline-primary btn-sm"><i class="bi bi-key me-1" aria-hidden="true"></i><?= e(__('Change password')) ?></a></div>
        </div>
    </div>
    <div class="col-lg-6">
        <div class="card">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Two-factor authentication')) ?></h2></div>
            <form method="post" action="<?= e(url('/profile/recovery-codes')) ?>" novalidate>
            <div class="card-body">
                <p><span class="badge text-bg-success"><i class="bi bi-shield-lock me-1" aria-hidden="true"></i><?= e(__('On')) ?></span>
                    <?= e(__('{n} unused recovery codes left.', ['n' => $recoveryLeft])) ?></p>
                <?= Csrf::field() ?>
                <label for="current_password_rc" class="form-label"><?= e(__('Current password')) ?></label>
                <input type="password" class="form-control" id="current_password_rc" name="current_password" required autocomplete="current-password">
                <div class="form-text"><?= e(__('Creating new codes makes all old codes stop working.')) ?></div>
            </div>
            <div class="card-footer"><button type="submit" class="btn btn-outline-warning btn-sm"><?= e(__('Create new recovery codes')) ?></button></div>
            </form>
        </div>
    </div>
</div>
