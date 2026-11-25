<?php
/** Own profile. Expects: $currentUser (public fields), $recoveryLeft (int). */
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
                    <dt class="col-sm-4"><?= e(__('Role')) ?></dt><dd class="col-sm-8"><?= e(role_label($currentUser)) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Clients')) ?></dt><dd class="col-sm-8"><?= e(($currentUser['client_ids'] ?? null) === null ? __('All clients') : __('{n} client(s)', ['n' => count($currentUser['client_ids'])])) ?></dd>
                </dl>
            </div>
            <div class="card-footer"><a href="<?= e(url('/profile/password')) ?>" class="btn btn-outline-primary btn-sm"><i class="bi bi-key me-1" aria-hidden="true"></i><?= e(__('Change password')) ?></a></div>
        </div>
    </div>
    <div class="col-lg-6">
        <div class="card mb-3">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Email alerts')) ?></h2></div>
            <form method="post" action="<?= e(url('/profile/alerts')) ?>">
            <div class="card-body">
                <?= Csrf::field() ?>
                <?php foreach (['immediate' => __('New Fail findings, immediately'), 'digest' => __('A summary after each scan'), 'both' => __('Both'), 'none' => __('No emails (in-app notifications only)')] as $k => $l): ?>
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="alert_email" id="ae-<?= e($k) ?>" value="<?= e($k) ?>" <?= ($currentUser['alert_email'] ?? 'immediate') === $k ? 'checked' : '' ?>>
                    <label class="form-check-label" for="ae-<?= e($k) ?>"><?= e($l) ?></label>
                </div>
                <?php endforeach; ?>
                <p class="form-text mb-0"><?= e($currentUser['email'] !== '' ? __('Emails go to {email}.', ['email' => $currentUser['email']]) : __('Your account has no email address: ask an admin to add one.')) ?></p>
            </div>
            <div class="card-footer"><button type="submit" class="btn btn-outline-primary btn-sm"><?= e(__('Save preference')) ?></button></div>
            </form>
        </div>
        <?php if (\Sentinel\Core\App::entraSso() !== null || ($currentUser['sso_subject'] ?? null) !== null): ?>
        <div class="card mb-3" id="microsoft">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Microsoft account')) ?></h2></div>
            <div class="card-body small">
                <?php if (($currentUser['sso_subject'] ?? null) !== null): ?>
                <p class="mb-2"><?= e(__('Linked to {who}: you can use "Sign in with Microsoft".', ['who' => ($currentUser['sso_name'] ?? '') !== '' ? $currentUser['sso_name'] : __('a Microsoft account')])) ?></p>
                <form method="post" action="<?= e(url('/profile/sso-unlink')) ?>" data-confirm="<?= e(__('Unlink your Microsoft account? You then sign in with your password and Sentinel\'s code.')) ?>"><?= \Sentinel\Core\Csrf::field() ?>
                    <button class="btn btn-outline-danger btn-sm" type="submit"><?= e(__('Unlink')) ?></button></form>
                <?php else: ?>
                <p class="mb-2"><?= e(__('Not linked. Link your Microsoft 365 work account once, and then use "Sign in with Microsoft" on the sign-in page. Microsoft asks you to sign in to prove it is yours.')) ?></p>
                <form method="post" action="<?= e(url('/profile/sso-link')) ?>" class="d-flex flex-wrap align-items-end gap-2"><?= \Sentinel\Core\Csrf::field() ?>
                    <div><label class="form-label small mb-0" for="sso-link-pw"><?= e(__('Your password')) ?></label>
                        <input class="form-control form-control-sm" type="password" id="sso-link-pw" name="my_password" required autocomplete="current-password"></div>
                    <button class="btn btn-outline-primary btn-sm" type="submit"><i class="bi bi-microsoft me-1" aria-hidden="true"></i><?= e(__('Link my Microsoft account')) ?></button></form>
                <p class="form-text mb-0"><?= e(__('Pick your own account at Microsoft: whoever owns the linked account can sign in as you.')) ?></p>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
        <div class="card mb-3" id="appearance">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Appearance')) ?></h2></div>
            <form method="post" action="<?= e(url('/profile/theme')) ?>">
            <div class="card-body">
                <?= Csrf::field() ?>
                <?php foreach (['dark' => __('Dark console (default)'), 'light' => __('Light, for bright rooms')] as $k => $l): ?>
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="ui_theme" id="theme-<?= e($k) ?>" value="<?= e($k) ?>" <?= ($currentUser['ui_theme'] ?? 'dark') === $k ? 'checked' : '' ?>>
                    <label class="form-check-label" for="theme-<?= e($k) ?>"><?= e($l) ?></label>
                </div>
                <?php endforeach; ?>
                <p class="form-text mb-0"><?= e(__('Only changes how Sentinel looks for you. Client reports always use their own printable style.')) ?></p>
            </div>
            <div class="card-footer"><button type="submit" class="btn btn-outline-primary btn-sm"><?= e(__('Save appearance')) ?></button></div>
            </form>
        </div>
        <div class="card mb-3" id="timezone">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Time zone')) ?></h2></div>
            <form method="post" action="<?= e(url('/profile/timezone')) ?>">
            <div class="card-body">
                <?= Csrf::field() ?>
                <?php $orgZone = \Sentinel\Core\App::settings()->get('display_timezone'); ?>
                <label class="form-label" for="my-timezone"><?= e(__('Show times in')) ?></label>
                <input class="form-control" id="my-timezone" name="timezone" list="my-timezone-list" value="<?= e($currentUser['timezone'] ?? '') ?>" autocomplete="off" spellcheck="false" placeholder="<?= e(__('The organization\'s: {zone}', ['zone' => $orgZone])) ?>">
                <datalist id="my-timezone-list">
                    <?php foreach (\DateTimeZone::listIdentifiers() as $tz): ?><option value="<?= e($tz) ?>"></option><?php endforeach; ?>
                </datalist>
                <p class="form-text mb-0"><?= e(__('Leave empty to use the organization\'s time zone ({zone}). Only changes how times are shown to you; scan windows follow each client\'s own time zone.', ['zone' => $orgZone])) ?></p>
            </div>
            <div class="card-footer"><button type="submit" class="btn btn-outline-primary btn-sm"><?= e(__('Save time zone')) ?></button></div>
            </form>
        </div>
        <div class="card">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Two-factor authentication')) ?></h2></div>
            <form method="post" data-confirm="<?= e(__('Create new recovery codes? Your current recovery codes stop working.')) ?>" action="<?= e(url('/profile/recovery-codes')) ?>" novalidate>
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
