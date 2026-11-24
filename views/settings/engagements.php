<?php
/**
 * Pen-test engagement approval card on the Settings page (1.47).
 * Expects: $twoPerson (bool), $mayChangeTwoPerson (an Admin who holds every permission and sees every client).
 * Changing it needs the Admin's own password; the form is CSRF-protected and everything is escaped.
 */
use Sentinel\Core\Csrf;
?>
<div class="card">
    <div class="card-header d-flex align-items-center gap-2"><h2 class="card-title h5 mb-0"><?= e(__('Pen-test engagement approval')) ?></h2>
        <span class="badge <?= $twoPerson ? 'text-bg-success' : 'text-bg-warning' ?>"><?= e($twoPerson ? __('Two people') : __('One person')) ?></span></div>
    <form method="post" action="<?= e(url('/admin/settings/engagements')) ?>" autocomplete="off" novalidate>
    <div class="card-body">
        <?= Csrf::field() ?>
        <p class="small text-body-secondary"><?= e(__('Nothing in an engagement runs before it is approved by someone who may approve engagements, after checking the client\'s signed authorisation against the scope.')) ?></p>
        <div class="form-check mb-2">
            <input type="hidden" name="two_person" value="0">
            <input class="form-check-input" type="checkbox" id="two_person" name="two_person" value="1" <?= $twoPerson ? 'checked' : '' ?><?= $mayChangeTwoPerson ? '' : ' disabled' ?>>
            <label class="form-check-label" for="two_person"><?= e(__('Require a second person to approve (recommended)')) ?></label>
            <div class="form-text"><?= e(__('On: the creator can never approve their own engagement, nor can an account they made or reset recently. Off: whoever creates an engagement may approve it themselves if their role may approve engagements; the engagement page, audit log and pen-test report then say "single-person approval". Engagements created while it was on still need a second person.')) ?></div>
        </div>
        <?php if ($mayChangeTwoPerson): ?>
        <label class="form-label" for="engagement-pw"><?= e(__('Your own password (to confirm)')) ?></label>
        <input class="form-control form-control-sm sn-w-20" type="password" id="engagement-pw" name="my_password" required autocomplete="current-password">
        <div class="form-text"><?= e(__('Everyone who may approve engagements is told when this changes.')) ?></div>
        <?php else: ?>
        <p class="small text-body-secondary mb-0"><?= e(__('Only an Admin who holds every permission and sees every client can change this.')) ?></p>
        <?php endif; ?>
    </div>
    <?php if ($mayChangeTwoPerson): ?><div class="card-footer"><button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save')) ?></button></div><?php endif; ?>
    </form>
</div>
