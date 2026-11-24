<?php
/**
 * Main dashboard ("command view"). The panels refresh every 60 seconds from
 * /dashboard/live while the tab is visible (public/assets/js/sentinel.js).
 * Expects: $d (dashboard data), $globallyPaused, $awaitingApproval (engagements this admin may approve), $currentUser. Every value is escaped.
 */
?>
<?php if ($globallyPaused): ?>
<?php require __DIR__ . '/partials/kill_switch.php'; ?>
<div class="dash-actions"><button type="button" class="btn btn-sm btn-outline-secondary refresh-toggle" data-refresh-toggle aria-pressed="false" data-label-pause="<?= e(__('Pause live refresh')) ?>" data-label-resume="<?= e(__('Resume live refresh')) ?>" title="<?= e(__('Stops this page refreshing itself every minute. Scans are not affected.')) ?>"><?= e(__('Pause live refresh')) ?></button></div>
<?php else: ?>
<div class="dash-actions"><button type="button" class="btn btn-sm btn-outline-secondary refresh-toggle" data-refresh-toggle aria-pressed="false" data-label-pause="<?= e(__('Pause live refresh')) ?>" data-label-resume="<?= e(__('Resume live refresh')) ?>" title="<?= e(__('Stops this page refreshing itself every minute. Scans are not affected.')) ?>"><?= e(__('Pause live refresh')) ?></button><?php require __DIR__ . '/partials/kill_switch.php'; ?></div>
<?php endif; ?>
<?php if (($awaitingApproval ?? []) !== []): ?>
<div class="alert alert-warning d-flex flex-wrap align-items-center gap-2" role="status">
    <i class="bi bi-hourglass-split" aria-hidden="true"></i>
    <span><?= e(\Sentinel\Controllers\EngagementController::twoPerson() ? __('{n} pen-test engagement(s) awaiting your approval: nothing runs until a second admin approves.', ['n' => count($awaitingApproval)])
        : __('{n} pen-test engagement(s) awaiting approval: nothing runs until it is approved.', ['n' => count($awaitingApproval)])) ?></span>
    <a class="btn btn-sm btn-warning ms-auto" href="<?= e(url(count($awaitingApproval) === 1 ? '/engagements/' . (int) $awaitingApproval[0]['id'] : '/engagements')) ?>"><?= e(__('Review')) ?></a>
</div>
<?php endif; ?>
<div id="live-dashboard" data-refresh-url="<?= e(url('/dashboard/live')) ?>" aria-live="off">
    <?php require __DIR__ . '/dashboard/panels.php'; ?>
</div>
