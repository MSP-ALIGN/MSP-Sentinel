<?php
/**
 * Main dashboard ("command view"). The panels refresh every 60 seconds from
 * /dashboard/live while the tab is visible (public/assets/js/sentinel.js).
 * Expects: $d (dashboard data), $globallyPaused, $currentUser. Every value is escaped.
 */
?>
<?php if ($globallyPaused): ?>
<?php require __DIR__ . '/partials/kill_switch.php'; ?>
<div class="dash-actions"><button type="button" class="btn btn-sm btn-outline-secondary refresh-toggle" data-refresh-toggle aria-pressed="false" data-label-pause="<?= e(__('Pause updates')) ?>" data-label-resume="<?= e(__('Resume updates')) ?>"><?= e(__('Pause updates')) ?></button></div>
<?php else: ?>
<div class="dash-actions"><button type="button" class="btn btn-sm btn-outline-secondary refresh-toggle" data-refresh-toggle aria-pressed="false" data-label-pause="<?= e(__('Pause updates')) ?>" data-label-resume="<?= e(__('Resume updates')) ?>"><?= e(__('Pause updates')) ?></button><?php require __DIR__ . '/partials/kill_switch.php'; ?></div>
<?php endif; ?>
<div id="live-dashboard" data-refresh-url="<?= e(url('/dashboard/live')) ?>" aria-live="off">
    <?php require __DIR__ . '/dashboard/panels.php'; ?>
</div>
