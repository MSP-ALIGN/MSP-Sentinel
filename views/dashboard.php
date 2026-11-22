<?php
/**
 * Main dashboard ("command view"). The panels refresh every 60 seconds from
 * /dashboard/live while the tab is visible (public/assets/js/sentinel.js).
 * Expects: $d (dashboard data), $globallyPaused, $currentUser. Every value is escaped.
 */
?>
<?php if ($globallyPaused): ?>
<?php require __DIR__ . '/partials/kill_switch.php'; ?>
<?php else: ?>
<div class="dash-actions"><?php require __DIR__ . '/partials/kill_switch.php'; ?></div>
<?php endif; ?>
<div id="live-dashboard" data-refresh-url="<?= e(url('/dashboard/live')) ?>" aria-live="off">
    <?php require __DIR__ . '/dashboard/panels.php'; ?>
</div>
