<?php
/**
 * Main dashboard ("command view"). The panels refresh every 60 seconds from
 * /dashboard/live while the tab is visible (public/assets/js/sentinel.js).
 * Expects: $d (dashboard data), $globallyPaused, $awaitingApproval (engagements this admin may approve), $setup (first-run
 * checklist steps, or [] when it is not shown, 1.51), $currentUser. Every value is escaped.
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
<?php if (($setup ?? []) !== []): $doneN = count(array_filter($setup, static fn (array $s): bool => $s['done'])); ?>
<section class="card mb-3 setup-checklist" aria-labelledby="h-setup">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 id="h-setup" class="card-title h5 mb-0"><i class="bi bi-list-check me-1" aria-hidden="true"></i><?= e(__('Getting started')) ?></h2>
        <span class="small text-body-secondary"><?= e(__('{done} of {n} done', ['done' => $doneN, 'n' => count($setup)])) ?></span>
        <form method="post" action="<?= e(url('/dashboard/setup-checklist/hide')) ?>" class="ms-auto" data-confirm="<?= e(__('Hide this checklist for everyone? The same steps are in Help, "Your first day".')) ?>">
            <?= \Sentinel\Core\Csrf::field() ?>
            <button type="submit" class="btn btn-sm btn-outline-secondary"><?= e(__('Hide checklist')) ?></button>
        </form>
    </div>
    <ol class="list-group list-group-flush list-group-numbered">
        <?php foreach ($setup as $step): ?>
        <li class="list-group-item d-flex align-items-start gap-2" data-step="<?= e($step['key']) ?>">
            <i class="bi <?= $step['done'] ? 'bi-check-circle-fill text-success' : 'bi-circle text-body-secondary' ?>" aria-hidden="true"></i>
            <div class="flex-grow-1">
                <?php if ($step['done']): ?><s><?= e($step['label']) ?></s> <span class="visually-hidden"><?= e(__('(done)')) ?></span>
                <?php else: ?><a href="<?= e(url($step['url'])) ?>"><?= e($step['label']) ?></a><?php endif; ?>
                <div class="small text-body-secondary"><?= e($step['hint']) ?></div>
            </div>
        </li>
        <?php endforeach; ?>
    </ol>
</section>
<?php endif; ?>
<div id="live-dashboard" data-refresh-url="<?= e(url('/dashboard/live')) ?>" aria-live="off">
    <?php require __DIR__ . '/dashboard/panels.php'; ?>
</div>
