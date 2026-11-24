<?php
/**
 * Every pen-test engagement across clients (1.34), with the ones waiting for this admin's approval first.
 * Expects: $engagements (EngagementRepository::all), $awaiting (awaitingApprovalBy, admins only), $adminCount,
 * $currentUser. Times are shown in UTC here (each client's page shows its own time zone). Every value is escaped.
 */
use Sentinel\Engagements\EngagementRepository;

$now = gmdate('Y-m-d H:i:s');
$stateBadge = [
    EngagementRepository::STATE_AWAITING => ['text-bg-warning', __('Awaiting approval')],
    EngagementRepository::STATE_SCHEDULED => ['text-bg-info', __('Approved, scheduled')],
    EngagementRepository::STATE_ACTIVE => ['text-bg-danger', __('Active: testing allowed')],
    EngagementRepository::STATE_ENDED => ['text-bg-secondary', __('Ended')],
    EngagementRepository::STATE_STOPPED => ['text-bg-dark', __('Stopped')],
    EngagementRepository::STATE_CANCELLED => ['text-bg-light border', __('Cancelled')],
];
$isAdmin = can('engagements.approve');
?>
<?php if ($awaiting !== []): ?>
<div class="card border-warning mb-3">
    <div class="card-header"><h2 class="card-title h5 mb-0"><i class="bi bi-hourglass-split me-1" aria-hidden="true"></i><?= e(__('Awaiting your approval')) ?></h2></div>
    <ul class="list-group list-group-flush">
        <?php foreach ($awaiting as $a): ?>
        <li class="list-group-item"><a href="<?= e(url('/engagements/' . (int) $a['id'])) ?>"><?= e($a['name']) ?></a>
            <span class="text-body-secondary small">· <?= e($a['client_name']) ?> · <?= e(__('created by {u}', ['u' => (string) $a['created_by_name']])) ?> · <?= e(__('starts {t} UTC', ['t' => substr((string) $a['window_start'], 0, 16)])) ?></span></li>
        <?php endforeach; ?>
    </ul>
</div>
<?php endif; ?>
<?php if ($isAdmin && $approverCount < 2 && \Sentinel\Controllers\EngagementController::twoPerson()): ?>
<div class="alert alert-info"><?= e(__('Engagements need a second person to approve them, and you are the only one who may.')) ?> <?php if (can('users.manage')): ?><a href="<?= e(url('/users')) ?>"><?= e(__('Give another user a role that can approve engagements')) ?></a><?php endif; ?></div>
<?php endif; ?>
<div class="card">
    <div class="card-header d-flex flex-wrap align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('All engagements')) ?></h2>
        <label class="visually-hidden" for="engagements-filter"><?= e(__('Filter engagements')) ?></label>
        <input type="search" id="engagements-filter" class="form-control form-control-sm ms-auto sn-w-16" data-filter-list="#engagements-table" placeholder="<?= e(__('Filter by name or client')) ?>">
    </div>
    <div class="card-body">
        <p class="small text-body-secondary"><?= e(__('Create an engagement from the client\'s Pen-test engagements page. A different admin approves it before anything runs.')) ?></p>
        <?php if ($engagements === []): ?>
        <p class="text-body-secondary mb-0"><?= e(__('No engagements yet.')) ?> <a href="<?= e(url('/clients')) ?>"><?= e(__('Open a client to create one')) ?></a></p>
        <?php else: ?>
        <div class="table-responsive"><table class="table table-sm align-middle mb-0" id="engagements-table">
            <thead><tr><th><?= e(__('Engagement')) ?></th><th><?= e(__('Client')) ?></th><th><?= e(__('Window (UTC)')) ?></th><th><?= e(__('State')) ?></th><th><?= e(__('Created / approved by')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($engagements as $g): [$cls, $label] = $stateBadge[EngagementRepository::state($g, $now)]; ?>
                <tr data-filter-item>
                    <td><a href="<?= e(url('/engagements/' . (int) $g['id'])) ?>"><?= e($g['name']) ?></a> <span class="text-body-secondary small">#<?= (int) $g['id'] ?></span></td>
                    <td><a href="<?= e(url('/clients/' . (int) $g['client_id'] . '/engagements')) ?>"><?= e($g['client_name']) ?></a></td>
                    <td class="small"><?= e(substr((string) $g['window_start'], 0, 16)) ?> → <?= e(substr((string) $g['window_end'], 0, 16)) ?></td>
                    <td><span class="badge <?= e($cls) ?>"><?= e($label) ?></span></td>
                    <td class="small"><?= e((string) $g['created_by_name']) ?> / <?= e((string) ($g['approved_by_name'] ?? '–')) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table></div>
        <?php endif; ?>
    </div>
</div>
