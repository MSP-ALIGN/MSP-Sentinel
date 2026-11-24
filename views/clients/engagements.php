<?php
/**
 * A client's pen-test engagements (ClientController, section 'engagements').
 * Expects: $client, $engagements (EngagementRepository::forClient), $archived. Every value is escaped.
 */
use Sentinel\Engagements\EngagementRepository;

$now = gmdate('Y-m-d H:i:s');
$tz = new DateTimeZone((string) $client['timezone']);
$local = static fn (string $utc): string => (new DateTimeImmutable($utc, new DateTimeZone('UTC')))->setTimezone($tz)->format('Y-m-d H:i');
$stateBadge = [
    EngagementRepository::STATE_AWAITING => ['text-bg-warning', __('Awaiting approval')],
    EngagementRepository::STATE_SCHEDULED => ['text-bg-info', __('Approved, scheduled')],
    EngagementRepository::STATE_ACTIVE => ['text-bg-danger', __('Active: testing allowed')],
    EngagementRepository::STATE_ENDED => ['text-bg-secondary', __('Ended')],
    EngagementRepository::STATE_STOPPED => ['text-bg-dark', __('Stopped')],
    EngagementRepository::STATE_CANCELLED => ['text-bg-light border', __('Cancelled')],
];
?>
<div class="card mt-3" id="engagements">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Pen-test engagements')) ?></h2>
        <?php if (can('engagements.run') && !$archived && (int) ($client['is_demo'] ?? 0) !== 1): ?>
        <a class="btn btn-primary btn-sm ms-auto" href="<?= e(url('/clients/' . (int) $client['id'] . '/engagements/new')) ?>"><i class="bi bi-crosshair me-1" aria-hidden="true"></i><?= e(__('New engagement')) ?></a>
        <?php elseif (can('engagements.run') && (int) ($client['is_demo'] ?? 0) === 1): ?>
        <span class="small text-body-secondary ms-auto"><?= e(__('Demo clients are never tested, so engagements can\'t be created for them.')) ?></span>
        <?php elseif (can('engagements.run') && $archived): ?>
        <span class="small text-body-secondary ms-auto"><?= e(__('Archived clients can\'t get new engagements.')) ?></span>
        <?php endif; ?>
    </div>
    <div class="card-body">
        <p class="small text-body-secondary"><?= e(__('An engagement is a time-boxed, deeper test the client signed for: all ports, common UDP services, service scripts and anonymous-access checks, on targets already in its authorised scope. A different admin approves it before anything runs, and it can be stopped at any moment. Day-to-day scans stay gentle.')) ?></p>
        <?php if ($engagements === []): ?>
        <p class="text-body-secondary mb-0"><?= e(__('No engagements yet.')) ?></p>
        <?php else: ?>
        <div class="table-responsive"><table class="table table-sm align-middle mb-0">
            <thead><tr><th><?= e(__('Engagement')) ?></th><th><?= e(__('Window ({tz})', ['tz' => $client['timezone']])) ?></th><th><?= e(__('State')) ?></th><th><?= e(__('Created / approved by')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($engagements as $g): [$cls, $label] = $stateBadge[EngagementRepository::state($g, $now)]; ?>
                <tr>
                    <td><a href="<?= e(url('/engagements/' . (int) $g['id'])) ?>"><?= e($g['name']) ?></a> <span class="text-body-secondary small">#<?= (int) $g['id'] ?></span></td>
                    <td class="small"><?= e($local((string) $g['window_start'])) ?> → <?= e($local((string) $g['window_end'])) ?></td>
                    <td><span class="badge <?= e($cls) ?>"><?= e($label) ?></span></td>
                    <td class="small"><?= e((string) $g['created_by_name']) ?> / <?= e((string) ($g['approved_by_name'] ?? '–')) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table></div>
        <?php endif; ?>
    </div>
</div>
