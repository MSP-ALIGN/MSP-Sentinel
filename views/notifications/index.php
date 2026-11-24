<?php
/** The signed-in user's notifications (newest first). Expects: $notifications. Text comes from scan data: escaped. */
$sev = ['fail' => ['text-bg-danger', 'bi-x-octagon', __('Fail')], 'warn' => ['text-bg-warning', 'bi-exclamation-triangle', __('Warning')], 'info' => ['text-bg-secondary', 'bi-info-circle', __('Info')]];
?>
<div class="card">
    <?php $unreadIds = array_map(static fn (array $n): int => (int) $n['id'], array_filter($notifications, static fn (array $n): bool => $n['read_at'] === null)); ?>
    <?php if ($unreadIds !== []): ?>
    <div class="card-header d-flex align-items-center"><span class="small text-body-secondary"><?= e(__('{n} new', ['n' => count($unreadIds)])) ?></span>
        <form method="post" action="<?= e(url('/notifications/read')) ?>" class="ms-auto"><?= \Sentinel\Core\Csrf::field() ?>
            <input type="hidden" name="up_to" value="<?= e(max($unreadIds)) ?>">
            <button class="btn btn-sm btn-outline-secondary" type="submit"><i class="bi bi-check2-all me-1" aria-hidden="true"></i><?= e(__('Mark all as read')) ?></button></form></div>
    <?php endif; ?>
    <?php if ($notifications === []): ?>
    <div class="card-body"><p class="text-body-secondary mb-0"><?= e(__('No notifications yet.')) ?></p></div>
    <?php else: ?>
    <ul class="list-group list-group-flush">
        <?php foreach ($notifications as $n): ?>
        <?php [$cls, $icon, $label] = $sev[$n['severity']] ?? $sev['info']; ?>
        <li class="list-group-item<?= $n['read_at'] === null ? ' notification-unread' : '' ?>">
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <span class="badge <?= e($cls) ?>"><i class="bi <?= e($icon) ?> me-1" aria-hidden="true"></i><?= e($label) ?></span>
                <?php if ($n['link'] !== '' && str_starts_with((string) $n['link'], '/')): ?>
                <a href="<?= e(url((string) $n['link'])) ?>" class="fw-semibold"><?= e($n['title']) ?></a>
                <?php else: ?><span class="fw-semibold"><?= e($n['title']) ?></span><?php endif; ?>
                <?php if ($n['read_at'] === null): ?><span class="badge text-bg-primary"><?= e(__('New')) ?></span><?php endif; ?>
                <span class="ms-auto small text-body-secondary"><?= e(when($n['created_at'])) ?></span>
            </div>
            <?php if ($n['body'] !== ''): ?><div class="small text-pre-line text-body-secondary mt-1"><?= e(mb_strimwidth((string) $n['body'], 0, 600, '…')) ?></div><?php endif; ?>
        </li>
        <?php endforeach; ?>
    </ul>
    <?php endif; ?>
</div>
