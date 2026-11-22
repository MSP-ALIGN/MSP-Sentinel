<?php
/**
 * System page (admins): health checks, version/updates, data retention.
 * Expects: $checks, $version, $newer, $updateEnabled, $checkedAt, $retention, $retentionLast, $sourceUrl.
 * Every value is escaped. Status is shown with an icon and a word, not colour alone.
 */
use Sentinel\Core\Csrf;

$badge = ['ok' => ['success', 'bi-check-circle', __('OK')], 'warn' => ['warning', 'bi-exclamation-triangle', __('Warning')], 'fail' => ['danger', 'bi-x-octagon', __('Problem')]];
$fails = count(array_filter($checks, static fn (array $c): bool => $c['status'] === 'fail'));
?>
<div class="row g-3">
<div class="col-xl-8">
<div class="card mb-3" id="health">
    <div class="card-header d-flex align-items-center"><h2 class="card-title h5 mb-0"><?= e(__('Health')) ?></h2>
        <span class="ms-auto small text-body-secondary"><?= e(__('Same checks from the command line: php bin/doctor.php')) ?></span></div>
    <?php if ($fails > 0): ?><div class="card-body pb-0"><div class="alert alert-danger mb-0"><?= e(__('{n} problem(s) need attention.', ['n' => $fails])) ?></div></div><?php endif; ?>
    <div class="card-body p-0 table-responsive">
        <table class="table align-middle mb-0 small">
            <tbody>
            <?php foreach ($checks as $c): [$cls, $icon, $word] = $badge[$c['status']]; ?>
            <tr><td class="text-nowrap"><span class="badge text-bg-<?= e($cls) ?>"><i class="bi <?= e($icon) ?> me-1" aria-hidden="true"></i><?= e($word) ?></span></td>
                <th scope="row" class="text-nowrap"><?= e($c['label']) ?></th><td><?= e($c['detail']) ?></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
</div>
<div class="col-xl-4">
<div class="card mb-3" id="updates">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Version and updates')) ?></h2></div>
    <div class="card-body small">
        <p class="mb-2"><?= e(__('Installed: {v}', ['v' => $version])) ?></p>
        <?php if ($newer !== null): ?>
        <div class="alert alert-info py-2"><?= e(__('Version {v} is available.', ['v' => $newer])) ?> <a href="<?= e(rtrim($sourceUrl, '/') . '/releases') ?>" rel="noopener noreferrer" target="_blank"><?= e(__('Release notes')) ?></a></div>
        <?php endif; ?>
        <p class="text-body-secondary"><?= e($updateEnabled ? __('Once a day the worker asks the releases feed for the latest version. Nothing else is sent. Last check: {t}', ['t' => $checkedAt !== '' ? $checkedAt . ' UTC' : __('not yet')]) : __('The update check is off.')) ?></p>
        <form method="post" action="<?= e(url('/admin/system/updates')) ?>" class="mb-2">
            <?= Csrf::field() ?>
            <div class="form-check"><input class="form-check-input" type="checkbox" id="update_check_enabled" name="update_check_enabled" value="1" <?= $updateEnabled ? 'checked' : '' ?>>
                <label class="form-check-label" for="update_check_enabled"><?= e(__('Check for updates daily')) ?></label></div>
            <button type="submit" class="btn btn-outline-primary btn-sm mt-1"><?= e(__('Save')) ?></button>
        </form>
        <?php if ($updateEnabled): ?>
        <form method="post" action="<?= e(url('/admin/system/updates')) ?>"><?= Csrf::field() ?><input type="hidden" name="action" value="check"><button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Check now')) ?></button></form>
        <?php endif; ?>
    </div>
</div>
<div class="card mb-3" id="retention">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Data retention')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/system/retention')) ?>" novalidate>
        <?= Csrf::field() ?>
        <div class="card-body small">
            <p class="text-body-secondary"><?= e(__('Months to keep (0 = keep forever). The worker removes older data once a day. The audit log is always kept.')) ?></p>
            <?php foreach (['scans' => __('Scan history (finished scans and their log)'), 'findings' => __('Resolved findings and their history'), 'reports' => __('Reports')] as $k => $label): ?>
            <div class="row g-2 align-items-center mb-2">
                <label class="col-8 col-form-label" for="retention_<?= e($k) ?>"><?= e($label) ?></label>
                <div class="col-4"><input class="form-control form-control-sm" type="number" min="0" max="120" step="1" id="retention_<?= e($k) ?>" name="retention_<?= e($k) ?>" value="<?= e($retention[$k]) ?>"></div>
            </div>
            <?php endforeach; ?>
            <p class="text-body-secondary mb-0"><?= e(__('Last run: {t}', ['t' => $retentionLast !== '' ? $retentionLast . ' UTC' : __('not yet')])) ?></p>
        </div>
        <div class="card-footer"><button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save retention')) ?></button></div>
    </form>
</div>
</div>
</div>
