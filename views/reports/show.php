<?php
/**
 * One saved report: details, rating, totals and actions.
 * Expects: $report (without HTML), $counts, $rating, $currentUser. Every value is escaped.
 * Delete is shown to admins only (the route enforces it too).
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

$id = (int) $report['id'];
$ratingLabel = ['risk' => [__('At risk'), 'danger', 'bi-x-octagon'], 'attention' => [__('Needs attention'), 'warning', 'bi-exclamation-triangle'], 'good' => [__('Good'), 'success', 'bi-check-circle']];
$rt = $rating !== null ? ($ratingLabel[$rating['level']] ?? null) : null;
?>
<div class="row g-3">
    <div class="col-lg-8">
        <div class="card">
            <div class="card-body">
                <?php if ($rt !== null): ?>
                <p class="h5"><span class="badge text-bg-<?= e($rt[1]) ?>"><i class="bi <?= e($rt[2]) ?> me-1" aria-hidden="true"></i><?= e($rt[0]) ?></span> <span class="small"><?= e($rating['reason']) ?></span></p>
                <?php endif; ?>
                <dl class="row small mb-3">
                    <dt class="col-sm-4"><?= e(__('Client')) ?></dt><dd class="col-sm-8"><a href="<?= e(url('/clients/' . (int) $report['client_id'])) ?>"><?= e($report['client_name']) ?></a></dd>
                    <dt class="col-sm-4"><?= e(__('Type')) ?></dt><dd class="col-sm-8"><?= e(match ((string) $report['kind']) { 'executive' => __('Executive summary'), 'pentest' => __('Penetration test report'), 'retest' => __('Retest letter'), default => __('Technical findings') }) ?><?= $report['source'] === 'scheduled' ? ' · ' . e(__('Monthly')) : '' ?></dd>
                    <dt class="col-sm-4"><?= e(__('Period')) ?></dt><dd class="col-sm-8"><?= e($report['period_start'] . ' – ' . $report['period_end']) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Created')) ?></dt><dd class="col-sm-8"><?= e($report['generated_at']) ?> UTC · <?= e($report['generated_by_name'] ?? __('Monthly schedule')) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Totals')) ?></dt><dd class="col-sm-8"><?= e(__('{f} Fail, {w} Warning, {x} fixed this period, {a} accepted, {p} false positive', ['f' => $counts['fail'] ?? 0, 'w' => $counts['warn'] ?? 0, 'x' => $counts['fixed'] ?? 0, 'a' => $counts['accepted'] ?? 0, 'p' => $counts['false_positive'] ?? 0])) ?></dd>
                    <dt class="col-sm-4"><?= e(__('SHA-256')) ?></dt><dd class="col-sm-8"><code class="small text-break"><?= e($report['html_sha256']) ?></code></dd>
                </dl>
                <p class="small text-body-secondary"><?= e(__('This report is frozen: it shows the data as it was when it was created and never changes. The SHA-256 above identifies the exact document.')) ?></p>
                <div class="d-flex flex-wrap gap-2">
                    <a class="btn btn-primary btn-sm" href="<?= e(url('/reports/' . $id . '/view')) ?>" target="_blank" rel="noopener"><i class="bi bi-eye me-1" aria-hidden="true"></i><?= e(__('Open report (print to PDF from the browser)')) ?></a>
                    <a class="btn btn-outline-secondary btn-sm" href="<?= e(url('/reports/' . $id . '/download')) ?>"><i class="bi bi-download me-1" aria-hidden="true"></i><?= e(__('Download HTML')) ?></a>
                    <a class="btn btn-outline-secondary btn-sm" href="<?= e(url('/reports/' . $id . '/csv')) ?>"><i class="bi bi-filetype-csv me-1" aria-hidden="true"></i><?= e(__('Download findings (CSV)')) ?></a>
                </div>
            </div>
            <?php if (Role::atLeast((string) $currentUser['role'], Role::ADMIN)): ?>
            <div class="card-footer">
                <form method="post" action="<?= e(url('/reports/' . $id . '/delete')) ?>" data-confirm="<?= e(__('Delete this report? This cannot be undone.')) ?>">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-trash me-1" aria-hidden="true"></i><?= e(__('Delete report')) ?></button>
                </form>
            </div>
            <?php endif; ?>
        </div>
    </div>
</div>
