<?php
/**
 * Saved reports, newest first, optionally for one client.
 * Expects: $reports, $clients, $clientFilter, $currentUser. Every value is escaped.
 */
use Sentinel\Core\Csrf;

$kindLabel = static fn (string $k): string => match ($k) { 'executive' => __('Executive summary'), 'pentest' => __('Penetration test report'), 'retest' => __('Retest letter'), default => __('Technical findings') };
?>
<div class="card">
    <div class="card-header">
        <form method="get" action="<?= e(url('/reports')) ?>" class="row g-2 align-items-end">
            <div class="col-md-4">
                <label class="form-label small mb-0" for="r-client"><?= e(__('Client')) ?></label>
                <select class="form-select form-select-sm" id="r-client" name="client">
                    <option value=""><?= e(__('All clients')) ?></option>
                    <?php foreach ($clients as $c): ?><option value="<?= e($c['id']) ?>" <?= $clientFilter === (int) $c['id'] ? 'selected' : '' ?>><?= e($c['name']) ?></option><?php endforeach; ?>
                </select>
            </div>
            <div class="col-auto"><button type="submit" class="btn btn-sm btn-outline-primary"><?= e(__('Filter')) ?></button></div>
        </form>
    </div>
    <?php if (in_array($currentUser['role'] ?? '', ['technician', 'admin'], true)): ?>
    <div class="card-body border-bottom">
        <h2 class="h6"><?= e(__('Create a report')) ?></h2>
        <form method="post" action="<?= e(url('/reports')) ?>" class="row g-2 align-items-end">
            <?= Csrf::field() ?>
            <div class="col-md-4"><label class="form-label small mb-0" for="new-client"><?= e(__('Client')) ?></label>
                <select class="form-select form-select-sm" id="new-client" name="client_id" required>
                    <option value=""><?= e(__('Choose…')) ?></option>
                    <?php foreach ($clients as $c): if ((int) ($c['is_archived'] ?? 0) === 1) { continue; } ?><option value="<?= e($c['id']) ?>" <?= $clientFilter === (int) $c['id'] ? 'selected' : '' ?>><?= e($c['name']) ?></option><?php endforeach; ?>
                </select></div>
            <div class="col-md-4"><label class="form-label small mb-0" for="new-kind"><?= e(__('Report')) ?></label>
                <select class="form-select form-select-sm" id="new-kind" name="kind">
                    <option value="both"><?= e(__('Executive summary and Technical findings')) ?></option>
                    <option value="executive"><?= e(__('Executive summary (for management)')) ?></option>
                    <option value="technical"><?= e(__('Technical findings (for IT)')) ?></option>
                </select></div>
            <div class="col-md-2"><label class="form-label small mb-0" for="new-period"><?= e(__('Period')) ?></label>
                <select class="form-select form-select-sm" id="new-period" name="period">
                    <option value="30"><?= e(__('Last 30 days')) ?></option>
                    <option value="month"><?= e(__('Last calendar month')) ?></option>
                    <option value="90"><?= e(__('Last 90 days')) ?></option>
                </select></div>
            <div class="col-md-2"><button type="submit" class="btn btn-primary btn-sm w-100"><i class="bi bi-file-earmark-plus me-1" aria-hidden="true"></i><?= e(__('Create')) ?></button></div>
        </form>
    </div>
    <?php endif; ?>
    <?php if ($reports === []): ?>
    <div class="card-body"><p class="text-body-secondary mb-0"><?= e(__('No reports yet.')) ?></p></div>
    <?php else: ?>
    <div class="card-body p-0 table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead><tr><th><?= e(__('Report')) ?></th><th><?= e(__('Client')) ?></th><th><?= e(__('Period')) ?></th><th><?= e(__('Created (UTC)')) ?></th><th><?= e(__('By')) ?></th><th></th></tr></thead>
            <tbody>
            <?php foreach ($reports as $r): ?>
            <tr>
                <td><a href="<?= e(url('/reports/' . (int) $r['id'])) ?>"><?= e($kindLabel((string) $r['kind'])) ?></a> <?php if ($r['source'] === 'scheduled'): ?><span class="badge text-bg-secondary"><?= e(__('Monthly')) ?></span><?php endif; ?></td>
                <td><?= e($r['client_name']) ?></td>
                <td class="small"><?= e($r['period_start'] . ' – ' . $r['period_end']) ?></td>
                <td class="small"><?= e($r['generated_at']) ?></td>
                <td class="small"><?= e($r['generated_by_name'] ?? __('Monthly schedule')) ?></td>
                <td class="text-end text-nowrap">
                    <a class="btn btn-sm btn-outline-primary" href="<?= e(url('/reports/' . (int) $r['id'] . '/view')) ?>" target="_blank" rel="noopener"><i class="bi bi-eye me-1" aria-hidden="true"></i><?= e(__('Open')) ?></a>
                    <a class="btn btn-sm btn-outline-secondary" href="<?= e(url('/reports/' . (int) $r['id'] . '/csv')) ?>"><i class="bi bi-filetype-csv me-1" aria-hidden="true"></i>CSV</a>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>
