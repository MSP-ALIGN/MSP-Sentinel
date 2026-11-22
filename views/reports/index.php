<?php
/**
 * Saved reports, newest first, optionally for one client.
 * Expects: $reports, $clients, $clientFilter. Every value is escaped.
 */
$kindLabel = static fn (string $k): string => $k === 'executive' ? __('Executive summary') : __('Technical findings');
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
            <div class="col small text-body-secondary text-md-end"><?= e(__('To create a report, open a client and use the Reports card.')) ?></div>
        </form>
    </div>
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
