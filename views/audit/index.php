<?php
/** Audit log (read-only). Expects: $entries (rows), $page, $pages, $q (text filter, 1.34), $total. All values escaped. */
$q ??= '';
?>
<div class="card">
    <div class="card-header">
        <form method="get" action="<?= e(url('/admin/audit')) ?>" role="search" class="d-flex flex-wrap gap-2 align-items-center">
            <label class="visually-hidden" for="audit-q"><?= e(__('Filter the audit log')) ?></label>
            <input class="form-control form-control-sm" style="max-width: 24rem" type="search" id="audit-q" name="q" maxlength="100" value="<?= e($q) ?>" placeholder="<?= e(__('Action, user or details contain…')) ?>">
            <button class="btn btn-sm btn-primary" type="submit"><?= e(__('Filter')) ?></button>
            <?php if ($q !== ''): ?><a class="small" href="<?= e(url('/admin/audit')) ?>"><?= e(__('Clear')) ?></a> <span class="small text-body-secondary"><?= e(__('{n} matching entries', ['n' => (int) ($total ?? 0)])) ?></span><?php endif; ?>
        </form>
    </div>
    <div class="card-body p-0 table-responsive">
        <table class="table table-sm table-striped align-middle mb-0">
            <thead>
            <tr>
                <th scope="col"><?= e(__('Time (UTC)')) ?></th>
                <th scope="col"><?= e(__('User')) ?></th>
                <th scope="col"><?= e(__('Action')) ?></th>
                <th scope="col"><?= e(__('Target')) ?></th>
                <th scope="col"><?= e(__('IP address')) ?></th>
                <th scope="col"><?= e(__('Details')) ?></th>
            </tr>
            </thead>
            <tbody>
            <?php if ($entries === []): ?>
            <tr><td colspan="6" class="text-center text-body-secondary py-3"><?= e(__('No entries yet.')) ?></td></tr>
            <?php endif; ?>
            <?php foreach ($entries as $row): ?>
            <tr>
                <td class="text-nowrap"><?= e($row['created_at']) ?></td>
                <td><?= e($row['username'] ?? '—') ?></td>
                <td><code><?= e($row['action']) ?></code></td>
                <td><?= e($row['target_type'] !== null ? $row['target_type'] . ' #' . $row['target_id'] : '') ?></td>
                <td><?= e($row['ip'] ?? '') ?></td>
                <td class="small text-break audit-details"><?= e($row['details'] ?? '') ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php if ($pages > 1): ?>
    <div class="card-footer">
        <nav aria-label="<?= e(__('Audit log pages')) ?>">
            <ul class="pagination pagination-sm mb-0">
                <li class="page-item<?= $page <= 1 ? ' disabled' : '' ?>"><a class="page-link" href="<?= e(url('/admin/audit', array_filter(['page' => max(1, $page - 1), 'q' => $q]))) ?>"><?= e(__('Newer')) ?></a></li>
                <li class="page-item disabled"><span class="page-link"><?= e(__('Page {p} of {n}', ['p' => $page, 'n' => $pages])) ?></span></li>
                <li class="page-item<?= $page >= $pages ? ' disabled' : '' ?>"><a class="page-link" href="<?= e(url('/admin/audit', array_filter(['page' => min($pages, $page + 1), 'q' => $q]))) ?>"><?= e(__('Older')) ?></a></li>
            </ul>
        </nav>
    </div>
    <?php endif; ?>
</div>
