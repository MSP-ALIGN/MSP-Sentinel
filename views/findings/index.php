<?php
/**
 * All findings across clients, with filters.
 * Expects: $filters (validated; assignee is 'none', a user ID or ''), $rows, $total, $page, $pages, $clients,
 * $counts, $fixCounts (overdue, due_soon, mine, unassigned), $assignable, $currentUser.
 * Finding text comes from scan data and is always escaped.
 */
require __DIR__ . '/../partials/finding_badges.php';
$q = static fn (array $over): array => array_filter(array_merge(['client' => $filters['client'] ?: null, 'status' => $filters['status'] === '' ? 'all' : $filters['status'],
    'severity' => $filters['severity'] ?: null, 'type' => $filters['type'] ?: null, 'assignee' => $filters['assignee'] ?: null, 'due' => $filters['due'] ?: null, 'source' => $filters['source'] ?: null], $over), static fn ($v) => $v !== null && $v !== '');
$me = (string) (int) $currentUser['id'];
$quick = [
    ['label' => __('Assigned to me'), 'n' => $fixCounts['mine'], 'params' => ['assignee' => 'me', 'status' => 'open'], 'active' => $filters['assignee'] === $me && $filters['due'] === '', 'icon' => 'bi-person-check'],
    ['label' => __('Unassigned'), 'n' => $fixCounts['unassigned'], 'params' => ['assignee' => 'none', 'status' => 'open'], 'active' => $filters['assignee'] === 'none' && $filters['due'] === '', 'icon' => 'bi-person-dash'],
    ['label' => __('Overdue'), 'n' => $fixCounts['overdue'], 'params' => ['due' => 'overdue'], 'active' => $filters['due'] === 'overdue', 'icon' => 'bi-alarm'],
    ['label' => __('Due within {d} days', ['d' => \Sentinel\Findings\FixWorkflow::DUE_SOON_DAYS]), 'n' => $fixCounts['due_soon'], 'params' => ['due' => 'soon'], 'active' => $filters['due'] === 'soon', 'icon' => 'bi-hourglass-split'],
];
$typeLabels = ['port' => __('Exposed service'), 'tls' => __('Certificate'), 'web' => __('Web page'), 'vuln' => __('Vulnerability'), 'email' => __('Email security'), 'patch' => __('Missing updates'), 'device' => __('Device security'), 'directory' => __('Active Directory')];
?>
<div class="row g-3 mb-3">
    <div class="col-6 col-md-3"><div class="small-box <?= $counts['fail'] > 0 ? 'text-bg-danger' : 'text-bg-secondary' ?>"><div class="inner"><h3><?= e($counts['fail']) ?></h3><p><?= e(__('Open Fail')) ?></p></div><i class="small-box-icon bi bi-x-octagon" aria-hidden="true"></i></div></div>
    <div class="col-6 col-md-3"><div class="small-box <?= $counts['warn'] > 0 ? 'text-bg-warning' : 'text-bg-secondary' ?>"><div class="inner"><h3><?= e($counts['warn']) ?></h3><p><?= e(__('Open Warning')) ?></p></div><i class="small-box-icon bi bi-exclamation-triangle" aria-hidden="true"></i></div></div>
    <div class="col-6 col-md-3"><div class="small-box text-bg-info"><div class="inner"><h3><?= e($counts['accepted']) ?></h3><p><?= e(__('Accepted risks')) ?></p></div><i class="small-box-icon bi bi-hand-thumbs-up" aria-hidden="true"></i></div></div>
    <div class="col-6 col-md-3"><div class="small-box text-bg-secondary"><div class="inner"><h3><?= e($counts['false_positive']) ?></h3><p><?= e(__('False positives')) ?></p></div><i class="small-box-icon bi bi-slash-circle" aria-hidden="true"></i></div></div>
</div>
<nav class="d-flex flex-wrap gap-2 mb-3" aria-label="<?= e(__('Fix workflow')) ?>">
    <?php foreach ($quick as $item): ?>
    <a class="btn btn-sm <?= $item['active'] ? 'btn-primary' : 'btn-outline-secondary' ?>" href="<?= e(url('/findings', $item['params'])) ?>"<?= $item['active'] ? ' aria-current="page"' : '' ?>><i class="bi <?= e($item['icon']) ?> me-1" aria-hidden="true"></i><?= e($item['label']) ?> <span class="badge text-bg-dark ms-1"><?= e($item['n']) ?></span></a>
    <?php endforeach; ?>
</nav>
<div class="card">
    <div class="card-header">
        <form method="get" action="<?= e(url('/findings')) ?>" class="row g-2 align-items-end">
            <div class="col-6 col-md-3">
                <label class="form-label small mb-0" for="f-client"><?= e(__('Client')) ?></label>
                <select class="form-select form-select-sm" id="f-client" name="client">
                    <option value=""><?= e(__('All clients')) ?></option>
                    <?php foreach ($clients as $c): ?><option value="<?= e($c['id']) ?>" <?= (int) $filters['client'] === (int) $c['id'] ? 'selected' : '' ?>><?= e($c['name']) ?></option><?php endforeach; ?>
                </select>
            </div>
            <div class="col-6 col-md-3">
                <label class="form-label small mb-0" for="f-status"><?= e(__('Status')) ?></label>
                <select class="form-select form-select-sm" id="f-status" name="status">
                    <?php foreach (['open' => __('Open'), 'accepted' => __('Accepted risk'), 'false_positive' => __('False positive'), 'resolved' => __('Resolved'), 'all' => __('Any status')] as $v => $l): ?>
                    <option value="<?= e($v) ?>" <?= ($filters['status'] === '' ? 'all' : $filters['status']) === $v ? 'selected' : '' ?>><?= e($l) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-6 col-md-3">
                <label class="form-label small mb-0" for="f-sev"><?= e(__('Grade')) ?></label>
                <select class="form-select form-select-sm" id="f-sev" name="severity">
                    <option value=""><?= e(__('Fail and Warning')) ?></option>
                    <option value="fail" <?= $filters['severity'] === 'fail' ? 'selected' : '' ?>><?= e(__('Fail')) ?></option>
                    <option value="warn" <?= $filters['severity'] === 'warn' ? 'selected' : '' ?>><?= e(__('Warning')) ?></option>
                </select>
            </div>
            <div class="col-6 col-md-3">
                <label class="form-label small mb-0" for="f-assignee"><?= e(__('Owner')) ?></label>
                <select class="form-select form-select-sm" id="f-assignee" name="assignee">
                    <option value=""><?= e(__('Anyone')) ?></option>
                    <option value="none" <?= $filters['assignee'] === 'none' ? 'selected' : '' ?>><?= e(__('Unassigned')) ?></option>
                    <?php foreach ($assignable as $u): ?><option value="<?= e($u['id']) ?>" <?= $filters['assignee'] === (string) $u['id'] ? 'selected' : '' ?>><?= e($u['username']) ?></option><?php endforeach; ?>
                </select>
            </div>
            <div class="col-6 col-md-3">
                <label class="form-label small mb-0" for="f-due"><?= e(__('Due')) ?></label>
                <select class="form-select form-select-sm" id="f-due" name="due">
                    <option value=""><?= e(__('Any')) ?></option>
                    <option value="overdue" <?= $filters['due'] === 'overdue' ? 'selected' : '' ?>><?= e(__('Overdue')) ?></option>
                    <option value="soon" <?= $filters['due'] === 'soon' ? 'selected' : '' ?>><?= e(__('Due soon')) ?></option>
                </select>
            </div>
            <div class="col-6 col-md-3">
                <label class="form-label small mb-0" for="f-source"><?= e(__('Where')) ?></label>
                <select class="form-select form-select-sm" id="f-source" name="source">
                    <option value=""><?= e(__('Internet and internal')) ?></option>
                    <option value="external" <?= $filters['source'] === 'external' ? 'selected' : '' ?>><?= e(__('Internet (external scan)')) ?></option>
                    <option value="internal" <?= $filters['source'] === 'internal' ? 'selected' : '' ?>><?= e(__('Internal devices')) ?></option>
                </select>
            </div>
            <div class="col-6 col-md-3">
                <label class="form-label small mb-0" for="f-type"><?= e(__('Type')) ?></label>
                <select class="form-select form-select-sm" id="f-type" name="type">
                    <option value=""><?= e(__('All types')) ?></option>
                    <?php foreach ($typeLabels as $v => $l): ?><option value="<?= e($v) ?>" <?= $filters['type'] === $v ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?>
                </select>
            </div>
            <div class="col-6 col-md-3"><button type="submit" class="btn btn-primary btn-sm w-100"><?= e(__('Filter')) ?></button></div>
        </form>
    </div>
    <div class="card-body p-0 table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead><tr>
                <th scope="col"><?= e(__('Grade')) ?></th><th scope="col"><?= e(__('Finding')) ?></th><th scope="col"><?= e(__('Client')) ?></th>
                <th scope="col"><?= e(__('Status')) ?></th><th scope="col"><?= e(__('Owner')) ?></th><th scope="col"><?= e(__('Due')) ?></th><th scope="col"><?= e(__('First seen (UTC)')) ?></th>
            </tr></thead>
            <tbody>
            <?php if ($rows === []): ?>
            <tr><td colspan="7" class="text-center text-body-secondary py-4"><?= e(__('No findings match these filters.')) ?></td></tr>
            <?php endif; ?>
            <?php foreach ($rows as $f): ?>
            <tr>
                <td><?= $findingSeverityBadge((string) $f['severity']) ?></td>
                <td><a href="<?= e(url('/findings/' . (int) $f['id'])) ?>"><?= e($f['title']) ?></a><div class="small text-body-secondary"><?= e($typeLabels[$f['finding_type']] ?? '') ?> · <code><?= e($f['target']) ?></code></div></td>
                <td><a href="<?= e(url('/clients/' . (int) $f['client_id'])) ?>"><?= e($f['client_name']) ?></a></td>
                <td><?= $findingStatusBadge((string) $f['status'], (int) $f['reappeared'] === 1) ?></td>
                <td class="small"><?= $f['assignee_username'] !== null ? e($f['assignee_username']) : '<span class="text-body-secondary">' . e(__('Unassigned')) . '</span>' ?></td>
                <td class="text-nowrap"><?= $findingDueBadge($f) ?></td>
                <td class="small text-nowrap"><?= e($f['first_seen']) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php if ($pages > 1): ?>
    <div class="card-footer small">
        <?= e(__('Page {p} of {n} ({t} findings)', ['p' => $page, 'n' => $pages, 't' => $total])) ?>
        <?php if ($page > 1): ?><a class="ms-2" href="<?= e(url('/findings', $q(['page' => $page - 1]))) ?>"><?= e(__('Previous')) ?></a><?php endif; ?>
        <?php if ($page < $pages): ?><a class="ms-2" href="<?= e(url('/findings', $q(['page' => $page + 1]))) ?>"><?= e(__('Next')) ?></a><?php endif; ?>
    </div>
    <?php endif; ?>
</div>
