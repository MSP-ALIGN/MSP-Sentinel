<?php
/**
 * All findings across clients, with filters. Grouped by issue by default (1.31): the same problem on several targets
 * of one client is one row; open it to see each target and act on all of them at once (technicians and admins).
 * Expects: $filters (validated; assignee is 'none', a user ID or ''; group: '' or a group key), $grouped, $rows (flat),
 * $groups (grouped, each with 'members'), $total, $page, $pages, $clients, $counts, $fixCounts (overdue, due_soon,
 * mine, unassigned), $assignable, $currentUser.
 * Finding text comes from scan data and is always escaped. Bulk forms post IDs only; the server checks each one.
 */
use Sentinel\Core\Csrf;
use Sentinel\Findings\FindingRepository;

require __DIR__ . '/../partials/finding_badges.php';
$q = static fn (array $over): array => array_filter(array_merge(['client' => $filters['client'] ?: null, 'status' => $filters['status'] === '' ? 'all' : $filters['status'],
    'severity' => $filters['severity'] ?: null, 'type' => $filters['type'] ?: null, 'assignee' => $filters['assignee'] ?: null, 'due' => $filters['due'] ?: null, 'source' => $filters['source'] ?: null,
    'view' => $grouped ? null : 'flat', 'group' => $filters['group'] ?: null, 'q' => $filters['q'] ?: null], $over), static fn ($v) => $v !== null && $v !== '');
// Actions on findings by permission (1.40): each action shows only with its own permission; the panels show if any.
$canAct = can('findings.assign') || can('findings.triage') || can('findings.verify') || can('findings.due');
$isAdmin = can('findings.due');
$returnTo = '/findings' . (($qs = http_build_query($q([]))) !== '' ? '?' . $qs : '');
$me = (string) (int) $currentUser['id'];
$quick = [
    ['label' => __('Assigned to me'), 'n' => $fixCounts['mine'], 'params' => ['assignee' => 'me', 'status' => 'open'], 'active' => $filters['assignee'] === $me && $filters['due'] === '', 'icon' => 'bi-person-check'],
    ['label' => __('Unassigned'), 'n' => $fixCounts['unassigned'], 'params' => ['assignee' => 'none', 'status' => 'open'], 'active' => $filters['assignee'] === 'none' && $filters['due'] === '', 'icon' => 'bi-person-dash'],
    ['label' => __('Overdue'), 'n' => $fixCounts['overdue'], 'params' => ['due' => 'overdue'], 'active' => $filters['due'] === 'overdue', 'icon' => 'bi-alarm'],
    ['label' => __('Due within {d} days', ['d' => \Sentinel\Findings\FixWorkflow::DUE_SOON_DAYS]), 'n' => $fixCounts['due_soon'], 'params' => ['due' => 'soon'], 'active' => $filters['due'] === 'soon', 'icon' => 'bi-hourglass-split'],
];
$typeLabels = ['port' => __('Exposed service'), 'tls' => __('Certificate'), 'web' => __('Web page'), 'vuln' => __('Vulnerability'), 'email' => __('Email security'), 'patch' => __('Missing updates'), 'device' => __('Device security'), 'directory' => __('Active Directory'), 'dns' => __('DNS'), 'breach' => __('Breached account'), 'pentest' => __('Pen test')];
?>
<?php
// One finding as a row (the flat list, and groups of one in the grouped list).
// Picking findings for a bulk action (1.37): in the one-row-per-target view, technicians and admins tick rows; the
// boxes belong to the form "sel-bulk" above the table (HTML form attribute), which posts to /findings/bulk.
$selectable = $canAct && !$grouped;
$flatRow = static function (array $f) use ($findingSeverityBadge, $findingStatusBadge, $findingDueBadge, $typeLabels, $selectable): string {
    return '<tr>' . ($selectable ? '<td><input class="form-check-input" type="checkbox" name="ids[]" value="' . e((int) $f['id']) . '" form="sel-bulk" aria-label="' . e(__('Select finding #{id}', ['id' => (int) $f['id']])) . '"></td>' : '')
        . '<td>' . $findingSeverityBadge((string) $f['severity']) . '</td>'
        . '<td><a href="' . e(url('/findings/' . (int) $f['id'])) . '">' . e($f['title']) . '</a><div class="small text-body-secondary">' . e($typeLabels[$f['finding_type']] ?? '') . ' · <code>' . e($f['target']) . '</code></div></td>'
        . '<td><a href="' . e(url('/clients/' . (int) $f['client_id'])) . '">' . e($f['client_name']) . '</a></td>'
        . '<td>' . $findingStatusBadge((string) $f['status'], (int) $f['reappeared'] === 1) . '</td>'
        . '<td class="small">' . ($f['assignee_username'] !== null ? e($f['assignee_username']) : '<span class="text-body-secondary">' . e(__('Unassigned')) . '</span>') . '</td>'
        . '<td class="text-nowrap">' . $findingDueBadge($f) . '</td>'
        . '<td class="small text-nowrap">' . e(when($f['first_seen'])) . '</td></tr>';
};
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
        <?php // Phones: the filters fold away behind a button (open when a filter is in use), so the list comes first (1.34). ?>
        <?php $filtersInUse = array_filter($filters, static fn ($v): bool => is_string($v) && $v !== '' && $v !== 'open') !== []; ?>
        <button class="btn btn-outline-secondary btn-sm d-md-none mb-2" type="button" data-bs-toggle="collapse" data-bs-target="#findings-filters" aria-expanded="<?= $filtersInUse ? 'true' : 'false' ?>" aria-controls="findings-filters"><i class="bi bi-funnel me-1" aria-hidden="true"></i><?= e(__('Filters')) ?></button>
        <form method="get" action="<?= e(url('/findings')) ?>" class="row g-2 align-items-end collapse d-md-flex<?= $filtersInUse ? ' show' : '' ?>" id="findings-filters">
            <div class="col-12 col-md-6">
                <label class="form-label small mb-0" for="f-q"><?= e(__('Contains')) ?></label>
                <input class="form-control form-control-sm" type="search" id="f-q" name="q" maxlength="100" value="<?= e($filters['q']) ?>" placeholder="<?= e(__('Title, target or CVE')) ?>">
            </div>
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
                    <?php foreach ($assignable as $u): ?><option value="<?= e($u['id']) ?>" <?= $filters['assignee'] === (string) $u['id'] ? 'selected' : '' ?>><?= e($u['display_name'] !== '' ? $u['display_name'] . ' (' . $u['username'] . ')' : $u['username']) ?></option><?php endforeach; ?>
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
            <?php if (!$grouped): ?><input type="hidden" name="view" value="flat"><?php endif; ?>
            <div class="col-6 col-md-3"><button type="submit" class="btn btn-primary btn-sm w-100"><?= e(__('Filter')) ?></button></div>
        </form>
        <div class="d-flex flex-wrap gap-2 align-items-center mt-2 small" role="group" aria-label="<?= e(__('How to list findings')) ?>">
            <span class="text-body-secondary"><?= e(__('Show:')) ?></span>
            <a class="btn btn-sm <?= $grouped ? 'btn-primary' : 'btn-outline-secondary' ?>" href="<?= e(url('/findings', $q(['view' => null, 'group' => null, 'page' => null]))) ?>"<?= $grouped ? ' aria-current="page"' : '' ?>><i class="bi bi-collection me-1" aria-hidden="true"></i><?= e(__('Grouped by issue')) ?></a>
            <a class="btn btn-sm <?= !$grouped ? 'btn-primary' : 'btn-outline-secondary' ?>" href="<?= e(url('/findings', $q(['view' => 'flat', 'page' => null]))) ?>"<?= !$grouped ? ' aria-current="page"' : '' ?>><i class="bi bi-list-ul me-1" aria-hidden="true"></i><?= e(__('One row per target')) ?></a>
            <?php if ($filters['group'] !== ''): ?><span class="badge text-bg-info"><?= e(__('One issue')) ?> <a class="link-light ms-1" href="<?= e(url('/findings', $q(['group' => null, 'view' => null]))) ?>"><?= e(__('clear')) ?></a></span><?php endif; ?>
        </div>
    </div>
    <?php if ($selectable && $rows !== []): ?>
    <div class="card-body border-bottom">
        <form method="post" id="sel-bulk" action="<?= e(url('/findings/bulk')) ?>" class="row g-2 align-items-end" data-confirm="<?= e(__('Apply this action to the selected findings?')) ?>">
            <?= Csrf::field() ?><input type="hidden" name="return" value="<?= e($returnTo) ?>">
            <div class="col-12 small text-body-secondary"><?= e(__('Tick findings below, then choose what to do with them (at most 500 at once).')) ?> <span data-select-count="sel-bulk" data-select-count-label="<?= e(__('{n} selected')) ?>"></span></div>
            <div class="col-sm-3"><label class="form-label small mb-0" for="sel-action"><?= e(__('Action')) ?></label>
                <select class="form-select form-select-sm" id="sel-action" name="action" required>
                    <option value=""><?= e(__('Choose…')) ?></option>
                    <?php if (can('findings.assign')): ?><option value="assign"><?= e(__('Assign')) ?></option><?php endif; ?>
                    <?php if (can('findings.triage')): ?><option value="triage"><?= e(__('Accept risk / false positive / reopen')) ?></option><?php endif; ?>
                    <?php if ($isAdmin): ?><option value="due"><?= e(__('Set due date')) ?></option><?php endif; ?>
                    <?php if (can('findings.verify')): ?><option value="verify"><?= e(__('Verify fix')) ?></option><?php endif; ?>
                </select></div>
            <div class="col-sm-2"><label class="form-label small mb-0" for="sel-assignee"><?= e(__('Owner (assign)')) ?></label>
                <select class="form-select form-select-sm" id="sel-assignee" name="assignee"><option value="me"><?= e(__('Me')) ?></option><option value=""><?= e(__('Nobody')) ?></option>
                    <?php foreach ($assignable as $u): ?><option value="<?= e($u['id']) ?>"><?= e($u['display_name'] !== '' ? $u['display_name'] . ' (' . $u['username'] . ')' : $u['username']) ?></option><?php endforeach; ?></select></div>
            <div class="col-sm-2"><label class="form-label small mb-0" for="sel-status"><?= e(__('Decision (triage)')) ?></label>
                <select class="form-select form-select-sm" id="sel-status" name="status"><option value=""><?= e(__('Choose…')) ?></option><option value="accepted"><?= e(__('Accept the risk')) ?></option><option value="false_positive"><?= e(__('False positive')) ?></option><option value="open"><?= e(__('Reopen')) ?></option></select></div>
            <?php if ($isAdmin): ?><div class="col-sm-2"><label class="form-label small mb-0" for="sel-due"><?= e(__('Due date (due)')) ?></label><input class="form-control form-control-sm" type="date" id="sel-due" name="due_date"></div><?php endif; ?>
            <div class="col-sm-3"><label class="form-label small mb-0" for="sel-note"><?= e(__('Note (triage and due date need one; up to 500 characters)')) ?></label><input class="form-control form-control-sm" id="sel-note" name="note" maxlength="500"></div>
            <div class="col-12"><button class="btn btn-sm btn-primary" type="submit"><?= e(__('Apply to selected')) ?></button></div>
        </form>
    </div>
    <?php endif; ?>
    <div class="card-body p-0 table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead><tr>
                <?php if ($selectable): ?><th scope="col"><input class="form-check-input" type="checkbox" data-select-all="sel-bulk" aria-label="<?= e(__('Select all findings on this page')) ?>"></th><?php endif; ?>
                <th scope="col"><?= e(__('Grade')) ?></th><th scope="col"><?= e(__('Finding')) ?></th><th scope="col"><?= e(__('Client')) ?></th>
                <th scope="col"><?= e(__('Status')) ?></th><th scope="col"><?= e(__('Owner')) ?></th><th scope="col"><?= e(__('Due')) ?></th><th scope="col"><?= e(__('First seen')) ?></th>
            </tr></thead>
            <tbody>
            <?php if ($rows === [] && $groups === []): ?>
            <tr><td colspan="<?= $selectable ? 8 : 7 ?>" class="text-center text-body-secondary py-4"><?= e(__('No findings match these filters.')) ?></td></tr>
            <?php endif; ?>
            <?php foreach ($groups as $g):
                $members = $g['members'];
                if ((int) $g['n'] === 1 && count($members) === 1) { echo $flatRow($members[0] + ['client_name' => $g['client_name']]); continue; }
                $ids = array_map(static fn (array $m): string => (string) (int) $m['id'], $members);
                $statusText = (int) $g['statuses'] === 1 ? $findingStatusBadge((string) $members[0]['status'], (int) $g['reappeared'] === 1)
                    : e(__('{o} open of {n}', ['o' => (int) $g['open_n'], 'n' => (int) $g['n']]));
                $owner = (int) $g['owners'] === 1 ? ($members[0]['assignee_username'] !== null ? e($members[0]['assignee_username']) : '<span class="text-body-secondary">' . e(__('Unassigned')) . '</span>')
                    : '<span class="text-body-secondary">' . e(__('Several')) . '</span>';
                $bulkHidden = static function (string $action) use ($ids, $returnTo): string {
                    $h = Csrf::field() . '<input type="hidden" name="action" value="' . e($action) . '"><input type="hidden" name="return" value="' . e($returnTo) . '">';
                    foreach ($ids as $id) { $h .= '<input type="hidden" name="ids[]" value="' . e($id) . '">'; }
                    return $h;
                };
            ?>
            <tr class="sn-group align-top">
                <td><?= $findingSeverityBadge((string) $g['severity']) ?></td>
                <td>
                    <details>
                        <summary><span class="fw-semibold"><?= e($g['title']) ?></span>
                            <div class="small text-body-secondary"><?= e($typeLabels[$g['finding_type']] ?? '') ?> · <?= e(__('on {n} targets', ['n' => (int) $g['n']])) ?>:
                                <code><?= e(implode(', ', array_slice(array_map(static fn (array $m): string => (string) $m['target'], $members), 0, 3))) ?></code><?= (int) $g['n'] > 3 ? ' …' : '' ?></div></summary>
                        <table class="table table-sm small mt-2 mb-2">
                            <thead><tr><th scope="col"><?= e(__('Target')) ?></th><th scope="col"><?= e(__('Status')) ?></th><th scope="col"><?= e(__('Owner')) ?></th><th scope="col"><?= e(__('Due')) ?></th></tr></thead>
                            <tbody>
                            <?php foreach ($members as $m): ?>
                            <tr><td><a href="<?= e(url('/findings/' . (int) $m['id'])) ?>"><code><?= e($m['target']) ?></code></a> <?= $findingSeverityBadge((string) $m['severity']) ?></td>
                                <td><?= $findingStatusBadge((string) $m['status'], (int) $m['reappeared'] === 1) ?></td>
                                <td><?= $m['assignee_username'] !== null ? e($m['assignee_username']) : '<span class="text-body-secondary">' . e(__('Unassigned')) . '</span>' ?></td>
                                <td class="text-nowrap"><?= $findingDueBadge($m) ?></td></tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                        <?php if ((int) $g['n'] > count($members)): ?>
                        <p class="small"><?= e(__('Showing {s} of {n}; actions apply to the ones shown.', ['s' => count($members), 'n' => (int) $g['n']])) ?> <a href="<?= e(url('/findings', $q(['group' => $g['group_key'], 'view' => 'flat', 'page' => null]))) ?>"><?= e(__('Show all')) ?></a></p>
                        <?php endif; ?>
                        <?php if ($canAct): ?>
                        <div class="border rounded p-2 mb-2">
                            <p class="small fw-semibold mb-2"><?= e(__('For all {n} targets above', ['n' => count($members)])) ?></p>
                            <?php if (can('findings.assign')): ?>
                            <form method="post" action="<?= e(url('/findings/bulk')) ?>" class="row g-1 align-items-end mb-2"><?= $bulkHidden('assign') ?>
                                <div class="col-sm-4"><label class="form-label small mb-0" for="ba-<?= e($g['group_key']) ?>"><?= e(__('Owner')) ?></label>
                                    <select class="form-select form-select-sm" id="ba-<?= e($g['group_key']) ?>" name="assignee">
                                        <option value="me"><?= e(__('Me')) ?></option><option value=""><?= e(__('Unassigned')) ?></option>
                                        <?php foreach ($assignable as $u): ?><option value="<?= e($u['id']) ?>"><?= e($u['display_name'] !== '' ? $u['display_name'] . ' (' . $u['username'] . ')' : $u['username']) ?></option><?php endforeach; ?>
                                    </select></div>
                                <div class="col-sm-5"><label class="form-label small mb-0" for="ban-<?= e($g['group_key']) ?>"><?= e(__('Note (optional)')) ?></label><input class="form-control form-control-sm" id="ban-<?= e($g['group_key']) ?>" name="note" maxlength="500"></div>
                                <div class="col-sm-3"><button class="btn btn-sm btn-outline-primary w-100" type="submit"><?= e(__('Assign all')) ?></button></div>
                            </form>
                            <?php endif; ?>
                            <?php if (can('findings.triage')): ?>
                            <form method="post" data-confirm="<?= e(__('Apply this decision to all {n} targets in this group?', ['n' => count($members)])) ?>" action="<?= e(url('/findings/bulk')) ?>" class="row g-1 align-items-end mb-2"><?= $bulkHidden('triage') ?>
                                <div class="col-sm-4"><label class="form-label small mb-0" for="bt-<?= e($g['group_key']) ?>"><?= e(__('Decision')) ?></label>
                                    <select class="form-select form-select-sm" id="bt-<?= e($g['group_key']) ?>" name="status">
                                        <option value="accepted"><?= e(__('Accept risk')) ?></option><option value="false_positive"><?= e(__('False positive')) ?></option><option value="open"><?= e(__('Reopen')) ?></option>
                                    </select></div>
                                <div class="col-sm-5"><label class="form-label small mb-0" for="btn-<?= e($g['group_key']) ?>"><?= e(__('Why (required)')) ?></label><input class="form-control form-control-sm" id="btn-<?= e($g['group_key']) ?>" name="note" maxlength="2000" required></div>
                                <div class="col-sm-3"><button class="btn btn-sm btn-outline-primary w-100" type="submit"><?= e(__('Apply to all')) ?></button></div>
                            </form>
                            <?php endif; ?>
                            <?php if ($isAdmin): ?>
                            <form method="post" data-confirm="<?= e(__('Set this due date for all {n} targets in this group?', ['n' => count($members)])) ?>" action="<?= e(url('/findings/bulk')) ?>" class="row g-1 align-items-end mb-2"><?= $bulkHidden('due') ?>
                                <div class="col-sm-4"><label class="form-label small mb-0" for="bd-<?= e($g['group_key']) ?>"><?= e(__('Due date')) ?></label><input class="form-control form-control-sm" type="date" id="bd-<?= e($g['group_key']) ?>" name="due_date">
                                    <div class="form-check small"><input class="form-check-input" type="checkbox" id="bdr-<?= e($g['group_key']) ?>" name="reset" value="1"><label class="form-check-label" for="bdr-<?= e($g['group_key']) ?>"><?= e(__('Follow the policy again')) ?></label></div></div>
                                <div class="col-sm-5"><label class="form-label small mb-0" for="bdn-<?= e($g['group_key']) ?>"><?= e(__('Reason (required)')) ?></label><input class="form-control form-control-sm" id="bdn-<?= e($g['group_key']) ?>" name="note" maxlength="500" required></div>
                                <div class="col-sm-3"><button class="btn btn-sm btn-outline-primary w-100" type="submit"><?= e(__('Set due date')) ?></button></div>
                            </form>
                            <?php endif; ?>
                            <?php if (can('findings.verify')): ?>
                            <form method="post" data-confirm="<?= e(__('Recheck all {n} targets in this group now? Each one is scanned again on its own.', ['n' => count($members)])) ?>" action="<?= e(url('/findings/bulk')) ?>"><?= $bulkHidden('verify') ?>
                                <button class="btn btn-sm btn-outline-secondary" type="submit"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Verify fix on all')) ?></button>
                                <span class="small text-body-secondary ms-1"><?= e(__('Each target is rechecked on its own (at most 10 waiting per client).')) ?></span>
                            </form>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>
                    </details>
                </td>
                <td><a href="<?= e(url('/clients/' . (int) $g['client_id'])) ?>"><?= e($g['client_name']) ?></a></td>
                <td><?= $statusText ?></td>
                <td class="small"><?= $owner ?></td>
                <td class="text-nowrap"><?= $findingDueBadge(['status' => (int) $g['open_n'] > 0 ? 'open' : '', 'due_at' => $g['due_at']]) ?></td>
                <td class="small text-nowrap"><?= e(when($g['first_seen'])) ?></td>
            </tr>
            <?php endforeach; ?>
            <?php foreach ($rows as $f) { echo $flatRow($f); } ?>
            </tbody>
        </table>
    </div>
    <?php if ($pages > 1): ?>
    <div class="card-footer small">
        <?= e($grouped ? __('Page {p} of {n} ({t} issues)', ['p' => $page, 'n' => $pages, 't' => $total]) : __('Page {p} of {n} ({t} findings)', ['p' => $page, 'n' => $pages, 't' => $total])) ?>
        <?php if ($page > 1): ?><a class="ms-2" href="<?= e(url('/findings', $q(['page' => $page - 1]))) ?>"><?= e(__('Previous')) ?></a><?php endif; ?>
        <?php if ($page < $pages): ?><a class="ms-2" href="<?= e(url('/findings', $q(['page' => $page + 1]))) ?>"><?= e(__('Next')) ?></a><?php endif; ?>
    </div>
    <?php endif; ?>
</div>
