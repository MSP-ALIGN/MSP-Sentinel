<?php
/**
 * One finding: details, the fix card (owner, due date, verify fix), history and the
 * triage form (technicians and admins).
 * Expects: $finding, $events, $errors, $values, $assignable, $verifiable, $currentUser.
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

require __DIR__ . '/../partials/finding_badges.php';
$canTriage = Role::atLeast((string) $currentUser['role'], Role::TECHNICIAN);
$isAdmin = Role::atLeast((string) $currentUser['role'], Role::ADMIN);
$editable = $finding['status'] !== 'resolved' && (int) $finding['client_archived'] !== 1;
$verifyResult = is_string($finding['verify_summary'] ?? null) ? (json_decode($finding['verify_summary'], true)['verify_result'] ?? null) : null;
$values = ($values ?? []) + ['status' => '', 'note' => ''];
$eventLabels = [
    'opened' => __('First seen'), 'resolved' => __('Resolved automatically'), 'reopened' => __('Seen again (reopened)'),
    'evidence_changed' => __('Reopened: evidence changed'), 'severity_changed' => __('Grade changed'), 'alerted' => __('Alert sent'),
    'triaged_accepted' => __('Marked as accepted risk'), 'triaged_false_positive' => __('Marked as false positive'), 'triaged_open' => __('Reopened by a user'),
    'assigned' => __('Assigned'), 'unassigned' => __('Unassigned'), 'due_changed' => __('Due date changed'),
    'verify_requested' => __('Recheck requested'), 'verified' => __('Recheck finished'), 'itflow_ticket' => __('ITFlow ticket'),
];
?>
<div class="row g-3">
    <div class="col-lg-7">
        <div class="card">
            <div class="card-header d-flex align-items-center flex-wrap gap-2">
                <?= $findingSeverityBadge((string) $finding['severity']) ?> <?= $findingStatusBadge((string) $finding['status'], (int) $finding['reappeared'] === 1) ?>
                <a class="ms-auto small" href="<?= e(url('/clients/' . (int) $finding['client_id'])) ?>"><?= e($finding['client_name']) ?></a>
            </div>
            <div class="card-body">
                <h2 class="h5"><?= e($finding['title']) ?></h2>
                <p class="mb-2"><code><?= e($finding['target']) ?></code>
                    <?php if (($finding['device_id'] ?? null) !== null): ?> · <a href="<?= e(url('/clients/' . (int) $finding['client_id'] . '/devices/' . (int) $finding['device_id'])) ?>"><i class="bi bi-pc-display me-1" aria-hidden="true"></i><?= e(__('Device details')) ?></a> <span class="badge text-bg-dark"><?= e(__('Internal')) ?></span><?php endif; ?></p>
                <p class="text-pre-line"><?= e($finding['detail']) ?></p>
                <?php if (($itflowTicket ?? null) !== null): ?>
                <p class="small"><i class="bi bi-ticket-perforated me-1" aria-hidden="true"></i><?= e(__('ITFlow ticket')) ?>:
                    <?php $tRef = $itflowTicket['reference'] !== '' ? $itflowTicket['reference'] : '#' . (int) $itflowTicket['itflow_ticket_id']; ?>
                    <?php $itflowBase = rtrim(\Sentinel\Core\App::settings()->get('itflow_url'), '/') . '/'; ?>
                    <?php if ($itflowTicket['url'] !== '' && str_starts_with($itflowTicket['url'], $itflowBase)): ?><a href="<?= e($itflowTicket['url']) ?>" rel="noopener noreferrer" target="_blank"><?= e($tRef) ?></a><?php else: ?><?= e($tRef) ?><?php endif; ?>
                    <span class="text-body-secondary">(<?= e(__('opened {t} UTC', ['t' => $itflowTicket['created_at']])) ?>)</span></p>
                <?php endif; ?>
                <?php if ($finding['cve_id'] !== null): ?>
                <p class="small"><a href="https://nvd.nist.gov/vuln/detail/<?= e(rawurlencode((string) $finding['cve_id'])) ?>" target="_blank" rel="noopener noreferrer"><?= e(__('{cve} on NVD', ['cve' => $finding['cve_id']])) ?></a></p>
                <?php endif; ?>
                <dl class="row small mb-0">
                    <dt class="col-sm-4"><?= e(__('First seen')) ?></dt><dd class="col-sm-8"><?= e($finding['first_seen']) ?> UTC</dd>
                    <dt class="col-sm-4"><?= e(__('Last seen')) ?></dt><dd class="col-sm-8"><?= e($finding['last_seen']) ?> UTC</dd>
                    <?php if ($finding['asset_last_scanned'] !== null): ?><dt class="col-sm-4"><?= e(__('Host last scanned')) ?></dt><dd class="col-sm-8"><?= e($finding['asset_last_scanned']) ?> UTC</dd><?php endif; ?>
                    <?php if ($finding['resolved_at'] !== null): ?><dt class="col-sm-4"><?= e(__('Resolved')) ?></dt><dd class="col-sm-8"><?= e($finding['resolved_at']) ?> UTC</dd><?php endif; ?>
                    <?php if ((int) $finding['reopened_count'] > 0): ?><dt class="col-sm-4"><?= e(__('Reopened')) ?></dt><dd class="col-sm-8"><?= e(__('{n} time(s)', ['n' => $finding['reopened_count']])) ?></dd><?php endif; ?>
                    <?php if ($finding['triage_note'] !== null): ?>
                    <dt class="col-sm-4"><?= e(__('Last triage note')) ?></dt>
                    <dd class="col-sm-8 text-pre-line"><?= e($finding['triage_note']) ?><div class="text-body-secondary"><?= e(__('{user}, {date} UTC', ['user' => $finding['triaged_by_username'] ?? '?', 'date' => $finding['triaged_at']])) ?></div></dd>
                    <?php endif; ?>
                </dl>
            </div>
        </div>

        <?php if ($canTriage && $finding['status'] !== 'resolved' && (int) $finding['client_archived'] !== 1): ?>
        <div class="card mt-3">
            <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('Triage')) ?></h2></div>
            <form method="post" action="<?= e(url('/findings/' . (int) $finding['id'] . '/triage')) ?>" novalidate>
            <div class="card-body">
                <?= Csrf::field() ?>
                <fieldset class="mb-3">
                    <legend class="form-label fs-6"><?= e(__('Decision')) ?></legend>
                    <?php foreach (['accepted' => __('Accept the risk (the client knows and accepts it)'), 'false_positive' => __('False positive (this is not really a problem; reopens if the evidence changes)'), 'open' => __('Reopen (undo an earlier decision)')] as $v => $l): ?>
                    <?php if ($v === $finding['status']) { continue; } ?>
                    <div class="form-check">
                        <input class="form-check-input" type="radio" name="status" id="st-<?= e($v) ?>" value="<?= e($v) ?>" <?= $values['status'] === $v ? 'checked' : '' ?>>
                        <label class="form-check-label" for="st-<?= e($v) ?>"><?= e($l) ?></label>
                    </div>
                    <?php endforeach; ?>
                    <?php $field = 'status'; require __DIR__ . '/../partials/field_error.php'; ?>
                </fieldset>
                <label for="note" class="form-label"><?= e(__('Note (required)')) ?></label>
                <textarea class="form-control<?= !empty($errors['note']) ? ' is-invalid' : '' ?>" id="note" name="note" rows="3" maxlength="2000" required><?= e($values['note']) ?></textarea>
                <?php $field = 'note'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
            <div class="card-footer"><button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save decision')) ?></button></div>
            </form>
        </div>
        <?php elseif (!empty($errors['status'])): ?>
        <div class="alert alert-info mt-3"><?= e($errors['status']) ?></div>
        <?php endif; ?>
    </div>
    <div class="col-lg-5">
        <div class="card mb-3" id="fix">
            <div class="card-header d-flex align-items-center gap-2"><h2 class="card-title h6 mb-0"><?= e(__('Fix')) ?></h2><span class="ms-auto"><?= $findingDueBadge($finding) ?></span></div>
            <div class="card-body small">
                <?php if (!empty($errors['assign'])): ?><div class="alert alert-danger py-2"><?= e($errors['assign']) ?></div><?php endif; ?>
                <?php if (!empty($errors['due'])): ?><div class="alert alert-danger py-2"><?= e($errors['due']) ?></div><?php endif; ?>
                <dl class="row mb-2">
                    <dt class="col-5"><?= e(__('Owner')) ?></dt>
                    <dd class="col-7"><?php if ($finding['assigned_to'] === null): ?><span class="text-body-secondary"><?= e(__('Unassigned')) ?></span>
                        <?php else: ?><i class="bi bi-person me-1" aria-hidden="true"></i><?= e($finding['assignee_username'] ?? '?') ?><?php if ((int) ($finding['assignee_active'] ?? 1) !== 1): ?> <span class="badge text-bg-secondary"><?= e(__('inactive')) ?></span><?php endif; ?>
                        <div class="text-body-secondary"><?= e(__('by {user}, {date} UTC', ['user' => $finding['assigned_by_username'] ?? '?', 'date' => $finding['assigned_at'] ?? '?'])) ?></div><?php endif; ?></dd>
                    <dt class="col-5"><?= e(__('Due')) ?></dt>
                    <dd class="col-7"><?php if ($finding['status'] !== 'open' || $finding['due_at'] === null): ?><span class="text-body-secondary"><?= e(__('Not due (only open findings are due)')) ?></span>
                        <?php else: ?><?= e(substr((string) $finding['due_at'], 0, 10)) ?> <span class="text-body-secondary"><?= e((int) $finding['due_custom'] === 1 ? __('(set by an admin)') : __('(policy)')) ?></span><?php endif; ?></dd>
                    <dt class="col-5"><?= e(__('Last recheck')) ?></dt>
                    <dd class="col-7"><?php if ($finding['verify_job_id'] === null): ?><span class="text-body-secondary"><?= e(__('Never')) ?></span>
                        <?php elseif (in_array($finding['verify_status'], ['queued', 'running'], true)): ?><span class="badge text-bg-info"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e($finding['verify_status'] === 'queued' ? __('Waiting') : __('Running')) ?></span>
                        <?php else: ?><?= e(match ($verifyResult) { 'fixed' => __('Fixed'), 'still_present' => __('Still present'), default => __('Could not finish') }) ?> <span class="text-body-secondary"><?= e(($finding['verify_finished_at'] ?? '') . ' UTC') ?></span><?php endif; ?></dd>
                </dl>
                <?php if ($canTriage && $editable): ?>
                <form method="post" action="<?= e(url('/findings/' . (int) $finding['id'] . '/assign')) ?>" class="mb-2">
                    <?= Csrf::field() ?>
                    <label class="form-label mb-1" for="assignee"><?= e(__('Assign to')) ?></label>
                    <div class="input-group input-group-sm">
                        <select class="form-select" id="assignee" name="assignee">
                            <option value=""><?= e(__('Nobody (unassigned)')) ?></option>
                            <?php foreach ($assignable as $u): ?><option value="<?= e($u['id']) ?>" <?= (int) ($finding['assigned_to'] ?? 0) === $u['id'] ? 'selected' : '' ?>><?= e($u['username']) ?></option><?php endforeach; ?>
                        </select>
                        <button type="submit" class="btn btn-outline-primary"><?= e(__('Assign')) ?></button>
                    </div>
                </form>
                <?php if ((int) ($finding['assigned_to'] ?? 0) !== (int) $currentUser['id']): ?>
                <form method="post" action="<?= e(url('/findings/' . (int) $finding['id'] . '/assign')) ?>" class="d-inline">
                    <?= Csrf::field() ?><input type="hidden" name="assignee" value="me">
                    <button type="submit" class="btn btn-sm btn-outline-secondary"><i class="bi bi-person-check me-1" aria-hidden="true"></i><?= e(__('Assign to me')) ?></button>
                </form>
                <?php endif; ?>
                <?php if ($verifiable): ?>
                <form method="post" action="<?= e(url('/findings/' . (int) $finding['id'] . '/verify')) ?>" class="d-inline">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-sm btn-primary"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Verify fix')) ?></button>
                </form>
                <div class="form-text"><?= e(__('Rechecks only this finding now (also outside the scan window), if it is still in scope. Once every 10 minutes.')) ?></div>
                <?php endif; ?>
                <?php if ($isAdmin && $finding['status'] === 'open'): ?>
                <details class="mt-2"<?= !empty($errors['due']) ? ' open' : '' ?>>
                    <summary><?= e(__('Change the due date (admins)')) ?></summary>
                    <form method="post" action="<?= e(url('/findings/' . (int) $finding['id'] . '/due')) ?>" class="mt-2">
                        <?= Csrf::field() ?>
                        <label class="form-label mb-1" for="due_date"><?= e(__('Due date (UTC)')) ?></label>
                        <input type="date" class="form-control form-control-sm mb-2" id="due_date" name="due_date" value="<?= e(substr((string) $finding['due_at'], 0, 10)) ?>">
                        <label class="form-label mb-1" for="due_note"><?= e(__('Reason (required)')) ?></label>
                        <input type="text" class="form-control form-control-sm mb-2" id="due_note" name="due_note" maxlength="500" required>
                        <button type="submit" class="btn btn-sm btn-outline-primary"><?= e(__('Set date')) ?></button>
                        <?php if ((int) $finding['due_custom'] === 1): ?><button type="submit" name="reset" value="1" class="btn btn-sm btn-outline-secondary"><?= e(__('Follow the policy again')) ?></button><?php endif; ?>
                    </form>
                </details>
                <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
        <div class="card">
            <div class="card-header"><h2 class="card-title h6 mb-0"><?= e(__('History')) ?></h2></div>
            <ul class="list-group list-group-flush small">
                <?php foreach ($events as $ev): ?>
                <li class="list-group-item">
                    <strong><?= e($eventLabels[$ev['event']] ?? $ev['event']) ?></strong>
                    <span class="text-body-secondary"><?= e($ev['created_at']) ?> UTC<?= $ev['username'] !== null ? ' · ' . e($ev['username']) : ' · ' . e(__('automatic')) ?></span>
                    <?php if ($ev['note'] !== null && $ev['note'] !== ''): ?><div class="text-pre-line"><?= e($ev['note']) ?></div><?php endif; ?>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
</div>
