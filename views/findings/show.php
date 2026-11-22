<?php
/**
 * One finding: details, history and the triage form (technicians and admins).
 * Expects: $finding, $events, $errors, optional $values, $currentUser.
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

require __DIR__ . '/../partials/finding_badges.php';
$canTriage = Role::atLeast((string) $currentUser['role'], Role::TECHNICIAN);
$values = $values ?? ['status' => '', 'note' => ''];
$eventLabels = [
    'opened' => __('First seen'), 'resolved' => __('Resolved automatically'), 'reopened' => __('Seen again (reopened)'),
    'evidence_changed' => __('Reopened: evidence changed'), 'severity_changed' => __('Grade changed'),
    'triaged_accepted' => __('Marked as accepted risk'), 'triaged_false_positive' => __('Marked as false positive'), 'triaged_open' => __('Reopened by a user'),
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
                <p class="mb-2"><code><?= e($finding['target']) ?></code></p>
                <p class="text-pre-line"><?= e($finding['detail']) ?></p>
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
