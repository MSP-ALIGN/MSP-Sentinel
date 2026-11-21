<?php
/**
 * Client detail: details, scanning state, authorisations (with scope) and sites.
 * Expects: $client, $sites, $authorisations (each with 'status' and 'entries'), $today, $globallyPaused, $currentUser.
 * Every value is escaped. Actions are shown only to roles allowed to use them (the routes enforce it too).
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

$role = (string) $currentUser['role'];
$isAdmin = Role::atLeast($role, Role::ADMIN);
$isTech = Role::atLeast($role, Role::TECHNICIAN);
$clientId = (int) $client['id'];
$archived = (int) $client['is_archived'] === 1;
$paused = (int) $client['scanning_paused'] === 1;
$activeCount = count(array_filter($authorisations, static fn ($a) => $a['status'] === 'active'));
?>
<?php if ($globallyPaused): ?><?php require __DIR__ . '/../partials/kill_switch.php'; ?><?php endif; ?>
<?php if ($archived): ?>
<div class="alert alert-secondary"><i class="bi bi-archive me-1" aria-hidden="true"></i><?= e(__('This client is archived. It will not be scanned.')) ?></div>
<?php endif; ?>

<div class="row g-3">
    <div class="col-lg-4">
        <div class="card mb-3">
            <div class="card-header d-flex align-items-center">
                <h2 class="card-title h5 mb-0"><?= e(__('Details')) ?></h2>
                <?php if ($isAdmin): ?><a href="<?= e(url('/clients/' . $clientId . '/edit')) ?>" class="btn btn-outline-primary btn-sm ms-auto"><i class="bi bi-pencil me-1" aria-hidden="true"></i><?= e(__('Edit')) ?></a><?php endif; ?>
            </div>
            <div class="card-body">
                <dl class="row mb-0 small">
                    <dt class="col-5"><?= e(__('ITFlow ID')) ?></dt><dd class="col-7"><?= e($client['itflow_client_id'] ?? '—') ?></dd>
                    <dt class="col-5"><?= e(__('Timezone')) ?></dt><dd class="col-7"><?= e($client['timezone']) ?></dd>
                    <dt class="col-5"><?= e(__('Scan window')) ?></dt><dd class="col-7"><?= e(substr((string) $client['scan_window_start'], 0, 5) . '–' . substr((string) $client['scan_window_end'], 0, 5)) ?></dd>
                    <dt class="col-5"><?= e(__('Today there')) ?></dt><dd class="col-7"><?= e($today) ?></dd>
                </dl>
                <?php if (!empty($client['notes'])): ?><p class="small mt-2 mb-0 text-pre-line"><?= e($client['notes']) ?></p><?php endif; ?>
            </div>
            <?php if ($isAdmin): ?>
            <div class="card-footer">
                <form method="post" action="<?= e(url('/clients/' . $clientId . '/archive')) ?>" data-confirm="<?= e($archived ? __('Restore this client?') : __('Archive this client? It will no longer be scanned. History is kept.')) ?>">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="archive" value="<?= $archived ? '0' : '1' ?>">
                    <button type="submit" class="btn btn-sm btn-outline-secondary"><i class="bi bi-archive me-1" aria-hidden="true"></i><?= e($archived ? __('Restore client') : __('Archive client')) ?></button>
                </form>
            </div>
            <?php endif; ?>
        </div>

        <div class="card mb-3">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Scanning')) ?></h2></div>
            <div class="card-body">
                <?php if ($paused): ?>
                <p><span class="badge text-bg-danger"><i class="bi bi-pause-circle me-1" aria-hidden="true"></i><?= e(__('Paused for this client')) ?></span></p>
                <?php if ($isAdmin): ?>
                <form method="post" action="<?= e(url('/clients/' . $clientId . '/resume')) ?>" data-confirm="<?= e(__('Resume scanning for this client?')) ?>">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-sm btn-success"><i class="bi bi-play-fill me-1" aria-hidden="true"></i><?= e(__('Resume scanning')) ?></button>
                </form>
                <?php else: ?><p class="small text-body-secondary mb-0"><?= e(__('Only an admin can resume scanning.')) ?></p><?php endif; ?>
                <?php else: ?>
                <p class="small"><?php
                    if ($archived) {
                        echo e(__('Cannot be scanned: the client is archived.'));
                    } elseif ($globallyPaused) {
                        echo e(__('Cannot be scanned: all scanning is paused.'));
                    } elseif ($activeCount > 0) {
                        echo e(__('Can be scanned: {n} active authorisation(s).', ['n' => $activeCount]));
                    } else {
                        echo e(__('Cannot be scanned: there is no active authorisation.'));
                    } ?></p>
                <?php if ($isTech): ?>
                <form method="post" action="<?= e(url('/clients/' . $clientId . '/pause')) ?>" data-confirm="<?= e(__('Pause all scanning for this client now?')) ?>">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-pause-fill me-1" aria-hidden="true"></i><?= e(__('Pause scanning for this client')) ?></button>
                </form>
                <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Sites')) ?></h2></div>
            <ul class="list-group list-group-flush">
                <?php foreach ($sites as $site): ?>
                <li class="list-group-item">
                    <?php if ($isAdmin): ?>
                    <form method="post" action="<?= e(url('/sites/' . (int) $site['id'])) ?>" class="row g-2 align-items-center" novalidate>
                        <?= Csrf::field() ?>
                        <div class="col-7"><input type="text" class="form-control form-control-sm" name="name" value="<?= e($site['name']) ?>" maxlength="150" aria-label="<?= e(__('Site name')) ?>"></div>
                        <div class="col-3"><input type="text" class="form-control form-control-sm" name="itflow_location_id" value="<?= e($site['itflow_location_id'] ?? '') ?>" placeholder="<?= e(__('ITFlow')) ?>" inputmode="numeric" maxlength="10" aria-label="<?= e(__('ITFlow location ID')) ?>"></div>
                        <div class="col-2"><button type="submit" class="btn btn-sm btn-outline-primary w-100" aria-label="<?= e(__('Save site')) ?>"><i class="bi bi-check-lg" aria-hidden="true"></i></button></div>
                    </form>
                    <?php else: ?>
                    <?= e($site['name']) ?><?php if ($site['itflow_location_id'] !== null): ?> <span class="small text-body-secondary">(ITFlow <?= e($site['itflow_location_id']) ?>)</span><?php endif; ?>
                    <?php endif; ?>
                    <?php if ((int) $site['is_default'] === 1): ?><span class="badge text-bg-light border mt-1"><?= e(__('Default')) ?></span><?php endif; ?>
                </li>
                <?php endforeach; ?>
            </ul>
            <?php if ($isAdmin): ?>
            <div class="card-footer">
                <form method="post" action="<?= e(url('/clients/' . $clientId . '/sites')) ?>" class="row g-2" novalidate>
                    <?= Csrf::field() ?>
                    <div class="col-7"><input type="text" class="form-control form-control-sm" name="name" placeholder="<?= e(__('New site name')) ?>" maxlength="150" required aria-label="<?= e(__('New site name')) ?>"></div>
                    <div class="col-3"><input type="text" class="form-control form-control-sm" name="itflow_location_id" placeholder="<?= e(__('ITFlow')) ?>" inputmode="numeric" maxlength="10" aria-label="<?= e(__('ITFlow location ID')) ?>"></div>
                    <div class="col-2"><button type="submit" class="btn btn-sm btn-primary w-100" aria-label="<?= e(__('Add site')) ?>"><i class="bi bi-plus-lg" aria-hidden="true"></i></button></div>
                </form>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <div class="col-lg-8">
        <div class="card">
            <div class="card-header d-flex align-items-center flex-wrap gap-2">
                <h2 class="card-title h5 mb-0"><?= e(__('Authorised to scan')) ?></h2>
                <?php if ($isAdmin && !$archived): ?>
                <div class="ms-auto d-flex gap-2">
                    <?php if ($activeCount > 0): ?>
                    <a href="<?= e(url('/clients/' . $clientId . '/authorisations/new', ['replace' => '1'])) ?>" class="btn btn-outline-primary btn-sm"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Change scope / renew')) ?></a>
                    <?php endif; ?>
                    <a href="<?= e(url('/clients/' . $clientId . '/authorisations/new')) ?>" class="btn btn-primary btn-sm"><i class="bi bi-file-earmark-plus me-1" aria-hidden="true"></i><?= e(__('Record authorisation')) ?></a>
                </div>
                <?php endif; ?>
            </div>
            <div class="card-body">
                <?php if ($authorisations === []): ?>
                <p class="text-body-secondary mb-0"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i><?= e(__('No authorisation recorded. Sentinel will not scan anything for this client until an admin records who approved scanning and what may be scanned.')) ?></p>
                <?php endif; ?>
                <?php foreach ($authorisations as $a): ?>
                <div class="border rounded p-3 mb-3 authorisation" data-testid="authorisation-<?= e($a['id']) ?>">
                    <div class="d-flex align-items-center flex-wrap gap-2 mb-2">
                        <?php $status = $a['status']; require __DIR__ . '/../partials/auth_status.php'; ?>
                        <strong><?= e(__('{from} to {until}', ['from' => $a['valid_from'], 'until' => $a['valid_until']])) ?></strong>
                        <?php
                        $daysLeft = (int) ((strtotime((string) $a['valid_until']) - strtotime($today)) / 86400);
                        if ($a['status'] === 'active' && $daysLeft <= 30): ?>
                        <span class="badge text-bg-warning"><i class="bi bi-hourglass-split me-1" aria-hidden="true"></i><?= e(__('Ends in {n} days', ['n' => $daysLeft])) ?></span>
                        <?php endif; ?>
                        <span class="small text-body-secondary ms-auto">#<?= e($a['id']) ?></span>
                    </div>
                    <dl class="row small mb-2">
                        <dt class="col-sm-3"><?= e(__('Approved by')) ?></dt><dd class="col-sm-9"><?= e($a['approved_by_name']) ?>, <?= e($a['approved_by_role']) ?> (<?= e($a['approved_on']) ?>)</dd>
                        <?php if ($a['document_ref'] !== ''): ?><dt class="col-sm-3"><?= e(__('Reference')) ?></dt><dd class="col-sm-9"><?= e($a['document_ref']) ?></dd><?php endif; ?>
                        <dt class="col-sm-3"><?= e(__('Recorded')) ?></dt><dd class="col-sm-9"><?= e(__('{date} UTC by {user}', ['date' => $a['created_at'], 'user' => $a['recorded_by_username'] ?? '?'])) ?></dd>
                        <?php if ($a['revoked_at'] !== null): ?>
                        <dt class="col-sm-3"><?= e(__('Revoked')) ?></dt><dd class="col-sm-9"><?= e(__('{date} UTC by {user}: {reason}', ['date' => $a['revoked_at'], 'user' => $a['revoked_by_username'] ?? '?', 'reason' => $a['revoke_reason']])) ?></dd>
                        <?php endif; ?>
                        <?php if (!empty($a['notes'])): ?><dt class="col-sm-3"><?= e(__('Notes')) ?></dt><dd class="col-sm-9 text-pre-line"><?= e($a['notes']) ?></dd><?php endif; ?>
                    </dl>
                    <div class="small fw-semibold mb-1"><?= e(__('Scope ({n})', ['n' => count($a['entries'])])) ?></div>
                    <ul class="list-inline mb-2 scope-list">
                        <?php foreach ($a['entries'] as $entry): ?>
                        <li class="list-inline-item"><code><?= e($entry['value']) ?></code></li>
                        <?php endforeach; ?>
                    </ul>
                    <?php if ($isAdmin && $a['revoked_at'] === null): ?>
                    <details class="small">
                        <summary class="text-danger"><?= e(__('Revoke this authorisation')) ?></summary>
                        <form method="post" action="<?= e(url('/authorisations/' . (int) $a['id'] . '/revoke')) ?>" class="mt-2" data-confirm="<?= e(__('Revoke this authorisation? This cannot be undone.')) ?>" novalidate>
                            <?= Csrf::field() ?>
                            <label for="reason-<?= e($a['id']) ?>" class="form-label"><?= e(__('Reason')) ?></label>
                            <input type="text" class="form-control form-control-sm mb-2" id="reason-<?= e($a['id']) ?>" name="reason" maxlength="500" required>
                            <button type="submit" class="btn btn-sm btn-outline-danger"><?= e(__('Revoke')) ?></button>
                        </form>
                    </details>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php require __DIR__ . '/scans.php'; ?>
        <?php require __DIR__ . '/discovery.php'; ?>
    </div>
</div>
