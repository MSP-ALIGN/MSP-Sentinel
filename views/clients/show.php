<?php
/**
 * A client's pages: the section in $section (ClientController::SECTIONS), with the client's menu in the sidebar
 * ($clientNav, drawn by the layout). Shared notices first, then only that section.
 * Expects: $client, $section, $today, $globallyPaused, $currentUser, $findingCounts, and the section's own data
 * (ClientController::show loads it): e.g. $sites/$authorisations/$overview for the overview.
 * Every value is escaped. Actions are shown only to roles allowed to use them (the routes enforce it too).
 */
use Sentinel\Core\Csrf;

$clientId = (int) $client['id'];
$archived = (int) $client['is_archived'] === 1;
$paused = (int) $client['scanning_paused'] === 1;
$activeCount = count(array_filter($authorisations, static fn ($a) => $a['status'] === 'active'));
?>
<?php if ($globallyPaused): ?><?php require __DIR__ . '/../partials/kill_switch.php'; ?><?php endif; ?>
<?php if ((int) ($client['is_demo'] ?? 0) === 1): ?>
<div class="alert alert-info"><i class="bi bi-easel me-1" aria-hidden="true"></i><?= e(__('Demo client: made-up data for trying Sentinel out. It is never scanned.')) ?><?php if (can('system.manage')): ?> <?= e(__('Remove all demo data under Administration → System.')) ?><?php endif; ?></div>
<?php endif; ?>
<?php if ($archived): ?>
<div class="alert alert-secondary"><i class="bi bi-archive me-1" aria-hidden="true"></i><?= e(__('This client is archived. It will not be scanned.')) ?></div>
<?php endif; ?>

<?php if ($section === 'overview'): ?>
<?php if (!$archived): ?>
<div class="dash-actions"><button type="button" class="btn btn-sm btn-outline-secondary refresh-toggle" data-refresh-toggle aria-pressed="false" data-label-pause="<?= e(__('Pause live refresh')) ?>" data-label-resume="<?= e(__('Resume live refresh')) ?>" title="<?= e(__('Stops this page refreshing itself every minute. Scans are not affected.')) ?>"><?= e(__('Pause live refresh')) ?></button></div>
<div id="live-client" data-refresh-url="<?= e(url('/clients/' . $clientId . '/overview')) ?>" aria-live="off">
    <?php $ov = $overview; require __DIR__ . '/overview.php'; ?>
</div>
<?php endif; ?>
<div class="row g-3">
    <div class="col-xl-4 col-lg-6">
        <div class="card mb-3">
            <div class="card-header d-flex align-items-center">
                <h2 class="card-title h5 mb-0"><?= e(__('Details')) ?></h2>
                <?php if (can('clients.manage')): ?><a href="<?= e(url('/clients/' . $clientId . '/edit')) ?>" class="btn btn-outline-primary btn-sm ms-auto"><i class="bi bi-pencil me-1" aria-hidden="true"></i><?= e(__('Edit')) ?></a><?php endif; ?>
            </div>
            <div class="card-body">
                <dl class="row mb-0 small">
                    <dt class="col-5"><?= e(__('ITFlow ID')) ?></dt><dd class="col-7"><?= e($client['itflow_client_id'] ?? '—') ?><?php if ((int) ($client['itflow_sync_off'] ?? 0) === 1): ?> <span class="badge text-bg-secondary"><?= e(__('Not synced')) ?></span><?php endif; ?></dd>
                    <dt class="col-5"><?= e(__('Time zone')) ?></dt><dd class="col-7"><?= e($client['timezone']) ?></dd>
                    <dt class="col-5"><?= e(__('Scan window')) ?></dt><dd class="col-7"><?= e(substr((string) $client['scan_window_start'], 0, 5) . '–' . substr((string) $client['scan_window_end'], 0, 5)) ?></dd>
                    <dt class="col-5"><?= e(__('Today there')) ?></dt><dd class="col-7"><?= e($today) ?></dd>
                </dl>
                <?php if (!empty($client['notes'])): ?><p class="small mt-2 mb-0 text-pre-line"><?= e($client['notes']) ?></p><?php endif; ?>
            </div>
            <?php if (can('clients.manage')): ?>
            <div class="card-footer">
                <form method="post" action="<?= e(url('/clients/' . $clientId . '/archive')) ?>" data-confirm="<?= e($archived ? __('Restore this client?') : __('Archive this client? It will no longer be scanned. History is kept.')) ?>">
                    <?= Csrf::field() ?>
                    <input type="hidden" name="archive" value="<?= $archived ? '0' : '1' ?>">
                    <button type="submit" class="btn btn-sm btn-outline-secondary"><i class="bi bi-archive me-1" aria-hidden="true"></i><?= e($archived ? __('Restore client') : __('Archive client')) ?></button>
                </form>
            </div>
            <?php endif; ?>
        </div>

    </div>
    <div class="col-xl-4 col-lg-6">
        <div class="card mb-3">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Scanning')) ?></h2></div>
            <div class="card-body">
                <?php if ($paused): ?>
                <p><span class="badge text-bg-danger"><i class="bi bi-pause-circle me-1" aria-hidden="true"></i><?= e(__('Paused for this client')) ?></span></p>
                <?php if (can('scanning.resume')): ?>
                <form method="post" action="<?= e(url('/clients/' . $clientId . '/resume')) ?>" data-confirm="<?= e(__('Resume scanning for this client?')) ?>">
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-sm btn-success"><i class="bi bi-play-fill me-1" aria-hidden="true"></i><?= e(__('Resume scanning')) ?></button>
                </form>
                <?php else: ?><p class="small text-body-secondary mb-0"><?= e(__('Your role can\'t resume scanning.')) ?></p><?php endif; ?>
                <?php else: ?>
                <p class="small"><?php
                    if ($archived) {
                        echo e(__('Cannot be scanned: the client is archived.'));
                    } elseif ($globallyPaused) {
                        echo e(__('Cannot be scanned: all scanning is paused.'));
                    } elseif ($activeCount > 0) {
                        echo e(__('Can be scanned: {n} active authorization(s).', ['n' => $activeCount]));
                    } else {
                        echo e(__('Cannot be scanned: there is no active authorization.'));
                    } ?></p>
                <?php if ($activeCount === 0 && !$archived && can('authorisations.manage')): ?>
                <p><a href="<?= e(url('/clients/' . $clientId . '/authorisations/new')) ?>" class="btn btn-primary btn-sm"><i class="bi bi-file-earmark-plus me-1" aria-hidden="true"></i><?= e(__('Record authorization')) ?></a></p>
                <?php elseif ($activeCount === 0 && !$archived): ?>
                <p class="small text-body-secondary"><?= e(__('Someone whose role can manage authorizations records the client\'s authorization first.')) ?></p>
                <?php endif; ?>
                <?php // 1.51: Scan now on the overview too (as the help says); the window override stays on Scans and ports. ?>
                <?php if ($activeCount > 0 && !$archived && !$globallyPaused && can('scans.run')): ?>
                <form method="post" class="mb-2 d-flex flex-wrap gap-2 align-items-center" action="<?= e(url('/clients/' . $clientId . '/scan')) ?>" data-confirm="<?= e(__('Start a scan of this client now? Only addresses and names in its active authorization are scanned.')) ?>" novalidate>
                    <?= Csrf::field() ?>
                    <button type="submit" class="btn btn-primary btn-sm"><i class="bi bi-broadcast me-1" aria-hidden="true"></i><?= e(__('Scan now')) ?></button>
                    <a class="small" href="<?= e(url('/clients/' . $clientId . '/scans')) ?>"><?= e(__('Scans and ports')) ?></a>
                </form>
                <?php endif; ?>
                <?php if (can('scanning.pause')): ?>
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
                    <?php if (can('clients.manage')): ?>
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
            <?php if (can('clients.manage')): ?>
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
</div>
<?php elseif ($section === 'authorisations'): ?>
        <div class="card">
            <div class="card-header d-flex align-items-center flex-wrap gap-2">
                <h2 class="card-title h5 mb-0"><?= e(__('Authorized to scan')) ?></h2>
                <?php if (can('authorisations.manage') && !$archived): ?>
                <div class="ms-auto d-flex gap-2">
                    <?php if ($activeCount > 0): ?>
                    <a href="<?= e(url('/clients/' . $clientId . '/authorisations/new', ['replace' => '1'])) ?>" class="btn btn-outline-primary btn-sm"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Change scope / renew')) ?></a>
                    <?php endif; ?>
                    <a href="<?= e(url('/clients/' . $clientId . '/authorisations/new')) ?>" class="btn btn-primary btn-sm"><i class="bi bi-file-earmark-plus me-1" aria-hidden="true"></i><?= e(__('Record authorization')) ?></a>
                </div>
                <?php endif; ?>
            </div>
            <div class="card-body">
                <?php if ($authorisations === []): ?>
                <p class="text-body-secondary mb-0"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i><?= e(__('No authorization recorded. Sentinel will not scan anything for this client until someone records who approved scanning and what may be scanned.')) ?></p>
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
                        <dt class="col-sm-3"><?= e(__('Recorded')) ?></dt><dd class="col-sm-9"><?= e(__('{date} by {user}', ['date' => when($a['created_at']), 'user' => $a['recorded_by_username'] ?? '?'])) ?></dd>
                        <?php if ($a['revoked_at'] !== null): ?>
                        <dt class="col-sm-3"><?= e(__('Revoked')) ?></dt><dd class="col-sm-9"><?= e(__('{date} by {user}: {reason}', ['date' => when($a['revoked_at']), 'user' => $a['revoked_by_username'] ?? '?', 'reason' => $a['revoke_reason']])) ?></dd>
                        <?php endif; ?>
                        <?php if (!empty($a['notes'])): ?><dt class="col-sm-3"><?= e(__('Notes')) ?></dt><dd class="col-sm-9 text-pre-line"><?= e($a['notes']) ?></dd><?php endif; ?>
                    </dl>
                    <div class="small fw-semibold mb-1"><?= e(__('Scope ({n})', ['n' => count($a['entries'])])) ?></div>
                    <ul class="list-inline mb-2 scope-list">
                        <?php foreach ($a['entries'] as $entry): ?>
                        <li class="list-inline-item"><code><?= e($entry['value']) ?></code></li>
                        <?php endforeach; ?>
                    </ul>
                    <?php if (can('authorisations.manage') && $a['revoked_at'] === null): ?>
                    <details class="small">
                        <summary class="text-danger"><?= e(__('Revoke this authorization')) ?></summary>
                        <form method="post" action="<?= e(url('/authorisations/' . (int) $a['id'] . '/revoke')) ?>" class="mt-2" data-confirm="<?= e(__('Revoke this authorization? This cannot be undone.')) ?>" novalidate>
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
        <?php // 1.51: internal authorizations (per site, for the agents) are listed here too; they are recorded and revoked on Agents. ?>
        <div class="card mt-3">
            <div class="card-header d-flex align-items-center flex-wrap gap-2">
                <h2 class="card-title h5 mb-0"><?= e(__('Internal networks (agents)')) ?></h2>
                <a href="<?= e(url('/clients/' . $clientId . '/agents')) ?>" class="btn btn-outline-primary btn-sm ms-auto"><i class="bi bi-router me-1" aria-hidden="true"></i><?= e(__('Manage on Agents')) ?></a>
            </div>
            <ul class="list-group list-group-flush">
                <?php foreach ($agentSites ?? [] as $s): ?>
                <li class="list-group-item small">
                    <strong><?= e($s['site']['name']) ?></strong>:
                    <?php if ($s['active'] === null): ?>
                    <span class="text-body-secondary"><?= e(__('no active internal authorization, so nothing at this site is scanned from inside.')) ?></span>
                    <?php else: ?>
                    <span class="font-monospace"><?= e(implode(', ', $s['active']['ranges_list'])) ?></span>
                    <span class="text-body-secondary">· <?= e(__('approved by {name}, valid until {date}', ['name' => $s['active']['approved_by_name'], 'date' => $s['active']['valid_until']])) ?></span>
                    <?php endif; ?>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
<?php else: ?>
<?php require __DIR__ . '/' . ['findings' => 'findings', 'scans' => 'scans', 'vulnerabilities' => 'vulns', 'certificates' => 'exposure', 'website' => 'website',
    'agents' => 'agents', 'devices' => 'devices', 'engagements' => 'engagements', 'discovery' => 'discovery', 'reports' => 'reports', 'compliance' => 'compliance'][$section] . '.php'; ?>
<?php endif; ?>
