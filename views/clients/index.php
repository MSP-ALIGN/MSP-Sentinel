<?php
/** Client list. Expects: $clients (rows + site_count + auth_summary), $showArchived, $globallyPaused, $currentUser. */
use Sentinel\Auth\Role;

$isAdmin = Role::atLeast((string) $currentUser['role'], Role::ADMIN);
?>
<?php if ($globallyPaused): ?><?php require __DIR__ . '/../partials/kill_switch.php'; ?><?php endif; ?>
<div class="card">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e($showArchived ? __('All clients, including archived') : __('Clients')) ?></h2>
        <div class="ms-auto d-flex gap-2">
            <a class="btn btn-outline-secondary btn-sm" href="<?= e(url('/clients', $showArchived ? [] : ['archived' => '1'])) ?>"><?= e($showArchived ? __('Hide archived') : __('Show archived')) ?></a>
            <?php if ($isAdmin): ?>
            <a href="<?= e(url('/clients/new')) ?>" class="btn btn-primary btn-sm"><i class="bi bi-plus-lg me-1" aria-hidden="true"></i><?= e(__('Add client')) ?></a>
            <?php endif; ?>
        </div>
    </div>
    <div class="card-body p-0 table-responsive">
        <table class="table table-hover align-middle mb-0">
            <thead>
            <tr>
                <th scope="col"><?= e(__('Client')) ?></th>
                <th scope="col"><?= e(__('Scan authorisation')) ?></th>
                <th scope="col"><?= e(__('Scanning')) ?></th>
                <th scope="col"><?= e(__('Sites')) ?></th>
                <th scope="col"><?= e(__('ITFlow ID')) ?></th>
            </tr>
            </thead>
            <tbody>
            <?php if ($clients === []): ?>
            <tr><td colspan="5" class="text-center text-body-secondary py-4">
                <?= e(__('No clients yet.')) ?>
                <?php if ($isAdmin): ?><a href="<?= e(url('/clients/new')) ?>"><?= e(__('Add your first client.')) ?></a><?php endif; ?>
            </td></tr>
            <?php endif; ?>
            <?php foreach ($clients as $c): ?>
            <tr>
                <td>
                    <a href="<?= e(url('/clients/' . (int) $c['id'])) ?>"><?= e($c['name']) ?></a>
                    <?php if ((int) $c['is_archived'] === 1): ?><span class="badge text-bg-secondary ms-1"><?= e(__('Archived')) ?></span><?php endif; ?>
                </td>
                <td>
                    <?php $status = $c['auth_summary']['status']; require __DIR__ . '/../partials/auth_status.php'; ?>
                    <?php if ($c['auth_summary']['valid_until'] !== null && $status === 'active'): ?>
                    <span class="small text-body-secondary ms-1"><?= e(__('until {date}', ['date' => $c['auth_summary']['valid_until']])) ?></span>
                    <?php endif; ?>
                </td>
                <td>
                    <?php if ((int) $c['scanning_paused'] === 1): ?>
                    <span class="badge text-bg-danger"><i class="bi bi-pause-circle me-1" aria-hidden="true"></i><?= e(__('Paused')) ?></span>
                    <?php else: ?>
                    <span class="text-body-secondary small"><?= e(__('Window {from}–{to}', ['from' => substr((string) $c['scan_window_start'], 0, 5), 'to' => substr((string) $c['scan_window_end'], 0, 5)])) ?></span>
                    <?php endif; ?>
                </td>
                <td><?= e($c['site_count']) ?></td>
                <td><?= e($c['itflow_client_id'] ?? '—') ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
