<?php
/**
 * Internal devices card on the client page (inventory sources such as NinjaOne).
 * Expects: $client, $inventorySources (name => label), $inventoryLinks (name => link row|null),
 * $devices (InventoryRepository::devicesForClient), $devicePatches (by device ID), $currentUser.
 * Device data comes from the source (untrusted) and is always escaped.
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;
use Sentinel\Inventory\DeviceRules;

$isAdmin = Role::atLeast((string) $currentUser['role'], Role::ADMIN);
$isTech = Role::atLeast((string) $currentUser['role'], Role::TECHNICIAN);
$chip = static function (string $sev, string $text): string {
    [$cls, $icon] = match ($sev) { 'fail' => ['danger', 'bi-x-octagon'], 'warn' => ['warning', 'bi-exclamation-triangle'], 'ok' => ['success', 'bi-check-circle'], default => ['secondary', 'bi-info-circle'] };
    return '<span class="badge text-bg-' . $cls . ' me-1 mb-1 text-wrap text-start"><i class="bi ' . $icon . ' me-1" aria-hidden="true"></i>' . e($text) . '</span>';
};
?>
<div class="card mb-3" id="devices">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Internal devices')) ?></h2></div>
    <div class="card-body">
        <?php if ($inventorySources === []): ?>
        <p class="small text-body-secondary mb-0"><?= e(__('No inventory source is set up yet. When NinjaOne is connected (Administration > Settings), an admin links this client to its NinjaOne organisation and its devices, installed software and missing updates appear here.')) ?></p>
        <?php endif; ?>
        <?php foreach ($inventorySources as $name => $label): $link = $inventoryLinks[$name] ?? null; ?>
        <div class="d-flex flex-wrap align-items-center gap-2 mb-2 small">
            <strong><?= e($label) ?>:</strong>
            <?php if ($link === null): ?>
                <span class="text-body-secondary"><?= e(__('not linked')) ?></span>
                <?php if ($isAdmin): ?><a class="btn btn-sm btn-outline-primary" href="<?= e(url('/clients/' . (int) $client['id'] . '/inventory/link', ['source' => $name])) ?>"><?= e(__('Link to an organisation')) ?></a><?php endif; ?>
            <?php else: ?>
                <span><?= e(__('linked to {org}', ['org' => $link['org_name']])) ?></span>
                <span class="text-body-secondary">· <?= e($link['last_sync_at'] !== null ? __('last sync {t} UTC', ['t' => $link['last_sync_at']]) : __('first sync pending')) ?></span>
                <?php if ($link['last_sync_status'] === 'error'): ?><span class="badge text-bg-danger"><i class="bi bi-x-octagon me-1" aria-hidden="true"></i><?= e(__('Sync failed')) ?></span>
                <?php elseif ($link['last_sync_status'] === 'partial'): ?><span class="badge text-bg-warning"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i><?= e(__('Partial data')) ?></span><?php endif; ?>
                <?php if ($isTech): ?>
                <form method="post" action="<?= e(url('/clients/' . (int) $client['id'] . '/inventory/sync')) ?>" class="d-inline"><?= Csrf::field() ?><input type="hidden" name="source" value="<?= e($name) ?>"><button type="submit" class="btn btn-sm btn-outline-primary"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Sync now')) ?></button></form>
                <?php endif; ?>
                <?php if ($isAdmin): ?>
                <form method="post" action="<?= e(url('/clients/' . (int) $client['id'] . '/inventory/unlink')) ?>" class="d-inline" data-confirm="<?= e(__('Unlink? Its devices disappear from Sentinel and their findings are resolved.')) ?>"><?= Csrf::field() ?><input type="hidden" name="source" value="<?= e($name) ?>"><button type="submit" class="btn btn-sm btn-outline-secondary"><?= e(__('Unlink')) ?></button></form>
                <?php endif; ?>
                <?php if ($link['last_sync_message'] !== ''): ?><div class="w-100 text-body-secondary"><?= e($link['last_sync_message']) ?></div><?php endif; ?>
            <?php endif; ?>
        </div>
        <?php endforeach; ?>
        <?php if ($devices !== []): ?>
        <div class="table-responsive">
        <table class="table table-sm align-middle small mb-0">
            <thead><tr><th><?= e(__('Device')) ?></th><th><?= e(__('Operating system')) ?></th><th><?= e(__('Problems')) ?></th><th class="text-end"><?= e(__('Vulnerabilities')) ?></th><th class="text-nowrap"><?= e(__('Last contact (UTC)')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($devices as $d): $issues = DeviceRules::issues($d, $devicePatches[(int) $d['id']] ?? []); ?>
            <tr>
                <td><a href="<?= e(url('/clients/' . (int) $client['id'] . '/devices/' . (int) $d['id'])) ?>"><?= e($d['name'] !== '' ? $d['name'] : $d['source_id']) ?></a>
                    <div class="text-body-secondary"><?= e(match ($d['device_class']) { 'server' => __('Server'), 'workstation' => __('Workstation'), default => __('Other') }) ?></div></td>
                <td><?= e($d['os_name'] ?: '?') ?><?php if ($d['os_build'] !== ''): ?> <span class="text-body-secondary font-monospace"><?= e($d['os_build']) ?></span><?php endif; ?></td>
                <td><?php if ($issues === []): ?><?= $chip('ok', __('No problems found')) ?><?php endif; ?>
                    <?php foreach ($issues as $i): ?><?= $chip($i['severity'], $i['text']) ?><?php endforeach; ?></td>
                <td class="text-end"><?= (int) $d['vuln_count'] > 0 ? '<span class="badge text-bg-danger">' . e($d['vuln_count']) . '</span>' : '<span class="text-body-secondary">0</span>' ?></td>
                <td class="text-nowrap"><?= e((string) ($d['last_contact'] ?? '?')) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php elseif ($inventorySources !== []): ?>
        <p class="small text-body-secondary mb-0"><?= e(__('No devices yet.')) ?></p>
        <?php endif; ?>
    </div>
</div>
