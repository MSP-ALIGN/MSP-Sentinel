<?php
/**
 * A client's Compliance page: its frameworks from MSP Align, with Sentinel's evidence per control.
 * Expects: $client, $alignOn (bool), $compliance (AlignCompliance::forClient() or null when not linked),
 * $alignClients (list, error: choices for linking), $archived. Every value is escaped.
 * Read-only towards MSP Align: control statuses are decided there.
 */
use Sentinel\Core\Csrf;

$clientId = (int) $client['id'];
$linked = (int) ($client['align_client_id'] ?? 0) > 0;
$statusBadge = ['met' => ['success', __('Met')], 'partial' => ['warning', __('Partial')], 'not_met' => ['danger', __('Not met')],
                'na' => ['secondary', __('Not applicable')], 'not_assessed' => ['light border', __('Not assessed')]];
?>
<div class="card" id="compliance">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Compliance')) ?></h2>
        <?php if ($linked): ?>
        <span class="small text-body-secondary"><?= e(__('From MSP Align: {name}', ['name' => (string) $client['align_client_name']])) ?></span>
        <div class="ms-auto d-flex gap-2">
            <?php if (can('scans.run')): ?>
            <form method="post" action="<?= e(url('/clients/' . $clientId . '/compliance/refresh')) ?>"><?= Csrf::field() ?><button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-clockwise me-1" aria-hidden="true"></i><?= e(__('Read again')) ?></button></form>
            <?php endif; ?>
            <?php if (can('integrations.link')): ?>
            <form method="post" action="<?= e(url('/clients/' . $clientId . '/compliance/unlink')) ?>" data-confirm="<?= e(__('Unlink this client from MSP Align?')) ?>"><?= Csrf::field() ?><button type="submit" class="btn btn-outline-danger btn-sm"><?= e(__('Unlink')) ?></button></form>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>
    <div class="card-body">
    <?php if (!$alignOn && !$linked): ?>
        <p class="mb-0 text-body-secondary"><?= e(can('integrations.link')
            ? __('Connect MSP Align under Administration, Integrations to see this client\'s compliance frameworks here, with Sentinel\'s findings matched to their controls.')
            : __('Compliance frameworks appear here once an admin connects MSP Align.')) ?></p>
    <?php elseif (!$linked): ?>
        <p class="small"><?= e(__('Link this client to its MSP Align client to see its compliance frameworks here.')) ?></p>
        <?php if ($alignClients['error'] !== ''): ?>
        <div class="alert alert-danger py-2 small"><?= e($alignClients['error']) ?></div>
        <?php elseif (!can('integrations.link')): ?>
        <p class="small text-body-secondary mb-0"><?= e(__('An admin can link it.')) ?></p>
        <?php elseif ($archived || (int) ($client['is_demo'] ?? 0) === 1): ?>
        <p class="small text-body-secondary mb-0"><?= e(__('Archived and demo clients can\'t be linked.')) ?></p>
        <?php else: ?>
        <form method="post" action="<?= e(url('/clients/' . $clientId . '/compliance/link')) ?>" class="row g-2 align-items-end">
            <?= Csrf::field() ?>
            <div class="col-md-6">
                <label class="form-label" for="align-client"><?= e(__('MSP Align client')) ?></label>
                <select class="form-select" id="align-client" name="align_client_id" required>
                    <?php foreach ($alignClients['list'] as $i => $c): ?>
                    <option value="<?= (int) $c['id'] ?>"><?= e($c['name']) ?><?= $i === 0 && strcasecmp($c['name'], (string) $client['name']) === 0 ? ' — ' . e(__('same name')) : '' ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-3"><button type="submit" class="btn btn-primary"><?= e(__('Link')) ?></button></div>
        </form>
        <?php endif; ?>
    <?php else: ?>
        <?php $cp = $compliance; ?>
        <?php if ($cp['error'] !== ''): ?>
        <div class="alert alert-warning py-2 small"><?= e($cp['error']) ?><?= $cp['fetched_at'] !== '' ? ' ' . e(__('Showing what was read at {t} UTC.', ['t' => $cp['fetched_at']])) : '' ?></div>
        <?php endif; ?>
        <p class="small text-body-secondary"><?= e(__('Each framework\'s controls that Sentinel\'s checks relate to, matched by MSP Align\'s crosswalk tags. "Open problems" lists Sentinel findings in that area. "No problems found" means Sentinel checked that area and found nothing open: it supports the control but does not prove it is met. Control statuses are set in MSP Align.')) ?>
            <?= $cp['fetched_at'] !== '' ? e(__('Read from MSP Align at {t} UTC.', ['t' => $cp['fetched_at']])) : '' ?></p>
        <?php if ($cp['frameworks'] === [] && $cp['error'] === ''): ?>
        <p class="mb-0"><?= e(__('No frameworks are assigned to this client in MSP Align.')) ?></p>
        <?php endif; ?>
        <?php foreach ($cp['frameworks'] as $f): ?>
        <div class="border rounded p-2 mb-3">
            <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
                <h3 class="h6 mb-0"><?= e($f['framework']) ?></h3>
                <span class="badge text-bg-light border"><?= e(__('MSP Align score {p}%', ['p' => $f['score']])) ?></span>
                <?php if ($f['issues'] > 0): ?><span class="badge text-bg-danger"><?= e(__('{n} control(s) with open problems', ['n' => $f['issues']])) ?></span><?php endif; ?>
                <?php $alignBase = rtrim(\Sentinel\Core\App::settings()->get('mspalign_url'), '/') . '/'; // only links into the configured MSP Align ?>
                <?php if ($f['url'] !== '' && preg_match('#^https?://#', $f['url']) === 1 && str_starts_with($f['url'], $alignBase)): ?>
                <a class="small ms-auto" href="<?= e($f['url']) ?>" rel="noopener noreferrer" target="_blank"><?= e(__('Open in MSP Align')) ?> <i class="bi bi-box-arrow-up-right" aria-hidden="true"></i></a>
                <?php endif; ?>
            </div>
            <?php if ($f['controls'] === []): ?>
            <p class="small text-body-secondary mb-0"><?= e(__('None of this framework\'s controls are in areas Sentinel checks.')) ?></p>
            <?php else: ?>
            <div class="table-responsive"><table class="table table-sm align-middle mb-1">
                <thead><tr><th scope="col"><?= e(__('Control')) ?></th><th scope="col"><?= e(__('In MSP Align')) ?></th><th scope="col"><?= e(__('Sentinel')) ?></th></tr></thead>
                <tbody>
                <?php foreach ($f['controls'] as $c): ?>
                <?php [$bc, $bl] = $statusBadge[$c['status']] ?? $statusBadge['not_assessed']; ?>
                <tr>
                    <td><span class="font-monospace small"><?= e($c['ref']) ?></span> <?= e($c['title']) ?></td>
                    <td><span class="badge text-bg-<?= e($bc) ?>"><?= e($bl) ?></span></td>
                    <td class="small">
                        <?php if ($c['sentinel'] === 'issues'): ?>
                        <span class="badge text-bg-danger"><i class="bi bi-x-octagon me-1" aria-hidden="true"></i><?= e(__('{n} open problem(s)', ['n' => $c['finding_count']])) ?></span>
                        <ul class="mb-0 ps-3 mt-1">
                            <?php foreach ($c['findings'] as $fd): ?>
                            <li><a href="<?= e(url('/findings/' . $fd['id'])) ?>"><?= e($fd['title']) ?></a> <span class="text-body-secondary"><?= e($fd['target']) ?></span></li>
                            <?php endforeach; ?>
                            <?php if ($c['finding_count'] > count($c['findings'])): ?><li class="text-body-secondary"><?= e(__('and {n} more', ['n' => $c['finding_count'] - count($c['findings'])])) ?></li><?php endif; ?>
                        </ul>
                        <?php elseif ($c['sentinel'] === 'clear'): ?>
                        <span class="badge text-bg-success"><i class="bi bi-check-circle me-1" aria-hidden="true"></i><?= e(__('No problems found')) ?></span>
                        <span class="text-body-secondary"><?= e(__('Checked: {list}', ['list' => implode(', ', $c['areas'])])) ?></span>
                        <?php else: ?>
                        <span class="badge text-bg-light border"><?= e(__('Not checked yet')) ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table></div>
            <?php endif; ?>
            <?php if ($f['outside'] > 0): ?><p class="small text-body-secondary mb-0"><?= e(__('{n} other control(s) are about things Sentinel doesn\'t check (policies, training, backups, physical security...).', ['n' => $f['outside']])) ?></p><?php endif; ?>
        </div>
        <?php endforeach; ?>
    <?php endif; ?>
    </div>
</div>
