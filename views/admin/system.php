<?php
/**
 * System page (admins): health checks, version/updates, data retention.
 * Expects: $checks, $demoLoaded (bool), $version, $build (null or branch/commit/development), $branchStatus (null or branch/behind/head),
 *          $webUpdate (available, pending, status, log), $newer, $updateEnabled, $checkedAt, $retention, $retentionLast, $sourceUrl.
 * Every value is escaped. Status is shown with an icon and a word, not colour alone.
 */
use Sentinel\Core\Csrf;

$badge = ['ok' => ['success', 'bi-check-circle', __('OK')], 'warn' => ['warning', 'bi-exclamation-triangle', __('Warning')], 'fail' => ['danger', 'bi-x-octagon', __('Problem')]];
$fails = count(array_filter($checks, static fn (array $c): bool => $c['status'] === 'fail'));
?>
<div class="row g-3">
<div class="col-xl-8">
<div class="card mb-3" id="health">
    <div class="card-header d-flex align-items-center"><h2 class="card-title h5 mb-0"><?= e(__('Health')) ?></h2>
        <span class="ms-auto small text-body-secondary"><?= e(__('Same checks from the command line: php bin/doctor.php')) ?></span></div>
    <?php if ($fails > 0): ?><div class="card-body pb-0"><div class="alert alert-danger mb-0"><?= e(__('{n} problem(s) need attention.', ['n' => $fails])) ?></div></div><?php endif; ?>
    <div class="card-body p-0 table-responsive">
        <table class="table align-middle mb-0 small">
            <tbody>
            <?php foreach ($checks as $c): [$cls, $icon, $word] = $badge[$c['status']]; ?>
            <tr><td class="text-nowrap"><span class="badge text-bg-<?= e($cls) ?>"><i class="bi <?= e($icon) ?> me-1" aria-hidden="true"></i><?= e($word) ?></span></td>
                <th scope="row" class="text-nowrap"><?= e($c['label']) ?></th><td><?= e($c['detail']) ?></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
</div>
<div class="col-xl-4">
<div class="card mb-3" id="updates">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Version and updates')) ?></h2></div>
    <div class="card-body small">
        <p class="mb-2"><?= e(__('Installed: {v}', ['v' => $version])) ?><?php if ($build !== null): ?> · <?= e(__('branch {b}, commit {c}', ['b' => $build['branch'], 'c' => $build['commit']])) ?><?php endif; ?></p>
        <?php if ($build !== null && $build['development']): ?>
        <div class="alert alert-warning py-2"><?= e(__('Development build: this server follows the {b} branch, so it gets changes before they are released. Use it to test, not for client work. Update now (below) or sudo msp-sentinel-update fetches the newest {b}.', ['b' => $build['branch']])) ?></div>
        <?php endif; ?>
        <?php if ($newer !== null): ?>
        <div class="alert alert-info py-2"><?= e(__('Version {v} is available.', ['v' => $newer])) ?> <a href="<?= e(rtrim($sourceUrl, '/') . '/releases') ?>" rel="noopener noreferrer" target="_blank"><?= e(__('Release notes')) ?></a></div>
        <?php endif; ?>
        <?php if ($branchStatus !== null): ?>
        <?php if ($branchStatus['behind'] > 0): ?>
        <div class="alert alert-info py-2"><i class="bi bi-arrow-up-circle me-1" aria-hidden="true"></i><?= e(__('Update available: the {b} branch has {n} new commit(s) since this install (newest {h}).', ['b' => $branchStatus['branch'], 'n' => $branchStatus['behind'], 'h' => $branchStatus['head'] !== '' ? $branchStatus['head'] : '?'])) ?></div>
        <?php else: ?>
        <p class="mb-2"><i class="bi bi-check-circle text-success me-1" aria-hidden="true"></i><?= e(__('Up to date with the {b} branch.', ['b' => $branchStatus['branch']])) ?></p>
        <?php endif; ?>
        <?php endif; ?>
        <?php $wu = $webUpdate; $st = $wu['status']; ?>
        <div class="border rounded p-2 mb-3" id="update-now">
            <h3 class="h6"><?= e(__('Update now')) ?></h3>
            <?php if (!$wu['available']): ?>
            <p class="mb-0 text-body-secondary"><?= e($build !== null
                ? __('Updating from the web interface is turned off on this server. Run sudo msp-sentinel-update on the server.')
                : __('This server was installed from a release download, so it is updated on the server: see docs/upgrade.md.')) ?></p>
            <?php else: ?>
            <?php if ($wu['pending'] && $wu['unclaimed']): ?>
            <div class="alert alert-warning py-2 mb-2"><?= e(__('The update request was not picked up: the update helper on the server is stopped. On the server, run: sudo systemctl reset-failed msp-sentinel-web-update.path && sudo systemctl restart msp-sentinel-web-update.path (or run sudo msp-sentinel-update).')) ?>
                <form method="post" action="<?= e(url('/admin/system/update')) ?>" class="mt-2"><?= Csrf::field() ?><input type="hidden" name="action" value="cancel"><button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Remove the waiting request')) ?></button></form></div>
            <?php elseif ($wu['pending']): ?>
            <p class="mb-2"><span class="badge text-bg-info"><?= e(__('Waiting')) ?></span> <?= e(__('The update was requested and starts within a few seconds.')) ?></p>
            <?php elseif ($st['state'] === 'running' && !$st['stale']): ?>
            <p class="mb-2"><span class="badge text-bg-warning"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Running')) ?></span> <?= e(__('Started {t} UTC. Sentinel may be unavailable for a minute while it restarts; refresh this page to follow it.', ['t' => $st['started']])) ?></p>
            <?php elseif ($st['state'] === 'done'): ?>
            <p class="mb-2"><span class="badge text-bg-success"><i class="bi bi-check-circle me-1" aria-hidden="true"></i><?= e(__('Done')) ?></span> <?= e(__('Last update finished {t} UTC.', ['t' => $st['finished']])) ?></p>
            <?php elseif ($st['state'] === 'failed' || $st['stale']): ?>
            <p class="mb-2"><span class="badge text-bg-danger"><i class="bi bi-x-octagon me-1" aria-hidden="true"></i><?= e(__('Failed')) ?></span> <?= e($st['stale'] ? __('The last update started {t} UTC and never finished (the server may have restarted).', ['t' => $st['started']]) : __('The last update stopped with an error at {t} UTC (exit code {c}). Sentinel kept running the previous version; see the output below.', ['t' => $st['finished'], 'c' => $st['exit']])) ?></p>
            <?php endif; ?>
            <?php if ($wu['log'] !== ''): ?>
            <details class="mb-2"<?= $st['state'] === 'failed' || ($st['state'] === 'running' && !$st['stale']) ? ' open' : '' ?>><summary><?= e(__('Output of the last update')) ?></summary><pre class="small mb-0 mt-1 update-log"><?= e($wu['log']) ?></pre></details>
            <?php endif; ?>
            <?php if (!$wu['pending'] && !($st['state'] === 'running' && !$st['stale']) && $wu['wait'] > 0): ?>
            <p class="text-body-secondary mb-0"><?= e(__('One update every 15 minutes: you can start the next one in {m} minute(s).', ['m' => (int) ceil($wu['wait'] / 60)])) ?></p>
            <?php elseif (!$wu['pending'] && !($st['state'] === 'running' && !$st['stale'])): ?>
            <p class="text-body-secondary mb-2"><?= e($build !== null
                ? __('Fetches the newest {b} branch, backs up first, applies database changes and checks health. Same as sudo msp-sentinel-update on the server.', ['b' => $build['branch']])
                : __('Backs up first, applies database changes and checks health.')) ?></p>
            <form method="post" action="<?= e(url('/admin/system/update')) ?>" data-confirm="<?= e(__('Update Sentinel now? It backs up first and may be unavailable for a minute.')) ?>">
                <?= Csrf::field() ?>
                <button type="submit" class="btn btn-primary btn-sm"><i class="bi bi-cloud-arrow-down me-1" aria-hidden="true"></i><?= e(__('Update now')) ?></button>
            </form>
            <?php endif; ?>
            <?php endif; ?>
        </div>
        <p class="text-body-secondary"><?= e($updateEnabled ? __('Once a day the worker asks GitHub for the latest release (and, for installs that follow a branch, how many commits the branch has moved on). Nothing else is sent. Last check: {t}', ['t' => $checkedAt !== '' ? $checkedAt . ' UTC' : __('not yet')]) : __('The update check is off.')) ?></p>
        <form method="post" action="<?= e(url('/admin/system/updates')) ?>" class="mb-2">
            <?= Csrf::field() ?>
            <div class="form-check"><input class="form-check-input" type="checkbox" id="update_check_enabled" name="update_check_enabled" value="1" <?= $updateEnabled ? 'checked' : '' ?>>
                <label class="form-check-label" for="update_check_enabled"><?= e(__('Check for updates daily')) ?></label></div>
            <button type="submit" class="btn btn-outline-primary btn-sm mt-1"><?= e(__('Save')) ?></button>
        </form>
        <?php if ($updateEnabled): ?>
        <form method="post" action="<?= e(url('/admin/system/updates')) ?>"><?= Csrf::field() ?><input type="hidden" name="action" value="check"><button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Check now')) ?></button></form>
        <?php endif; ?>
    </div>
</div>
<div class="card mb-3" id="agents">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('On-premises agent updates')) ?></h2></div>
    <div class="card-body small">
        <?php $rel = $agentRelease->version(); ?>
        <?php if ($rel !== null): ?>
            <p><?= e(__('This Sentinel can hand agents version {v}, signed with your release key. Agents install it only when the signature checks with the key they pinned at install.', ['v' => $rel])) ?></p>
        <?php else: ?>
            <p class="text-body-secondary"><?= e(__('No signed agent release to hand out: {why}. Agents can still be upgraded by hand.', ['why' => $agentRelease->why()])) ?></p>
        <?php endif; ?>
        <p class="mb-2"><?= e(__('Agents by version:')) ?>
            <?php foreach ($agentVersions as $v): ?><span class="badge text-bg-light border font-monospace me-1"><?= e(($v['version'] ?: '?') . ' × ' . (int) $v['n']) ?></span><?php endforeach; ?>
            <?php if ($agentVersions === []): ?><span class="text-body-secondary"><?= e(__('none yet')) ?></span><?php endif; ?></p>
        <?php if ($rel !== null): ?>
        <form method="post" action="<?= e(url('/admin/system/agents-update')) ?>" data-confirm="<?= e(__('Update every agent that runs an older version to {v}, at each one\'s next check-in between scans?', ['v' => $rel])) ?>"><?= \Sentinel\Core\Csrf::field() ?>
            <button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-cloud-arrow-down me-1" aria-hidden="true"></i><?= e(__('Update all agents to {v}', ['v' => $rel])) ?></button></form>
        <?php endif; ?>
    </div>
</div>

<div class="card mb-3" id="demo">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Demo data')) ?></h2></div>
    <div class="card-body small">
        <p><?= e(__('Made-up clients with findings, devices, scan history and reports, for trying Sentinel out or training. They use *.example names and documentation addresses, are marked Demo, and are never scanned. Removing them deletes only demo clients and what belongs to them.')) ?></p>
        <?php if ($demoLoaded): ?>
        <form method="post" action="<?= e(url('/admin/system/demo')) ?>" data-confirm="<?= e(__('Remove all demo clients and everything that belongs to them?')) ?>"><?= Csrf::field() ?><input type="hidden" name="action" value="remove">
            <button type="submit" class="btn btn-outline-danger btn-sm"><i class="bi bi-trash me-1" aria-hidden="true"></i><?= e(__('Remove demo data')) ?></button>
        </form>
        <?php else: ?>
        <form method="post" action="<?= e(url('/admin/system/demo')) ?>" data-confirm="<?= e(__('Load four demo clients? Demo findings are assigned to you.')) ?>"><?= Csrf::field() ?><input type="hidden" name="action" value="load">
            <button type="submit" class="btn btn-outline-primary btn-sm"><i class="bi bi-easel me-1" aria-hidden="true"></i><?= e(__('Load demo data')) ?></button>
        </form>
        <?php endif; ?>
    </div>
</div>
<div class="card mb-3" id="retention">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Data retention')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/system/retention')) ?>" novalidate>
        <?= Csrf::field() ?>
        <div class="card-body small">
            <p class="text-body-secondary"><?= e(__('Months to keep (0 = keep forever). The worker removes older data once a day. The audit log is always kept.')) ?></p>
            <?php foreach (['scans' => __('Scan history (finished scans and their log)'), 'findings' => __('Resolved findings and their history'), 'reports' => __('Reports')] as $k => $label): ?>
            <div class="row g-2 align-items-center mb-2">
                <label class="col-8 col-form-label" for="retention_<?= e($k) ?>"><?= e($label) ?></label>
                <div class="col-4"><input class="form-control form-control-sm" type="number" min="0" max="120" step="1" id="retention_<?= e($k) ?>" name="retention_<?= e($k) ?>" value="<?= e($retention[$k]) ?>"></div>
            </div>
            <?php endforeach; ?>
            <p class="text-body-secondary mb-0"><?= e(__('Last run: {t}', ['t' => $retentionLast !== '' ? $retentionLast . ' UTC' : __('not yet')])) ?></p>
        </div>
        <div class="card-footer"><button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save retention')) ?></button></div>
    </form>
</div>
</div>
</div>
