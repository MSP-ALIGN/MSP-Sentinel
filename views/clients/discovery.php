<?php
/**
 * Discovery panel on the client's pages: last run, pending and dismissed suggestions.
 * Expects: $client, $suggestions, $dismissed, $lastRun (or null), $isAdmin, $isTech, $archived.
 * All values escaped. Dismiss and restore forms sit outside the selection form
 * (HTML forms can't nest) and are linked with the form="" attribute.
 */
use Sentinel\Core\Csrf;

$clientId = (int) $client['id'];
$sourceLabels = [
    'dns' => __('DNS'), 'dns-mx' => __('Mail (MX)'), 'dns-ns' => __('Name server'), 'dns-common' => __('Common name'),
    'crtsh' => __('Certificate logs'), 'ptr' => __('Reverse DNS'),
];
$runBadges = [
    'ok' => ['text-bg-success', 'bi-check-circle', __('Completed')],
    'partial' => ['text-bg-warning', 'bi-exclamation-circle', __('Partly completed')],
    'failed' => ['text-bg-danger', 'bi-x-octagon', __('Failed')],
    'running' => ['text-bg-info', 'bi-hourglass-split', __('Running')],
];
?>
<div class="card mt-3" id="discovery">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Discovered targets')) ?></h2>
        <?php if ($isTech && !$archived): ?>
        <form method="post" action="<?= e(url('/clients/' . $clientId . '/discover')) ?>" class="ms-auto">
            <?= Csrf::field() ?>
            <button type="submit" class="btn btn-outline-primary btn-sm"><i class="bi bi-search me-1" aria-hidden="true"></i><?= e(__('Discover now')) ?></button>
        </form>
        <?php endif; ?>
    </div>
    <div class="card-body">
        <p class="small text-body-secondary"><?= e(__('Sentinel looks up DNS records, public certificate logs and reverse DNS for this client\'s domains and addresses. This is passive: nothing connects to the client\'s systems. Found names are only suggestions. Nothing is scanned until an admin adds them to an authorisation.')) ?></p>

        <?php if ($lastRun !== null): ?>
        <?php [$rc, $ri, $rl] = $runBadges[$lastRun['status']] ?? $runBadges['failed']; $sum = $lastRun['summary']; ?>
        <div class="border rounded p-2 mb-3 small" data-testid="last-run">
            <span class="badge <?= e($rc) ?>"><i class="bi <?= e($ri) ?> me-1" aria-hidden="true"></i><?= e($rl) ?></span>
            <?= e(__('Last run {date} UTC ({trigger}): {new} new, {seen} already suggested, {inscope} already in scope, {q} lookups in {s} s.', [
                'date' => $lastRun['started_at'], 'trigger' => $lastRun['trigger_type'] === 'manual' ? __('manual') : __('weekly'),
                'new' => $sum['new'] ?? 0, 'seen' => $sum['seen_again'] ?? 0, 'inscope' => $sum['already_in_scope'] ?? 0,
                'q' => $sum['queries'] ?? 0, 's' => $sum['seconds'] ?? 0,
            ])) ?>
            <?php if (!empty($sum['certificate_names_not_resolving'])): ?>
            <?= e(__('{n} names from certificate logs no longer resolve and were skipped.', ['n' => $sum['certificate_names_not_resolving']])) ?>
            <?php endif; ?>
            <?php if (!empty($sum['errors'])): ?>
            <details class="mt-1"><summary><?= e(__('Problems ({n})', ['n' => count($sum['errors'])])) ?></summary>
                <ul class="mb-0"><?php foreach ($sum['errors'] as $err): ?><li><?= e($err) ?></li><?php endforeach; ?></ul>
            </details>
            <?php endif; ?>
            <?php if (!empty($sum['external'])): ?>
            <details class="mt-1"><summary><?= e(__('Names at other providers, not suggested ({n})', ['n' => count($sum['external'])])) ?></summary>
                <p class="mb-1"><?= e(__('These belong to someone else\'s domain (for example hosted email or DNS). They are never suggested for scanning.')) ?></p>
                <ul class="mb-0"><?php foreach ($sum['external'] as $host => $why): ?><li><code><?= e($host) ?></code>: <?= e($why) ?></li><?php endforeach; ?></ul>
            </details>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <?php if ($suggestions === []): ?>
        <p class="text-body-secondary mb-0"><?= e($lastRun === null ? __('Discovery has not run yet for this client.') : __('No new suggestions.')) ?></p>
        <?php else: ?>
        <form method="get" action="<?= e(url('/clients/' . $clientId . '/authorisations/new')) ?>" id="suggestion-select">
            <div class="table-responsive">
            <table class="table table-sm align-middle mb-2">
                <thead><tr>
                    <?php if ($isAdmin): ?><th scope="col"><span class="visually-hidden"><?= e(__('Select')) ?></span></th><?php endif; ?>
                    <th scope="col"><?= e(__('Target')) ?></th><th scope="col"><?= e(__('Found by')) ?></th><th scope="col"><?= e(__('First seen (UTC)')) ?></th>
                    <?php if ($isTech): ?><th scope="col"><span class="visually-hidden"><?= e(__('Actions')) ?></span></th><?php endif; ?>
                </tr></thead>
                <tbody>
                <?php foreach ($suggestions as $s): ?>
                <tr>
                    <?php if ($isAdmin): ?>
                    <td><input class="form-check-input" type="checkbox" name="suggestion[]" value="<?= e($s['id']) ?>" id="sg-<?= e($s['id']) ?>" <?= (int) $s['third_party_hint'] === 1 ? '' : 'checked' ?>></td>
                    <?php endif; ?>
                    <td>
                        <?php if ($isAdmin): ?><label for="sg-<?= e($s['id']) ?>"><code><?= e($s['value']) ?></code></label><?php else: ?><code><?= e($s['value']) ?></code><?php endif; ?>
                        <?php if ((int) $s['third_party_hint'] === 1): ?>
                        <span class="badge text-bg-warning"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i><?= e(__('Check: maybe third-party')) ?></span>
                        <?php endif; ?>
                    </td>
                    <td class="small"><?= e($sourceLabels[$s['source']] ?? $s['source']) ?>: <?= e($s['detail']) ?></td>
                    <td class="small text-nowrap"><?= e($s['first_seen']) ?></td>
                    <?php if ($isTech): ?>
                    <td class="text-end"><button type="submit" form="dismiss-<?= e($s['id']) ?>" class="btn btn-link btn-sm text-body-secondary p-0"><?= e(__('Dismiss')) ?></button></td>
                    <?php endif; ?>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <?php if ($isAdmin): ?>
            <button type="submit" class="btn btn-primary btn-sm"><i class="bi bi-file-earmark-plus me-1" aria-hidden="true"></i><?= e(__('Add selected to a new authorisation')) ?></button>
            <span class="small text-body-secondary ms-2"><?= e(__('Opens the authorisation form with the current scope plus your selection. The client must approve the additions.')) ?></span>
            <?php endif; ?>
        </form>
        <?php if ($isTech): ?>
        <?php foreach ($suggestions as $s): ?>
        <form method="post" action="<?= e(url('/suggestions/' . (int) $s['id'] . '/dismiss')) ?>" id="dismiss-<?= e($s['id']) ?>" class="d-none"><?= Csrf::field() ?></form>
        <?php endforeach; ?>
        <?php endif; ?>
        <?php endif; ?>

        <?php if ($dismissed !== []): ?>
        <details class="mt-3 small">
            <summary><?= e(__('Dismissed suggestions ({n})', ['n' => count($dismissed)])) ?></summary>
            <ul class="list-unstyled mt-2 mb-0">
                <?php foreach ($dismissed as $s): ?>
                <li class="d-flex align-items-center gap-2 mb-1">
                    <code><?= e($s['value']) ?></code>
                    <?php if ($isTech): ?>
                    <form method="post" action="<?= e(url('/suggestions/' . (int) $s['id'] . '/restore')) ?>"><?= Csrf::field() ?><button type="submit" class="btn btn-link btn-sm p-0"><?= e(__('Restore')) ?></button></form>
                    <?php endif; ?>
                </li>
                <?php endforeach; ?>
            </ul>
        </details>
        <?php endif; ?>
    </div>
</div>
