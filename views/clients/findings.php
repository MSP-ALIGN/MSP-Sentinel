<?php
/**
 * Findings card at the top of the client page.
 * Expects: $client, $clientFindings (open, most important first), $findingCounts.
 */
require __DIR__ . '/../partials/finding_badges.php';
$shown = array_slice($clientFindings, 0, 15);
?>
<div class="card mb-3" id="findings">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Findings')) ?></h2>
        <span class="badge text-bg-danger"><?= e(__('{n} Fail', ['n' => $findingCounts['fail']])) ?></span>
        <span class="badge text-bg-warning"><?= e(__('{n} Warning', ['n' => $findingCounts['warn']])) ?></span>
        <?php if ($findingCounts['accepted'] + $findingCounts['false_positive'] > 0): ?>
        <span class="small text-body-secondary"><?= e(__('{a} accepted, {f} false positive', ['a' => $findingCounts['accepted'], 'f' => $findingCounts['false_positive']])) ?></span>
        <?php endif; ?>
        <a class="ms-auto small" href="<?= e(url('/findings', ['client' => (int) $client['id'], 'status' => 'all'])) ?>"><?= e(__('All findings for this client')) ?></a>
    </div>
    <?php if ($shown === []): ?>
    <div class="card-body"><p class="text-body-secondary mb-0 small"><?= e(__('No open findings.')) ?></p></div>
    <?php else: ?>
    <ul class="list-group list-group-flush">
        <?php foreach ($shown as $f): ?>
        <li class="list-group-item d-flex align-items-center gap-2 flex-wrap">
            <?= $findingSeverityBadge((string) $f['severity']) ?>
            <a href="<?= e(url('/findings/' . (int) $f['id'])) ?>"><?= e($f['title']) ?></a>
            <code class="small"><?= e($f['target']) ?></code>
            <?php if ((int) $f['reappeared'] === 1): ?><span class="badge text-bg-dark"><?= e(__('Reappeared')) ?></span><?php endif; ?>
            <span class="ms-auto d-flex gap-2 align-items-center small"><?php if (($f['assignee_username'] ?? null) !== null): ?><span class="text-body-secondary"><i class="bi bi-person me-1" aria-hidden="true"></i><?= e($f['assignee_username']) ?></span><?php endif; ?><?= $findingDueBadge($f) ?></span>
        </li>
        <?php endforeach; ?>
    </ul>
    <?php $openTotal = $findingCounts['fail'] + $findingCounts['warn']; ?>
    <?php if ($openTotal > count($shown)): ?>
    <div class="card-footer small"><a href="<?= e(url('/findings', ['client' => (int) $client['id']])) ?>"><?= e(__('{n} more open findings', ['n' => $openTotal - count($shown)])) ?></a></div>
    <?php endif; ?>
    <?php endif; ?>
</div>
