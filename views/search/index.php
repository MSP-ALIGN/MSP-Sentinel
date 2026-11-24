<?php
/**
 * Search results (1.34). Expects: $q (normalised query, '' when none or too short), $raw (what was typed), $results
 * (SearchService::search). Every value comes from the database or the query and is escaped. Breach findings show only
 * their masked title and target.
 */
require __DIR__ . '/../partials/finding_badges.php';
$searchQuery = $raw;
$r = $results;
$section = static function (string $title, string $icon, int $n): string {
    return '<h2 class="h6 mt-3"><i class="bi ' . e($icon) . ' me-1" aria-hidden="true"></i>' . e($title) . ' <span class="badge text-bg-secondary">' . e($n) . '</span></h2>';
};
?>
<div class="card">
    <div class="card-body">
        <form method="get" action="<?= e(url('/search')) ?>" role="search" class="mb-3">
            <label class="form-label" for="search-page-q"><?= e(__('Search')) ?></label>
            <div class="input-group">
                <input class="form-control" type="search" id="search-page-q" name="q" maxlength="100" value="<?= e($raw) ?>" autofocus placeholder="<?= e(__('A client, finding title, CVE, address, host name, device or engagement')) ?>">
                <button class="btn btn-primary" type="submit"><i class="bi bi-search me-1" aria-hidden="true"></i><?= e(__('Search')) ?></button>
            </div>
            <div class="form-text"><?= e(__('Searches client names, finding titles, targets and CVE IDs, scanned addresses and host names, devices, engagements and the help pages. At least 2 characters.')) ?></div>
        </form>
        <?php if ($q === ''): ?>
            <?php if (trim($raw) !== ''): ?><p class="text-body-secondary"><?= e(__('Type at least 2 characters.')) ?></p><?php endif; ?>
        <?php elseif ($r['total'] === 0): ?>
            <p class="text-body-secondary"><?= e(__('Nothing found for "{q}". Try part of a name, an address or a CVE number.', ['q' => $q])) ?></p>
        <?php else: ?>
            <?php if ($r['clients'] !== []): ?>
            <?= $section(__('Clients'), 'bi-building', count($r['clients'])) ?>
            <ul class="list-unstyled mb-0">
                <?php foreach ($r['clients'] as $c): ?><li><a href="<?= e(url('/clients/' . (int) $c['id'])) ?>"><?= e($c['name']) ?></a><?= (int) $c['is_archived'] === 1 ? ' <span class="badge text-bg-secondary">' . e(__('Archived')) . '</span>' : '' ?></li><?php endforeach; ?>
            </ul>
            <?php endif; ?>
            <?php if ($r['findings'] !== []): ?>
            <?= $section(__('Findings'), 'bi-exclamation-diamond', count($r['findings'])) ?>
            <div class="table-responsive"><table class="table table-sm align-middle small mb-0"><tbody>
                <?php foreach ($r['findings'] as $f): ?>
                <tr><td><?= $findingSeverityBadge((string) $f['severity']) ?></td>
                    <td><a href="<?= e(url('/findings/' . (int) $f['id'])) ?>"><?= e($f['title']) ?></a><div class="text-body-secondary"><code><?= e($f['target']) ?></code> · <?= e($f['client_name']) ?></div></td>
                    <td><?= $findingStatusBadge((string) $f['status']) ?></td></tr>
                <?php endforeach; ?>
            </tbody></table></div>
            <?php endif; ?>
            <?php if ($r['hosts'] !== []): ?>
            <?= $section(__('Scanned hosts'), 'bi-hdd-network', count($r['hosts'])) ?>
            <ul class="list-unstyled mb-0 small">
                <?php foreach ($r['hosts'] as $h): ?><li><a href="<?= e(url('/clients/' . (int) $h['client_id'] . '/scans')) ?>"><code><?= e($h['ip']) ?></code></a> <?= e($h['hostnames']) ?> · <?= e($h['client_name']) ?></li><?php endforeach; ?>
            </ul>
            <?php endif; ?>
            <?php if ($r['devices'] !== []): ?>
            <?= $section(__('Devices'), 'bi-pc-display', count($r['devices'])) ?>
            <ul class="list-unstyled mb-0 small">
                <?php foreach ($r['devices'] as $d): ?><li><a href="<?= e(url('/clients/' . (int) $d['client_id'] . '/devices/' . (int) $d['id'])) ?>"><?= e($d['name'] !== '' ? $d['name'] : $d['dns_name']) ?></a> <code><?= e($d['ip_addresses']) ?></code> · <?= e($d['client_name']) ?></li><?php endforeach; ?>
            </ul>
            <?php endif; ?>
            <?php if ($r['engagements'] !== []): ?>
            <?= $section(__('Engagements'), 'bi-shield-exclamation', count($r['engagements'])) ?>
            <ul class="list-unstyled mb-0 small">
                <?php foreach ($r['engagements'] as $en): ?><li><a href="<?= e(url('/engagements/' . (int) $en['id'])) ?>"><?= e($en['name']) ?></a> · <?= e($en['client_name']) ?></li><?php endforeach; ?>
            </ul>
            <?php endif; ?>
            <?php if ($r['help'] !== []): ?>
            <?= $section(__('Help'), 'bi-question-circle', count($r['help'])) ?>
            <ul class="list-unstyled mb-0 small">
                <?php foreach ($r['help'] as $h): ?><li><a href="<?= e(url('/help', ['q' => $q])) ?>"><?= e($h['title']) ?></a><div class="text-body-secondary"><?= e($h['snippet']) ?></div></li><?php endforeach; ?>
            </ul>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>
