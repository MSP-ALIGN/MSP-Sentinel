<?php
/**
 * Port scan panel on the client page.
 * Expects: $client, $openJob (or null), $recentJobs, $services, $scanLog, $ports (list<int>), $windowOpen,
 *          $isAdmin, $isTech, $archived, $paused, $globallyPaused.
 * Values from scanned hosts (product, version, banners) are untrusted and always escaped.
 */
use Sentinel\Core\Csrf;
use Sentinel\Scanning\PortProfile;

$clientId = (int) $client['id'];
$jobBadges = [
    'queued' => ['text-bg-secondary', 'bi-hourglass', __('Queued')],
    'running' => ['text-bg-info', 'bi-arrow-repeat', __('Running')],
    'done' => ['text-bg-success', 'bi-check-circle', __('Completed')],
    'partial' => ['text-bg-warning', 'bi-exclamation-circle', __('Partly completed')],
    'failed' => ['text-bg-danger', 'bi-x-octagon', __('Failed')],
    'cancelled' => ['text-bg-secondary', 'bi-slash-circle', __('Cancelled')],
];
$resultLabels = [
    'scanned' => __('Scanned'), 'skipped_out_of_scope' => __('Skipped: not in scope'), 'stopped' => __('Stopped'),
    'timeout' => __('Timed out'), 'error' => __('Error'), 'running' => __('Running'), 'interrupted' => __('Interrupted'),
    'checked' => __('Certificates and web pages checked'),
];
$canQueue = $isTech && !$archived && !$paused && !$globallyPaused;
?>
<div class="card mt-3" id="scans">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Port scans')) ?></h2>
        <span class="small text-body-secondary"><?= e($windowOpen
            ? __('Scan window is open now ({from}–{to}, client time).', ['from' => substr((string) $client['scan_window_start'], 0, 5), 'to' => substr((string) $client['scan_window_end'], 0, 5)])
            : __('Outside the scan window ({from}–{to}, client time). Queued scans wait for it.', ['from' => substr((string) $client['scan_window_start'], 0, 5), 'to' => substr((string) $client['scan_window_end'], 0, 5)])) ?></span>
    </div>
    <div class="card-body">
        <?php if ($openJob !== null): ?>
        <?php [$bc, $bi, $bl] = $jobBadges[$openJob['status']] ?? $jobBadges['queued']; ?>
        <div class="d-flex align-items-center gap-2 mb-3" data-testid="open-job">
            <span class="badge <?= e($bc) ?>"><i class="bi <?= e($bi) ?> me-1" aria-hidden="true"></i><?= e($bl) ?></span>
            <span class="small"><?= e(__('Scan #{id}, queued {date} UTC', ['id' => $openJob['id'], 'date' => $openJob['created_at']])) ?><?= (int) $openJob['outside_window'] === 1 ? ' · ' . e(__('outside the window: {reason}', ['reason' => (string) $openJob['override_reason']])) : '' ?></span>
            <?php if ($isTech): ?>
            <form method="post" action="<?= e(url('/scans/' . (int) $openJob['id'] . '/cancel')) ?>" class="ms-auto" data-confirm="<?= e(__('Cancel this scan?')) ?>">
                <?= Csrf::field() ?>
                <button type="submit" class="btn btn-sm btn-outline-danger"><?= e(__('Cancel scan')) ?></button>
            </form>
            <?php endif; ?>
        </div>
        <?php elseif ($canQueue): ?>
        <form method="post" action="<?= e(url('/clients/' . $clientId . '/scan')) ?>" class="mb-3" novalidate>
            <?= Csrf::field() ?>
            <div class="d-flex flex-wrap align-items-center gap-2">
                <button type="submit" class="btn btn-primary btn-sm"><i class="bi bi-broadcast me-1" aria-hidden="true"></i><?= e(__('Scan now')) ?></button>
                <?php if ($isAdmin && !$windowOpen): ?>
                <div class="form-check ms-2">
                    <input class="form-check-input" type="checkbox" value="1" id="outside_window" name="outside_window">
                    <label class="form-check-label small" for="outside_window"><?= e(__('Run outside the window (admins)')) ?></label>
                </div>
                <input type="text" class="form-control form-control-sm w-auto flex-grow-1" name="reason" maxlength="300" placeholder="<?= e(__('Reason (required when running outside the window)')) ?>" aria-label="<?= e(__('Reason')) ?>">
                <?php endif; ?>
            </div>
        </form>
        <?php endif; ?>

        <details class="small mb-3">
            <summary><?= e(__('{n} TCP ports are scanned for this client', ['n' => count($ports)])) ?></summary>
            <code class="d-block mt-1 text-break"><?= e(PortProfile::toNmapArg($ports)) ?></code>
            <span class="text-body-secondary"><?= e(__('Gentle settings: TCP connect scan, polite timing, at most 50 packets per second, one host at a time.')) ?></span>
        </details>

        <h3 class="h6"><?= e(__('Open ports found')) ?></h3>
        <?php if ($services === []): ?>
        <p class="text-body-secondary small"><?= e(__('No open ports recorded yet.')) ?></p>
        <?php else: ?>
        <div class="table-responsive">
        <table class="table table-sm align-middle">
            <thead><tr>
                <th scope="col"><?= e(__('Address')) ?></th><th scope="col"><?= e(__('Port')) ?></th><th scope="col"><?= e(__('Service')) ?></th>
                <th scope="col"><?= e(__('Product / version (as reported)')) ?></th><th scope="col"><?= e(__('Open since (UTC)')) ?></th><th scope="col"><?= e(__('Last checked (UTC)')) ?></th>
            </tr></thead>
            <tbody>
            <?php foreach ($services as $svc): ?>
            <tr>
                <td><code><?= e($svc['ip']) ?></code><?php if ($svc['hostnames'] !== ''): ?><div class="small text-body-secondary"><?= e(str_replace(',', ', ', (string) $svc['hostnames'])) ?></div><?php endif; ?></td>
                <td>
                    <?= e($svc['port']) ?>/tcp
                    <?php if (isset(PortProfile::HIGH_RISK[(int) $svc['port']])): ?>
                    <span class="badge text-bg-danger"><i class="bi bi-exclamation-octagon me-1" aria-hidden="true"></i><?= e(__('High risk: {what}', ['what' => PortProfile::HIGH_RISK[(int) $svc['port']]])) ?></span>
                    <?php endif; ?>
                </td>
                <td><?= e($svc['service_name']) ?></td>
                <td class="small"><?= e(trim($svc['product'] . ' ' . $svc['version'])) ?><?php if ($svc['extra_info'] !== ''): ?> <span class="text-body-secondary">(<?= e($svc['extra_info']) ?>)</span><?php endif; ?></td>
                <td class="small text-nowrap"><?= e($svc['first_seen']) ?></td>
                <td class="small text-nowrap"><?= e($svc['last_seen']) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <p class="small text-body-secondary"><?= e(__('Product and version are what the service itself reports, and can be wrong. Vulnerability matching comes in a later release.')) ?></p>
        <?php endif; ?>

        <?php if ($recentJobs !== []): ?>
        <h3 class="h6 mt-3"><?= e(__('Recent scans')) ?></h3>
        <ul class="list-unstyled small mb-2">
            <?php foreach ($recentJobs as $job): ?>
            <?php [$bc, $bi, $bl] = $jobBadges[$job['status']] ?? $jobBadges['failed']; $sum = $job['summary']; ?>
            <li class="mb-1">
                <span class="badge <?= e($bc) ?>"><i class="bi <?= e($bi) ?> me-1" aria-hidden="true"></i><?= e($bl) ?></span>
                #<?= e($job['id']) ?> · <?= e(($job['job_type'] ?? 'ports') === 'tls' ? __('daily certificate check') : (($job['job_type'] ?? 'ports') === 'verify' ? __('verify fix by {user}', ['user' => $job['requested_by_username'] ?? '?']) : ($job['trigger_type'] === 'manual' ? __('manual by {user}', ['user' => $job['requested_by_username'] ?? '?']) : __('weekly')))) ?>
                · <?= e($job['finished_at'] ?? $job['created_at']) ?> UTC
                <?php if ($sum !== [] && ($job['job_type'] ?? 'ports') === 'tls'): ?>· <?= e(__('{n} endpoint check(s), {k} skipped', ['n' => $sum['endpoints_checked'] ?? 0, 'k' => $sum['hosts_skipped'] ?? 0])) ?>
                <?php elseif ($sum !== []): ?>· <?= e(__('{s} scanned, {k} skipped, {f} failed, {o} open ports', ['s' => $sum['hosts_scanned'] ?? 0, 'k' => $sum['hosts_skipped'] ?? 0, 'f' => $sum['hosts_failed'] ?? 0, 'o' => $sum['open_ports'] ?? 0])) ?><?php endif; ?>
                <?php foreach (($sum['messages'] ?? []) as $msg): ?><div class="text-body-secondary ms-4"><?= e($msg) ?></div><?php endforeach; ?>
            </li>
            <?php endforeach; ?>
        </ul>
        <?php endif; ?>

        <?php if ($scanLog !== []): ?>
        <details class="small">
            <summary><?= e(__('Scan log: every host Sentinel touched or skipped (last {n})', ['n' => count($scanLog)])) ?></summary>
            <div class="table-responsive mt-2">
            <table class="table table-sm mb-0">
                <thead><tr><th scope="col"><?= e(__('Time (UTC)')) ?></th><th scope="col"><?= e(__('Address')) ?></th><th scope="col"><?= e(__('Result')) ?></th><th scope="col"><?= e(__('Detail')) ?></th></tr></thead>
                <tbody>
                <?php foreach ($scanLog as $row): ?>
                <tr>
                    <td class="text-nowrap"><?= e($row['started_at']) ?></td>
                    <td><code><?= e($row['target']) ?></code><?php if ($row['hostname'] !== null): ?> <span class="text-body-secondary"><?= e($row['hostname']) ?></span><?php endif; ?></td>
                    <td><?= e($resultLabels[$row['result']] ?? $row['result']) ?></td>
                    <td><?= e($row['detail']) ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        </details>
        <?php endif; ?>
    </div>
</div>
