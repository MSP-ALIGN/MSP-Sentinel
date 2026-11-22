<?php
/**
 * On-premises agents card on the client's pages: per site, the internal authorisation, agents, kill switch and recent scans.
 * Expects: $client, $agentSites (ClientController::agentSites), $currentUser, $globallyPaused.
 * Agent-reported names and versions are untrusted and escaped.
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

$isAdmin = Role::atLeast((string) $currentUser['role'], Role::ADMIN);
$isTech = Role::atLeast((string) $currentUser['role'], Role::TECHNICIAN);
$cid = (int) $client['id'];
$jobLabel = static fn (array $j): string => match ($j['status']) {
    'done' => __('done'), 'partial' => __('partial'), 'failed' => __('failed'), 'cancelled' => __('cancelled'), 'expired' => __('expired (agent offline?)'),
    'sent' => __('running'), default => __('waiting for the agent'),
};
?>
<div class="card mb-3" id="agents">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('On-premises agents (internal scans)')) ?></h2></div>
    <div class="card-body">
        <p class="small text-body-secondary"><?= e(__('An agent is a small Linux appliance at the client\'s site. It connects out to Sentinel, scans only the internal networks approved in a signed internal authorisation, and reports devices, open services and certificates. A full scan runs weekly and a light sweep daily, inside the scan window.')) ?></p>
        <?php foreach ($agentSites as $s): $site = $s['site']; $sid = (int) $site['id']; ?>
        <div class="border rounded p-3 mb-3">
            <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
                <h3 class="h6 mb-0"><i class="bi bi-building me-1" aria-hidden="true"></i><?= e($site['name']) ?></h3>
                <?php if ((int) $site['scanning_paused'] === 1): ?><span class="badge text-bg-warning"><i class="bi bi-pause-circle me-1" aria-hidden="true"></i><?= e(__('Agent scans paused')) ?></span><?php endif; ?>
                <span class="ms-auto d-flex gap-2">
                <?php if ((int) $site['scanning_paused'] === 0 && $isTech): ?>
                    <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/pause')) ?>" data-confirm="<?= e(__('Stop agent scans at this site now?')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-danger" type="submit"><i class="bi bi-stop-circle me-1" aria-hidden="true"></i><?= e(__('Pause')) ?></button></form>
                <?php elseif ((int) $site['scanning_paused'] === 1 && $isAdmin): ?>
                    <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/resume')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-primary" type="submit"><?= e(__('Resume')) ?></button></form>
                <?php endif; ?>
                </span>
            </div>
            <div class="small mb-2">
                <strong><?= e(__('Internal authorisation:')) ?></strong>
                <?php if ($s['active'] === null): ?>
                    <span class="text-body-secondary"><?= e(__('none valid. Agents at this site do not scan.')) ?></span>
                <?php else: ?>
                    <span class="font-monospace"><?= e(implode(', ', $s['active']['ranges_list'])) ?></span>
                    <span class="text-body-secondary">· <?= e(__('approved by {name}, valid until {date}', ['name' => $s['active']['approved_by_name'], 'date' => $s['active']['valid_until']])) ?></span>
                    <i class="bi bi-patch-check text-success" aria-hidden="true"></i><span class="visually-hidden"><?= e(__('signed')) ?></span>
                    <?php if ($isAdmin): ?>
                    <details class="d-inline-block ms-2"><summary class="text-danger"><?= e(__('Revoke')) ?></summary>
                        <form method="post" action="<?= e(url('/clients/' . $cid . '/internal-authorisations/' . (int) $s['active']['id'] . '/revoke')) ?>" class="d-flex gap-2 mt-1"><?= Csrf::field() ?>
                            <input class="form-control form-control-sm" name="reason" maxlength="500" placeholder="<?= e(__('Reason (required)')) ?>" required aria-label="<?= e(__('Reason')) ?>">
                            <button class="btn btn-sm btn-danger" type="submit"><?= e(__('Revoke')) ?></button></form></details>
                    <?php endif; ?>
                <?php endif; ?>
                <?php if ($isAdmin): ?> <a class="ms-2" href="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/internal-authorisations/new')) ?>"><?= e(__('Record a new internal authorisation')) ?></a><?php endif; ?>
            </div>
            <div class="table-responsive">
            <table class="table table-sm small align-middle mb-2">
                <thead><tr><th><?= e(__('Agent')) ?></th><th><?= e(__('Version')) ?></th><th><?= e(__('Last check-in (UTC)')) ?></th><th><?= e(__('Status')) ?></th><th></th></tr></thead>
                <tbody>
                <?php if ($s['agents'] === []): ?><tr><td colspan="5" class="text-body-secondary"><?= e(__('No agent enrolled yet.')) ?></td></tr><?php endif; ?>
                <?php foreach ($s['agents'] as $a): $online = $a['last_seen_at'] !== null && strtotime($a['last_seen_at'] . ' UTC') > time() - 600; ?>
                <tr>
                    <td><?= e($a['name']) ?><div class="text-body-secondary"><?= e($a['last_ip']) ?></div></td>
                    <td class="font-monospace"><?= e($a['version'] ?: '?') ?></td>
                    <td><?= e((string) ($a['last_seen_at'] ?? '-')) ?></td>
                    <td><?php if ($a['status'] === 'revoked'): ?><span class="badge text-bg-secondary"><?= e(__('Revoked')) ?></span>
                        <?php elseif ($online): ?><span class="badge text-bg-success"><i class="bi bi-wifi me-1" aria-hidden="true"></i><?= e(__('Online')) ?></span>
                        <?php else: ?><span class="badge text-bg-warning"><i class="bi bi-wifi-off me-1" aria-hidden="true"></i><?= e(__('Offline')) ?></span><?php endif; ?></td>
                    <td class="text-end"><?php if ($isAdmin && $a['status'] === 'active'): ?>
                        <form method="post" action="<?= e(url('/clients/' . $cid . '/agents/' . (int) $a['id'] . '/revoke')) ?>" data-confirm="<?= e(__('Revoke this agent? Its token stops working immediately.')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-secondary" type="submit"><?= e(__('Revoke')) ?></button></form>
                    <?php endif; ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
            <?php if ($isAdmin): ?>
            <div class="d-flex flex-wrap gap-2 mb-2">
                <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/enrol')) ?>"><?= Csrf::field() ?><button class="btn btn-sm btn-outline-primary" type="submit"><i class="bi bi-key me-1" aria-hidden="true"></i><?= e(__('Create an enrolment code')) ?></button></form>
                <form method="post" action="<?= e(url('/clients/' . $cid . '/sites/' . $sid . '/scan')) ?>" class="d-flex gap-2"><?= Csrf::field() ?>
                    <input class="form-control form-control-sm" name="reason" maxlength="300" placeholder="<?= e(__('Reason for a scan now')) ?>" aria-label="<?= e(__('Reason for a scan now')) ?>">
                    <button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-radar me-1" aria-hidden="true"></i><?= e(__('Scan now')) ?></button></form>
            </div>
            <?php endif; ?>
            <?php if ($s['jobs'] !== []): ?>
            <ul class="list-unstyled small mb-0">
                <?php foreach ($s['jobs'] as $j): $sum = json_decode((string) ($j['summary'] ?? ''), true) ?: []; ?>
                <li>#<?= e($j['id']) ?> · <?= e($j['kind'] === 'full' ? __('full scan') : __('light sweep')) ?> · <?= e($jobLabel($j)) ?> · <?= e($j['created_at']) ?> UTC
                    <?php if (isset($sum['hosts'])): ?>· <?= e(__('{n} device(s), {m} new', ['n' => $sum['hosts'], 'm' => $sum['new_devices'] ?? 0])) ?><?php endif; ?>
                    <?php foreach ((array) ($sum['messages'] ?? []) as $msg): ?><div class="text-body-secondary ps-3"><?= e((string) $msg) ?></div><?php endforeach; ?></li>
                <?php endforeach; ?>
            </ul>
            <?php endif; ?>
        </div>
        <?php endforeach; ?>
    </div>
</div>
