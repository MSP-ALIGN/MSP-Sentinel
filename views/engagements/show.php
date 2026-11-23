<?php
/**
 * One pen-test engagement: state, window, tests, scope, the signed authorisation, and the actions (approve by a
 * different admin, stop, cancel).
 * Expects: $client, $engagement (with 'targets', 'tests_list'), $state, $siteNames, $testLabels, $currentUser.
 * Every value is escaped. Actions are shown only to roles allowed to use them (the routes enforce it too).
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;
use Sentinel\Engagements\EngagementRepository as ER;

$e = $engagement;
$role = (string) $currentUser['role'];
$isAdmin = Role::atLeast($role, Role::ADMIN);
$isTech = Role::atLeast($role, Role::TECHNICIAN);
$mine = (int) $e['created_by'] === (int) $currentUser['id'];
$tz = new DateTimeZone((string) $client['timezone']);
$local = static fn (?string $utc): string => $utc === null ? '–' : (new DateTimeImmutable($utc, new DateTimeZone('UTC')))->setTimezone($tz)->format('Y-m-d H:i');
$labels = [ER::STATE_AWAITING => ['warning', __('Awaiting approval by another admin')], ER::STATE_SCHEDULED => ['info', __('Approved: testing starts at the window\'s start')],
    ER::STATE_ACTIVE => ['danger', __('Active: testing is allowed now')], ER::STATE_ENDED => ['secondary', __('Ended: the window is over')],
    ER::STATE_STOPPED => ['dark', __('Stopped (kill switch)')], ER::STATE_CANCELLED => ['secondary', __('Cancelled before approval')]];
[$cls, $label] = $labels[$state];
$byKind = ['external' => [], 'internal' => [], 'exclude' => []];
foreach ($e['targets'] as $t) {
    $byKind[$t['kind']][] = $t['kind'] === 'internal' ? ($siteNames[(int) $t['site_id']] ?? '?') . ': ' . $t['value'] : (string) $t['value'];
}
?>
<div class="alert alert-<?= e($cls) ?> d-flex align-items-center gap-2"><i class="bi bi-crosshair" aria-hidden="true"></i><strong><?= e($label) ?></strong></div>
<div class="row g-3">
    <div class="col-lg-7">
        <div class="card mb-3">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Engagement #{id}', ['id' => (int) $e['id']])) ?></h2></div>
            <div class="card-body">
                <dl class="row mb-0">
                    <dt class="col-sm-4"><?= e(__('Client')) ?></dt><dd class="col-sm-8"><a href="<?= e(url('/clients/' . (int) $client['id'] . '/engagements')) ?>"><?= e($client['name']) ?></a></dd>
                    <dt class="col-sm-4"><?= e(__('Window ({tz})', ['tz' => $client['timezone']])) ?></dt><dd class="col-sm-8"><?= e($local((string) $e['window_start'])) ?> → <?= e($local((string) $e['window_end'])) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Intensity')) ?></dt><dd class="col-sm-8"><?= e($e['intensity'] === 'normal' ? __('Normal (nmap -T3)') : __('Gentle (as day-to-day scans)')) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Tests')) ?></dt><dd class="col-sm-8"><ul class="mb-0 ps-3"><?php foreach ($e['tests_list'] as $t): ?><li><?= e($testLabels[$t] ?? $t) ?></li><?php endforeach; ?></ul></dd>
                    <dt class="col-sm-4"><?= e(__('External targets')) ?></dt><dd class="col-sm-8 font-monospace small"><?= e($byKind['external'] === [] ? '–' : implode(', ', $byKind['external'])) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Internal ranges')) ?></dt><dd class="col-sm-8 font-monospace small"><?= e($byKind['internal'] === [] ? '–' : implode(', ', $byKind['internal'])) ?></dd>
                    <dt class="col-sm-4"><?= e(__('Exclusions')) ?></dt><dd class="col-sm-8 font-monospace small"><?= e($byKind['exclude'] === [] ? '–' : implode(', ', $byKind['exclude'])) ?></dd>
                    <?php if ((string) ($e['notes'] ?? '') !== ''): ?><dt class="col-sm-4"><?= e(__('Notes')) ?></dt><dd class="col-sm-8"><?= nl2br(e((string) $e['notes'])) ?></dd><?php endif; ?>
                </dl>
            </div>
        </div>
    </div>
    <div class="col-lg-5">
        <div class="card mb-3">
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Authorisation and approval')) ?></h2></div>
            <div class="card-body">
                <p class="mb-2"><?= e(__('Signed by {n} ({r}) on {d}.', ['n' => $e['signer_name'], 'r' => $e['signer_role'], 'd' => $e['signed_on']])) ?>
                    <?php if ($isTech): ?><a href="<?= e(url('/engagements/' . (int) $e['id'] . '/document')) ?>"><?= e(__('Download the signed document')) ?></a><?php endif; ?></p>
                <p class="small text-body-secondary font-monospace text-break mb-2">SHA-256 <?= e($e['document_sha256']) ?></p>
                <p class="mb-1"><?= e(__('Created by {u} at {t}.', ['u' => $e['created_by_name'] ?? '?', 't' => $local((string) $e['created_at'])])) ?></p>
                <p class="mb-1"><?= e($e['approved_at'] !== null ? __('Approved by {u} at {t}.', ['u' => $e['approved_by_name'] ?? '?', 't' => $local((string) $e['approved_at'])]) : __('Not approved yet.')) ?></p>
                <?php if ($e['stopped_at'] !== null): ?><p class="mb-1"><?= e(__('Stopped by {u} at {t}: {r}', ['u' => $e['stopped_by_name'] ?? '?', 't' => $local((string) $e['stopped_at']), 'r' => $e['stop_reason']])) ?></p><?php endif; ?>

                <?php if ($state === ER::STATE_AWAITING && $isAdmin && !$mine): ?>
                <form method="post" action="<?= e(url('/engagements/' . (int) $e['id'] . '/approve')) ?>" class="mt-3"><?= Csrf::field() ?>
                    <label for="password" class="form-label"><?= e(__('Your Sentinel password')) ?></label>
                    <input type="password" class="form-control form-control-sm mb-2" id="password" name="password" autocomplete="current-password" required>
                    <button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-check2-circle me-1" aria-hidden="true"></i><?= e(__('Approve: I checked the signed document matches this scope')) ?></button>
                </form>
                <?php elseif ($state === ER::STATE_AWAITING && $mine): ?>
                <p class="small text-body-secondary mt-3"><?= e(__('You created it, so a different admin must approve it.')) ?></p>
                <?php endif; ?>
                <?php if ($state === ER::STATE_AWAITING && $isTech): ?>
                <form method="post" action="<?= e(url('/engagements/' . (int) $e['id'] . '/cancel')) ?>" class="mt-2" data-confirm="<?= e(__('Cancel this engagement?')) ?>"><?= Csrf::field() ?>
                    <button class="btn btn-sm btn-outline-secondary" type="submit"><?= e(__('Cancel engagement')) ?></button></form>
                <?php endif; ?>
                <?php if (in_array($state, [ER::STATE_SCHEDULED, ER::STATE_ACTIVE], true) && $isTech): ?>
                <form method="post" action="<?= e(url('/engagements/' . (int) $e['id'] . '/stop')) ?>" class="mt-3" data-confirm="<?= e(__('Stop this engagement for good? Running tests stop within a minute.')) ?>"><?= Csrf::field() ?>
                    <label for="reason" class="form-label"><?= e(__('Reason for stopping')) ?></label>
                    <input type="text" class="form-control form-control-sm mb-2" id="reason" name="reason" maxlength="500" required>
                    <button class="btn btn-sm btn-danger" type="submit"><i class="bi bi-stop-circle me-1" aria-hidden="true"></i><?= e(__('Stop engagement (kill switch)')) ?></button>
                </form>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
