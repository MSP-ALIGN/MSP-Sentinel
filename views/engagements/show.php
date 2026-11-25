<?php
/**
 * One pen-test engagement: state, window, tests, scope, the signed authorisation, and the actions (approve by a
 * different admin, stop, cancel).
 * Expects: $client, $engagement (with 'targets', 'tests_list'), $state, $selfApproval (1.47: the creator may approve), $siteNames, $testLabels, $currentUser, $results
 * (latest per host), $findings (EngagementFindings::analyse), $externalJobs, $agentJobs, $reports, $retestOf.
 * Every value is escaped; results came from the tested hosts and are untrusted. Actions are shown only to roles allowed to use them (the routes enforce it too).
 */
use Sentinel\Core\Csrf;
use Sentinel\Engagements\EngagementRepository as ER;

$e = $engagement;
$isAdmin = can('engagements.approve'); // may approve (never their own)
$isTech = can('engagements.run');
$mine = (int) $e['created_by'] === (int) $currentUser['id'];
$tz = new DateTimeZone((string) $client['timezone']);
$local = static fn (?string $utc): string => $utc === null ? '–' : (new DateTimeImmutable($utc, new DateTimeZone('UTC')))->setTimezone($tz)->format('Y-m-d H:i');
$labels = [ER::STATE_AWAITING => ['warning', __('Awaiting approval by another admin')], ER::STATE_SCHEDULED => ['info', __('Approved: testing starts at the window\'s start')],
    ER::STATE_ACTIVE => ['danger', __('Active: testing is allowed now')], ER::STATE_ENDED => ['secondary', __('Ended: the window is over')],
    ER::STATE_STOPPED => ['dark', __('Stopped (kill switch)')], ER::STATE_CANCELLED => ['secondary', __('Canceled before approval')]];
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
            <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Authorization and approval')) ?></h2></div>
            <div class="card-body">
                <p class="mb-2"><?= e(__('Signed by {n} ({r}) on {d}.', ['n' => $e['signer_name'], 'r' => $e['signer_role'], 'd' => $e['signed_on']])) ?>
                    <?php if ($isTech || $isAdmin): ?><a href="<?= e(url('/engagements/' . (int) $e['id'] . '/document')) ?>"><?= e(__('Download the signed document')) ?></a><?php endif; ?></p>
                <p class="small text-body-secondary font-monospace text-break mb-2">SHA-256 <?= e($e['document_sha256']) ?></p>
                <p class="mb-1"><?= e(__('Created by {u} at {t}.', ['u' => $e['created_by_name'] ?? '?', 't' => $local((string) $e['created_at'])])) ?></p>
                <p class="mb-1"><?= e($e['approved_at'] !== null ? __('Approved by {u} at {t}.', ['u' => $e['approved_by_name'] ?? '?', 't' => $local((string) $e['approved_at'])]) : __('Not approved yet.')) ?>
                    <?php if ($e['approved_at'] !== null && (int) $e['approved_by'] === (int) $e['created_by']): ?><span class="badge text-bg-warning"><?= e(__('Single-person approval')) ?></span><?php endif; ?></p>
                <?php if ($e['stopped_at'] !== null): ?><p class="mb-1"><?= e(__('Stopped by {u} at {t}: {r}', ['u' => $e['stopped_by_name'] ?? '?', 't' => $local((string) $e['stopped_at']), 'r' => $e['stop_reason']])) ?></p><?php endif; ?>

                <?php if ($state === ER::STATE_AWAITING && $isAdmin && (!$mine || ($selfApproval ?? false))): ?>
                <?php if ($mine): ?><p class="small text-body-secondary mt-3 mb-0"><?= e(__('Two-person approval is off, so you may approve your own engagement. Check the signed document against the scope first.')) ?></p><?php endif; ?>
                <form method="post" data-confirm="<?= e(__('Approve this engagement? Its tests can run as soon as its window opens.')) ?>" action="<?= e(url('/engagements/' . (int) $e['id'] . '/approve')) ?>" class="mt-3"><?= Csrf::field() ?>
                    <label for="password" class="form-label"><?= e(__('Your Sentinel password')) ?></label>
                    <input type="password" class="form-control form-control-sm mb-2" id="password" name="password" autocomplete="current-password" required>
                    <button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-check2-circle me-1" aria-hidden="true"></i><?= e(__('Approve: I checked the signed document matches this scope')) ?></button>
                </form>
                <?php elseif ($state === ER::STATE_AWAITING && $mine): ?>
                <p class="small text-body-secondary mt-3"><?= e(($selfApproval ?? false) ? __('Someone who may approve engagements must approve it (you can\'t).') : __('You created it, so a different admin must approve it.')) ?></p>
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
<?php if ($retestOf !== null): ?><p class="small"><?= e(__('Retest of engagement #{id} ({n}).', ['id' => (int) $retestOf['id'], 'n' => $retestOf['name']])) ?> <a href="<?= e(url('/engagements/' . (int) $retestOf['id'])) ?>"><?= e(__('Open it')) ?></a></p><?php endif; ?>
<div class="card mb-3">
    <div class="card-header d-flex align-items-center flex-wrap gap-2"><h2 class="card-title h5 mb-0"><?= e(__('Report')) ?></h2>
        <?php if ($isTech && $e['approved_at'] !== null && $results !== []): ?>
        <form method="post" action="<?= e(url('/engagements/' . (int) $e['id'] . '/report')) ?>" class="ms-auto"><?= Csrf::field() ?>
            <button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-file-earmark-text me-1" aria-hidden="true"></i><?= e($retestOf !== null ? __('Issue retest letter') : __('Issue penetration test report')) ?></button></form>
        <?php endif; ?>
    </div>
    <div class="card-body">
        <?php if ($reports === []): ?><p class="text-body-secondary mb-0"><?= e(__('No report issued yet. Issue it when the tests are done; each issue is kept.')) ?></p><?php else: ?>
        <ul class="mb-0"><?php foreach ($reports as $rep): ?><li><a href="<?= e(url('/reports/' . (int) $rep['id'])) ?>"><?= e($rep['kind'] === 'retest' ? __('Retest letter') : __('Penetration test report')) ?></a> <span class="small text-body-secondary"><?= e($local((string) $rep['generated_at'])) ?></span></li><?php endforeach; ?></ul>
        <?php endif; ?>
    </div>
</div>
<div class="card mb-3">
    <div class="card-header d-flex align-items-center flex-wrap gap-2"><h2 class="card-title h5 mb-0"><?= e(__('Tests and results')) ?></h2>
        <?php if ($state === ER::STATE_ACTIVE && $isTech): ?><div class="ms-auto d-flex gap-2">
        <?php if ($byKind['external'] !== []): ?>
        <form method="post" action="<?= e(url('/engagements/' . (int) $e['id'] . '/run-external')) ?>" data-confirm="<?= e(__('Start the external tests now?')) ?>"><?= Csrf::field() ?>
            <button class="btn btn-sm btn-danger" type="submit"><i class="bi bi-play-circle me-1" aria-hidden="true"></i><?= e(__('Run external tests')) ?></button></form>
        <?php endif; ?>
        <?php if ($byKind['internal'] !== []): ?>
        <form method="post" action="<?= e(url('/engagements/' . (int) $e['id'] . '/run-internal')) ?>" data-confirm="<?= e(__('Start the internal tests with the site agents now?')) ?>"><?= Csrf::field() ?>
            <button class="btn btn-sm btn-danger" type="submit"><i class="bi bi-router me-1" aria-hidden="true"></i><?= e(__('Run internal tests')) ?></button></form>
        <?php endif; ?></div>
        <?php endif; ?>
    </div>
    <div class="card-body">
        <?php if ($externalJobs !== []): ?>
        <p class="small mb-2"><?= e(__('External test runs:')) ?>
            <?php foreach (array_slice($externalJobs, 0, 5) as $j): ?><span class="badge text-bg-light border me-1">#<?= (int) $j['id'] ?> <?= e((string) $j['status']) ?></span><?php endforeach; ?></p>
        <?php endif; ?>
        <?php if ($agentJobs !== []): ?>
        <p class="small mb-2"><?= e(__('Internal test runs:')) ?>
            <?php foreach (array_slice($agentJobs, 0, 5) as $j): ?><span class="badge text-bg-light border me-1"><?= e(($siteNames[(int) $j['site_id']] ?? '?') . ' #' . (int) $j['id'] . ' ' . $j['status']) ?></span><?php endforeach; ?></p>
        <?php endif; ?>
        <?php if ($results === []): ?>
        <p class="text-body-secondary mb-0"><?= e(__('No results yet.')) ?></p>
        <?php else: ?>
        <div class="table-responsive"><table class="table table-sm align-middle mb-0">
            <thead><tr><th><?= e(__('Host')) ?></th><th><?= e(__('Open ports')) ?></th><th><?= e(__('Script results')) ?></th><th><?= e(__('Tested ({tz})', ['tz' => $client['timezone']])) ?></th></tr></thead>
            <tbody>
            <?php foreach ($results as $r): $scriptCount = 0; foreach ($r['ports_list'] as $p) { $scriptCount += count((array) ($p['scripts'] ?? [])); } $scriptCount += count((array) ($r['checks_list']['hostscripts'] ?? [])); ?>
                <tr>
                    <td class="font-monospace small"><?= e($r['ip']) ?><?php if ($r['hostnames'] !== ''): ?><div class="text-body-secondary"><?= e($r['hostnames']) ?></div><?php endif; ?>
                        <span class="badge text-bg-light border"><?= e($r['origin'] === 'external' ? __('external') : __('internal')) ?></span><?php if ((int) $r['complete'] !== 1): ?> <span class="badge text-bg-warning"><?= e(__('incomplete')) ?></span><?php endif; ?></td>
                    <td class="small"><?= e($r['ports_list'] === [] ? '–' : implode(', ', array_map(static fn (array $p): string => (int) ($p['port'] ?? 0) . '/' . (string) ($p['service'] ?? '') . ((string) ($p['product'] ?? '') !== '' ? ' (' . $p['product'] . ' ' . ($p['version'] ?? '') . ')' : ''), $r['ports_list']))) ?></td>
                    <td class="small"><?= e((string) $scriptCount) ?></td>
                    <td class="small"><?= e($local((string) $r['scanned_at'])) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table></div>
        <?php endif; ?>
    </div>
</div>
<?php if ($findings !== []): $sev = ['fail' => ['text-bg-danger', __('Fail')], 'warn' => ['text-bg-warning', __('Warning')], 'info' => ['text-bg-secondary', __('Info')]]; ?>
<div class="card mb-3">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Findings from the tests')) ?></h2></div>
    <div class="card-body">
        <div class="table-responsive"><table class="table table-sm align-middle mb-0">
            <thead><tr><th><?= e(__('Severity')) ?></th><th><?= e(__('Finding')) ?></th><th><?= e(__('Where')) ?></th><th><?= e(__('Evidence')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($findings as $f): [$cls, $lbl] = $sev[$f['severity']]; ?>
                <tr>
                    <td><span class="badge <?= e($cls) ?>"><?= e($lbl) ?></span></td>
                    <td><?= e($f['title']) ?><div class="small text-body-secondary"><?= e($f['fix']) ?></div></td>
                    <td class="font-monospace small"><?= e($f['target']) ?></td>
                    <td><?php if ($f['evidence'] !== ''): ?><pre class="small mb-0 update-log"><?= e($f['evidence']) ?></pre><?php endif; ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table></div>
    </div>
</div>
<?php endif; ?>
