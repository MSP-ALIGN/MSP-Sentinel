<?php
/**
 * Reports card on the client's pages: create a report (technicians and admins), the latest
 * reports, and the monthly schedule (admins). Expects: $client, $clientReports, $currentUser.
 * Every value is escaped; the routes enforce the roles too.
 */
use Sentinel\Auth\Role;
use Sentinel\Core\Csrf;

$rRole = (string) $currentUser['role'];
?>
<div class="card mb-3" id="reports">
    <div class="card-header d-flex align-items-center">
        <h2 class="card-title h5 mb-0"><?= e(__('Reports')) ?></h2>
        <a class="ms-auto small" href="<?= e(url('/reports', ['client' => (int) $client['id']])) ?>"><?= e(__('All reports for this client')) ?></a>
    </div>
    <div class="card-body">
        <?php if (Role::atLeast($rRole, Role::TECHNICIAN)): ?>
        <form method="post" action="<?= e(url('/clients/' . (int) $client['id'] . '/reports')) ?>" class="row g-2 align-items-end mb-3">
            <?= Csrf::field() ?>
            <div class="col-sm-5">
                <label class="form-label small mb-0" for="report-kind"><?= e(__('Report')) ?></label>
                <select class="form-select form-select-sm" id="report-kind" name="kind">
                    <option value="both"><?= e(__('Executive summary and Technical findings')) ?></option>
                    <option value="executive"><?= e(__('Executive summary (for management)')) ?></option>
                    <option value="technical"><?= e(__('Technical findings (for IT)')) ?></option>
                </select>
            </div>
            <div class="col-sm-4">
                <label class="form-label small mb-0" for="report-period"><?= e(__('Period')) ?></label>
                <select class="form-select form-select-sm" id="report-period" name="period">
                    <option value="30"><?= e(__('Last 30 days')) ?></option>
                    <option value="month"><?= e(__('Last calendar month')) ?></option>
                    <option value="90"><?= e(__('Last 90 days')) ?></option>
                </select>
            </div>
            <div class="col-sm-3"><button type="submit" class="btn btn-primary btn-sm w-100"><i class="bi bi-file-earmark-plus me-1" aria-hidden="true"></i><?= e(__('Create')) ?></button></div>
        </form>
        <?php endif; ?>
        <?php if ($clientReports === []): ?>
        <p class="small text-body-secondary mb-0"><?= e(__('No reports yet.')) ?></p>
        <?php else: ?>
        <ul class="list-unstyled small mb-0">
            <?php foreach ($clientReports as $r): ?>
            <li class="mb-1"><a href="<?= e(url('/reports/' . (int) $r['id'])) ?>"><?= e($r['kind'] === 'executive' ? __('Executive summary') : __('Technical findings')) ?></a>
                <span class="text-body-secondary"><?= e($r['period_start'] . ' – ' . $r['period_end']) ?></span>
                <?php if ($r['source'] === 'scheduled'): ?><span class="badge text-bg-secondary"><?= e(__('Monthly')) ?></span><?php endif; ?></li>
            <?php endforeach; ?>
        </ul>
        <?php endif; ?>
    </div>
    <div class="card-footer small">
        <?php if (Role::atLeast($rRole, Role::ADMIN)): ?>
        <form method="post" action="<?= e(url('/clients/' . (int) $client['id'] . '/report-schedule')) ?>" class="row g-2 align-items-end">
            <?= Csrf::field() ?>
            <div class="col-12 form-check ms-2">
                <input class="form-check-input" type="checkbox" id="report_monthly" name="report_monthly" value="1" <?= (int) ($client['report_monthly'] ?? 0) === 1 ? 'checked' : '' ?>>
                <label class="form-check-label" for="report_monthly"><?= e(__('Create both reports each month and email them to these MSP staff for review')) ?></label>
            </div>
            <div class="col-sm-9"><label class="visually-hidden" for="report_recipients"><?= e(__('Report recipients')) ?></label>
                <input class="form-control form-control-sm" id="report_recipients" name="report_recipients" value="<?= e(str_replace(',', ', ', (string) ($client['report_recipients'] ?? ''))) ?>" maxlength="1300" placeholder="accounts@msp.example"></div>
            <div class="col-sm-3"><button type="submit" class="btn btn-outline-primary btn-sm w-100"><?= e(__('Save')) ?></button></div>
        </form>
        <?php else: ?>
        <?= e((int) ($client['report_monthly'] ?? 0) === 1 ? __('Monthly reports are on.') : __('Monthly reports are off.')) ?>
        <?php endif; ?>
    </div>
</div>
