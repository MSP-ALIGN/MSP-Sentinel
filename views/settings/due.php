<?php
/**
 * Due-date policy card on the Settings page (admins).
 * Expects: $duePolicy (FixWorkflow::policy()).
 */
use Sentinel\Core\Csrf;
use Sentinel\Findings\FixWorkflow;
?>
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Fix due dates')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/settings/due-dates')) ?>" novalidate>
    <div class="card-body">
        <?= Csrf::field() ?>
        <p class="small text-body-secondary"><?= e(__('Days to fix an open finding, counted from when it was first seen (or reopened). Accepted risks and false positives are never due. Admins can also set a date on one finding.')) ?></p>
        <?php foreach (['kev' => __('Known-exploited vulnerabilities (CISA KEV)'), 'fail' => __('Other Fail findings'), 'warn' => __('Warnings')] as $k => $label): ?>
        <div class="row mb-2 align-items-center">
            <label class="col-8 col-form-label" for="due_days_<?= e($k) ?>"><?= e($label) ?></label>
            <div class="col-4"><div class="input-group input-group-sm">
                <input class="form-control" type="number" min="<?= e(FixWorkflow::MIN_DAYS) ?>" max="<?= e(FixWorkflow::MAX_DAYS) ?>" step="1" id="due_days_<?= e($k) ?>" name="due_days_<?= e($k) ?>" value="<?= e($duePolicy[$k]) ?>" required>
                <span class="input-group-text"><?= e(__('days')) ?></span>
            </div></div>
        </div>
        <?php endforeach; ?>
        <p class="small text-body-secondary mb-0"><?= e(__('Reminders go out once a day after {h} ({utc}:00 UTC): each person gets their overdue findings and those due within {d} days, and the team addresses get a summary of overdue findings per client.', ['h' => (new DateTimeImmutable(gmdate('Y-m-d') . sprintf(' %02d:00', FixWorkflow::REMINDER_HOUR_UTC), new DateTimeZone('UTC')))->setTimezone(display_zone())->format('H:i T'), 'utc' => sprintf('%02d', FixWorkflow::REMINDER_HOUR_UTC), 'd' => FixWorkflow::DUE_SOON_DAYS])) ?></p>
    </div>
    <div class="card-footer"><button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save due dates')) ?></button></div>
    </form>
</div>
