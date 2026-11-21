<?php
/**
 * Add or edit a client.
 * Expects: $mode ('create'|'edit'), $values (untrusted strings), $errors, and in edit mode $client.
 */
use Sentinel\Core\Csrf;

$isEdit = $mode === 'edit';
$action = $isEdit ? url('/clients/' . (int) $client['id']) : url('/clients');
$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<div class="row"><div class="col-lg-8">
<div class="card">
    <form method="post" action="<?= e($action) ?>" novalidate>
    <div class="card-body">
        <?= Csrf::field() ?>
        <div class="mb-3">
            <label for="name" class="form-label"><?= e(__('Client name')) ?></label>
            <input type="text" class="form-control<?= $invalid('name') ?>" id="name" name="name" value="<?= e($values['name']) ?>" required maxlength="150">
            <?php $field = 'name'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="mb-3">
            <label for="itflow_client_id" class="form-label"><?= e(__('ITFlow client ID (optional)')) ?></label>
            <input type="text" class="form-control<?= $invalid('itflow_client_id') ?>" id="itflow_client_id" name="itflow_client_id" value="<?= e($values['itflow_client_id']) ?>" inputmode="numeric" maxlength="10">
            <div class="form-text"><?= e(__('Links this client to ITFlow and MSP Align later. Find it in the ITFlow client URL.')) ?></div>
            <?php $field = 'itflow_client_id'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="row g-3 mb-3">
            <div class="col-md-6">
                <label for="timezone" class="form-label"><?= e(__('Client timezone')) ?></label>
                <select class="form-select<?= $invalid('timezone') ?>" id="timezone" name="timezone">
                    <?php foreach (\DateTimeZone::listIdentifiers() as $tz): ?>
                    <option value="<?= e($tz) ?>" <?= $values['timezone'] === $tz ? 'selected' : '' ?>><?= e($tz) ?></option>
                    <?php endforeach; ?>
                </select>
                <?php $field = 'timezone'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
            <div class="col-6 col-md-3">
                <label for="scan_window_start" class="form-label"><?= e(__('Scan window from')) ?></label>
                <input type="time" class="form-control<?= $invalid('scan_window_start') ?>" id="scan_window_start" name="scan_window_start" value="<?= e($values['scan_window_start']) ?>" required>
                <?php $field = 'scan_window_start'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
            <div class="col-6 col-md-3">
                <label for="scan_window_end" class="form-label"><?= e(__('to')) ?></label>
                <input type="time" class="form-control<?= $invalid('scan_window_end') ?>" id="scan_window_end" name="scan_window_end" value="<?= e($values['scan_window_end']) ?>" required>
                <?php $field = 'scan_window_end'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
            <div class="col-12 form-text mt-1"><?= e(__('Scans only run inside this window, in the client\'s timezone. A window like 22:00 to 06:00 runs overnight.')) ?></div>
        </div>
        <div class="mb-3">
            <label for="notes" class="form-label"><?= e(__('Notes (optional)')) ?></label>
            <textarea class="form-control<?= $invalid('notes') ?>" id="notes" name="notes" rows="3" maxlength="2000"><?= e($values['notes'] ?? '') ?></textarea>
            <?php $field = 'notes'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
    </div>
    <div class="card-footer">
        <button type="submit" class="btn btn-primary"><?= e($isEdit ? __('Save changes') : __('Create client')) ?></button>
        <a href="<?= e($isEdit ? url('/clients/' . (int) $client['id']) : url('/clients')) ?>" class="btn btn-outline-secondary"><?= e(__('Cancel')) ?></a>
    </div>
    </form>
</div>
</div></div>
