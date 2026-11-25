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
        <div class="form-check mb-3">
            <?php // 1.45: keeps this client out of the ITFlow sync (no rename, archive or restore) and out of ITFlow tickets. ?>
            <input class="form-check-input" type="checkbox" id="itflow_sync_off" name="itflow_sync_off" value="1"<?= ($values['itflow_sync_off'] ?? '0') === '1' ? ' checked' : '' ?>>
            <label class="form-check-label" for="itflow_sync_off"><?= e(__('Don\'t sync with ITFlow')) ?></label>
            <div class="form-text"><?= e(__('The ITFlow sync leaves this client alone (no renames, archives or restores), and Sentinel makes no ITFlow tickets for it. Tickets already open in ITFlow are no longer followed (close them there if they are not needed). When you turn this off again, only findings from then on get tickets. Its ITFlow client ID is kept.')) ?></div>
        </div>
        <div class="row g-3 mb-3">
            <div class="col-md-6">
                <label for="timezone" class="form-label"><?= e(__('Client time zone')) ?></label>
                <?php // Type to search the 400+ zones (1.34); the server accepts only a zone from this list. ?>
                <input class="form-control<?= $invalid('timezone') ?>" id="timezone" name="timezone" list="timezone-list" value="<?= e($values['timezone']) ?>" required autocomplete="off" spellcheck="false" placeholder="<?= e(__('Type a city, e.g. New_York or London')) ?>">
                <datalist id="timezone-list">
                    <?php foreach (\DateTimeZone::listIdentifiers() as $tz): ?><option value="<?= e($tz) ?>"></option><?php endforeach; ?>
                </datalist>
                <div class="form-text"><?= e(__('Type part of a city or region and pick from the list (for example America/New_York).')) ?></div>
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
        <div class="row g-3 mb-3">
            <div class="col-md-6">
                <label for="ports_extra" class="form-label"><?= e(__('Extra ports to scan (optional)')) ?></label>
                <input type="text" class="form-control<?= $invalid('ports_extra') ?>" id="ports_extra" name="ports_extra" value="<?= e($values['ports_extra'] ?? '') ?>" maxlength="500" placeholder="8090, 9000-9010">
                <?php $field = 'ports_extra'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
            <div class="col-md-6">
                <label for="ports_excluded" class="form-label"><?= e(__('Ports never to scan (optional)')) ?></label>
                <input type="text" class="form-control<?= $invalid('ports_excluded') ?>" id="ports_excluded" name="ports_excluded" value="<?= e($values['ports_excluded'] ?? '') ?>" maxlength="500" placeholder="5060">
                <?php $field = 'ports_excluded'; require __DIR__ . '/../partials/field_error.php'; ?>
            </div>
            <div class="col-12 form-text mt-1"><?= e(__('TCP ports. Every client gets the default list of {n} risky and admin ports; add or remove ports here.', ['n' => count(\Sentinel\Scanning\PortProfile::DEFAULT_TCP)])) ?></div>
        </div>
        <div class="mb-3">
            <label for="notes" class="form-label"><?= e(__('Notes (optional)')) ?></label>
            <textarea class="form-control<?= $invalid('notes') ?>" id="notes" name="notes" rows="3" maxlength="2000"><?= e($values['notes'] ?? '') ?></textarea>
            <?php $field = 'notes'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
    </div>
    <div class="card-footer">
        <button type="submit" class="btn btn-primary"><?= e($isEdit ? __('Save changes') : __('Add client')) ?></button>
        <a href="<?= e($isEdit ? url('/clients/' . (int) $client['id']) : url('/clients')) ?>" class="btn btn-outline-secondary"><?= e(__('Cancel')) ?></a>
    </div>
    </form>
</div>
</div></div>
