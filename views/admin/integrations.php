<?php
/**
 * Administration > Integrations: outside systems Sentinel reads from (NinjaOne first).
 * Expects: $ninja (enabled, host, client_id, has_secret, tested_at, test_result, linked).
 * Every value is escaped. The client secret is never sent back to the browser.
 */
use Sentinel\Core\Csrf;

$n = $ninja;
?>
<p class="text-body-secondary"><?= e(__('Systems Sentinel reads from. Sentinel only reads: it never changes anything in them.')) ?></p>
<div class="card mb-3" id="ninjaone">
    <div class="card-header d-flex align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('NinjaOne')) ?></h2>
        <?php if ($n['enabled'] && $n['host'] !== '' && $n['client_id'] !== '' && $n['has_secret']): ?>
        <span class="badge text-bg-success"><?= e(__('On')) ?></span>
        <?php else: ?>
        <span class="badge text-bg-secondary"><?= e(__('Off')) ?></span>
        <?php endif; ?>
        <span class="ms-auto small text-body-secondary"><?= e(__('{n} client(s) linked', ['n' => $n['linked']])) ?></span>
    </div>
    <div class="card-body">
        <p class="small"><?= e(__('Brings each linked client\'s devices into Sentinel every 6 hours: operating system and its support date, antivirus, disk encryption (BitLocker), missing Windows updates and installed software, which is checked for known vulnerabilities. Link a client to its NinjaOne organisation on the client\'s Devices page.')) ?></p>
        <details class="small mb-3">
            <summary><?= e(__('How to create the API app in NinjaOne')) ?></summary>
            <ol class="mt-2 mb-0">
                <li><?= e(__('In NinjaOne, go to Administration, Apps, API, and open the Client App IDs tab. Click Add client app.')) ?></li>
                <li><?= e(__('Application platform: API Services (machine-to-machine). Name: MSP Sentinel.')) ?></li>
                <li><?= e(__('Scopes: Monitoring only (read-only). Allowed grant types: Client credentials.')) ?></li>
                <li><?= e(__('Save, then copy the client ID and the client secret into the form below. NinjaOne shows the secret only once.')) ?></li>
            </ol>
        </details>
        <form method="post" action="<?= e(url('/admin/integrations/ninjaone')) ?>" autocomplete="off" novalidate>
            <?= Csrf::field() ?>
            <div class="row g-3">
                <div class="col-md-4">
                    <label class="form-label" for="ninja-host"><?= e(__('Instance')) ?></label>
                    <input class="form-control" id="ninja-host" name="host" value="<?= e($n['host']) ?>" placeholder="app.ninjarmm.com" maxlength="100" list="ninja-hosts">
                    <datalist id="ninja-hosts"><option value="app.ninjarmm.com"><option value="us2.ninjarmm.com"><option value="eu.ninjarmm.com"><option value="ca.ninjarmm.com"><option value="oc.ninjarmm.com"></datalist>
                    <div class="form-text"><?= e(__('The address you sign in to NinjaOne at.')) ?></div>
                </div>
                <div class="col-md-4">
                    <label class="form-label" for="ninja-id"><?= e(__('Client ID')) ?></label>
                    <input class="form-control" id="ninja-id" name="client_id" value="<?= e($n['client_id']) ?>" maxlength="200" spellcheck="false">
                </div>
                <div class="col-md-4">
                    <label class="form-label" for="ninja-secret"><?= e(__('Client secret')) ?></label>
                    <input class="form-control" type="password" id="ninja-secret" name="client_secret" value="" maxlength="500" autocomplete="new-password" placeholder="<?= e($n['has_secret'] ? __('Saved (leave empty to keep)') : '') ?>">
                    <?php if ($n['has_secret']): ?>
                    <div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="ninja-clear" name="clear_secret" value="1"><label class="form-check-label small" for="ninja-clear"><?= e(__('Remove the saved secret')) ?></label></div>
                    <?php endif; ?>
                </div>
            </div>
            <div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="ninja-enabled" name="enabled" value="1" <?= $n['enabled'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="ninja-enabled"><?= e(__('Sync linked clients from NinjaOne')) ?></label></div>
            <div class="form-text"><?= e(__('When syncing is off, linked clients keep the devices and findings from their last sync until it is turned on again or they are unlinked.')) ?></div>
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save')) ?></button>
        </form>
        <hr>
        <form method="post" action="<?= e(url('/admin/integrations/ninjaone/test')) ?>" class="d-flex flex-wrap align-items-center gap-2">
            <?= Csrf::field() ?>
            <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-plug me-1" aria-hidden="true"></i><?= e(__('Test connection')) ?></button>
            <?php if ($n['test_result'] !== ''): ?>
            <span class="small"><?= e($n['test_result']) ?> <span class="text-body-secondary">(<?= e($n['tested_at']) ?> UTC)</span></span>
            <?php endif; ?>
        </form>
    </div>
</div>
