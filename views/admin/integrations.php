<?php
/**
 * Administration > Integrations: outside systems Sentinel reads from (NinjaOne first).
 * Expects: $ninja (enabled, host, client_id, has_secret, tested_at, test_result, linked), $align (enabled, url, has_key,
 *          tested_at, test_result, linked).
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
<?php $a = $align; ?>
<div class="card mb-3" id="mspalign">
    <div class="card-header d-flex align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('MSP Align')) ?></h2>
        <?php if ($a['enabled'] && $a['url'] !== '' && $a['has_key']): ?>
        <span class="badge text-bg-success"><?= e(__('On')) ?></span>
        <?php else: ?>
        <span class="badge text-bg-secondary"><?= e(__('Off')) ?></span>
        <?php endif; ?>
        <span class="ms-auto small text-body-secondary"><?= e(__('{n} client(s) linked', ['n' => $a['linked']])) ?></span>
    </div>
    <div class="card-body">
        <p class="small"><?= e(__('Shows each linked client\'s compliance frameworks from MSP Align on its Compliance page, with Sentinel\'s findings matched to the controls they affect. Sentinel only reads: control statuses stay in MSP Align. Link a client on its Compliance page.')) ?></p>
        <details class="small mb-3">
            <summary><?= e(__('How to create the API key in MSP Align')) ?></summary>
            <ol class="mt-2 mb-0">
                <li><?= e(__('In MSP Align, go to Administration, API. Turn the API on if it is off.')) ?></li>
                <li><?= e(__('Create a key named MSP Sentinel with the permissions clients:read and compliance:read only. You can limit it to some clients.')) ?></li>
                <li><?= e(__('Copy the key (it starts with msa_) into the form below. MSP Align shows it only once.')) ?></li>
            </ol>
        </details>
        <form method="post" action="<?= e(url('/admin/integrations/mspalign')) ?>" autocomplete="off" novalidate>
            <?= \Sentinel\Core\Csrf::field() ?>
            <div class="row g-3">
                <div class="col-md-6">
                    <label class="form-label" for="align-url"><?= e(__('MSP Align address')) ?></label>
                    <input class="form-control" id="align-url" name="url" value="<?= e($a['url']) ?>" placeholder="https://align.msp.example" maxlength="255">
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="align-key"><?= e(__('API key')) ?></label>
                    <input class="form-control" type="password" id="align-key" name="api_key" value="" maxlength="60" autocomplete="new-password" placeholder="<?= e($a['has_key'] ? __('Saved (leave empty to keep)') : 'msa_...') ?>">
                    <?php if ($a['has_key']): ?>
                    <div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="align-clear" name="clear_key" value="1"><label class="form-check-label small" for="align-clear"><?= e(__('Remove the saved key')) ?></label></div>
                    <?php endif; ?>
                </div>
            </div>
            <div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="align-enabled" name="enabled" value="1" <?= $a['enabled'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="align-enabled"><?= e(__('Show compliance from MSP Align')) ?></label></div>
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save')) ?></button>
        </form>
        <hr>
        <form method="post" action="<?= e(url('/admin/integrations/mspalign/test')) ?>" class="d-flex flex-wrap align-items-center gap-2">
            <?= \Sentinel\Core\Csrf::field() ?>
            <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-plug me-1" aria-hidden="true"></i><?= e(__('Test connection')) ?></button>
            <?php if ($a['test_result'] !== ''): ?>
            <span class="small"><?= e($a['test_result']) ?> <span class="text-body-secondary">(<?= e($a['tested_at']) ?> UTC)</span></span>
            <?php endif; ?>
        </form>
    </div>
</div>
