<?php
/**
 * Administration > Integrations: outside systems Sentinel reads from (NinjaOne first).
 * Expects: $itflow (enabled, url, has_key, tested_at, test_result, last_sync, last_result, last_ok, linked, tickets,
 *          tickets_last_run, tickets_last_result, tickets_last_ok, tickets_total), $ninja (enabled, host, client_id, has_secret, tested_at, test_result, linked), $align (enabled, url, has_key,
 *          tested_at, test_result, linked), $breach (enabled, has_key, last_run, last_result, last_ok, unmatched, addresses: 1.33).
 * Every value is escaped. The client secret is never sent back to the browser.
 */
use Sentinel\Core\Csrf;

$n = $ninja;
?>
<p class="text-body-secondary"><?= e(__('Systems Sentinel works with. Sentinel only reads from them, except ITFlow tickets: when ticketing is turned on, Sentinel opens, updates and closes tickets for findings. It never changes anything else.')) ?></p>
<?php $it = $itflow; ?>
<div class="card mb-3" id="itflow">
    <div class="card-header d-flex align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('ITFlow')) ?></h2>
        <?php if ($it['enabled'] && $it['url'] !== '' && $it['has_key']): ?>
        <span class="badge text-bg-success"><?= e(__('On')) ?></span>
        <?php else: ?>
        <span class="badge text-bg-secondary"><?= e(__('Off')) ?></span>
        <?php endif; ?>
        <span class="ms-auto small text-body-secondary"><?= e(__('{n} client(s) from ITFlow', ['n' => $it['linked']])) ?></span>
    </div>
    <div class="card-body">
        <p class="small"><?= e(__('ITFlow is the list of clients: every 15 minutes new ITFlow clients are added to Sentinel, names are kept in step, and clients archived in ITFlow are archived here. A new client is not scanned until its written authorisation is recorded. With MSP Align connected, clients are linked to MSP Align by their ITFlow ID too. With tickets on, findings open tickets on the ITFlow board with how to fix them.')) ?></p>
        <details class="small mb-3">
            <summary><?= e(__('How to create the API key in ITFlow')) ?></summary>
            <ol class="mt-2 mb-0">
                <li><?= e(__('In ITFlow, add an agent named MSP Sentinel with a role that can read clients and create tickets and ticket replies, with access to all clients.')) ?></li>
                <li><?= e(__('Go to Admin, API Keys, create a key for that agent with an expiry date, and copy it into the form below. Each API key acts as its agent.')) ?></li>
            </ol>
        </details>
        <form method="post" action="<?= e(url('/admin/integrations/itflow')) ?>" autocomplete="off" novalidate>
            <?= Csrf::field() ?>
            <div class="row g-3">
                <div class="col-md-6">
                    <label class="form-label" for="itflow-url"><?= e(__('ITFlow address')) ?></label>
                    <input class="form-control" id="itflow-url" name="url" value="<?= e($it['url']) ?>" placeholder="https://itflow.msp.example" maxlength="255">
                </div>
                <div class="col-md-6">
                    <label class="form-label" for="itflow-key"><?= e(__('API key')) ?></label>
                    <input class="form-control" type="password" id="itflow-key" name="api_key" value="" maxlength="200" autocomplete="new-password" placeholder="<?= e($it['has_key'] ? __('Saved (leave empty to keep)') : '') ?>">
                    <?php if ($it['has_key']): ?>
                    <div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="itflow-clear" name="clear_key" value="1"><label class="form-check-label small" for="itflow-clear"><?= e(__('Remove the saved key')) ?></label></div>
                    <?php endif; ?>
                </div>
            </div>
            <div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="itflow-enabled" name="enabled" value="1" <?= $it['enabled'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="itflow-enabled"><?= e(__('Sync clients from ITFlow')) ?></label></div>
            <div class="form-check"><input class="form-check-input" type="checkbox" id="itflow-tickets" name="tickets" value="1" <?= $it['tickets'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="itflow-tickets"><?= e(__('Open ITFlow tickets for findings')) ?></label>
                <div class="form-text"><?= e(__('Each Fail, and anything known to be exploited, gets its own ticket (High; Urgent when exploited) with how to fix it. Warnings get one ticket per client a week when there are new ones. Tickets are internal: ITFlow does not email the client. Status goes both ways: fixed in Sentinel resolves the ticket; resolved or closed in ITFlow makes Sentinel check again, and the ticket is reopened (or replaced, if closed) when the problem is still there. Only findings that appear after this is turned on get tickets, unless you open them for the existing ones below.')) ?></div></div>
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save')) ?></button>
        </form>
        <hr>
        <div class="d-flex flex-wrap align-items-center gap-2">
            <form method="post" action="<?= e(url('/admin/integrations/itflow/test')) ?>"><?= Csrf::field() ?>
                <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-plug me-1" aria-hidden="true"></i><?= e(__('Test connection')) ?></button></form>
            <form method="post" data-confirm="<?= e(__('Sync clients with ITFlow now? New ITFlow clients are added here (not scanned until authorised), renames are applied, and clients archived in ITFlow are archived here.')) ?>" action="<?= e(url('/admin/integrations/itflow/sync')) ?>"><?= Csrf::field() ?>
                <button type="submit" class="btn btn-outline-primary btn-sm"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Sync now')) ?></button></form>
            <?php if ($it['tickets']): ?>
            <form method="post" data-confirm="<?= e(__('Open ITFlow tickets now? Tickets are created in ITFlow for open Fail and known-exploited findings that have none yet.')) ?>" action="<?= e(url('/admin/integrations/itflow/tickets')) ?>"><?= Csrf::field() ?>
                <button type="submit" class="btn btn-outline-primary btn-sm"><i class="bi bi-ticket-perforated me-1" aria-hidden="true"></i><?= e(__('Open tickets now')) ?></button></form>
            <form method="post" action="<?= e(url('/admin/integrations/itflow/tickets')) ?>" data-confirm="<?= e(__('Open tickets for every current open Fail finding of linked clients (up to 20 now, the rest every 5 minutes)? Weekly Warnings tickets are not affected.')) ?>"><?= Csrf::field() ?><input type="hidden" name="existing" value="1">
                <button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Also open tickets for existing Fail findings')) ?></button></form>
            <?php endif; ?>
        </div>
        <?php if ($it['test_result'] !== ''): ?><p class="small mb-1 mt-2"><?= e($it['test_result']) ?> <span class="text-body-secondary">(<?= e($it['tested_at']) ?> UTC)</span></p><?php endif; ?>
        <?php if ($it['last_sync'] !== ''): ?><p class="small mb-0 mt-1<?= $it['last_ok'] ? '' : ' text-danger' ?>"><?= e(__('Last sync {t} UTC: {r}', ['t' => $it['last_sync'], 'r' => $it['last_result']])) ?></p><?php endif; ?>
        <?php if ($it['tickets_last_run'] !== ''): ?><p class="small mb-0 mt-1<?= $it['tickets_last_ok'] ? '' : ' text-danger' ?>"><?= e(__('Tickets {t} UTC: {r} ({n} opened so far)', ['t' => $it['tickets_last_run'], 'r' => $it['tickets_last_result'], 'n' => $it['tickets_total']])) ?></p><?php endif; ?>
    </div>
</div>
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
                <li><?= e(__('In MSP Align, go to Settings, API. Turn the API on if it is off.')) ?></li>
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
<?php $br = $breach; ?>
<div class="card mb-3" id="breach">
    <div class="card-header d-flex align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Breach monitoring (XposedOrNot)')) ?></h2>
        <?php if ($br['enabled'] && $br['has_key']): ?>
        <span class="badge text-bg-success"><?= e(__('On')) ?></span>
        <?php else: ?>
        <span class="badge text-bg-secondary"><?= e(__('Off')) ?></span>
        <?php endif; ?>
        <span class="ms-auto small text-body-secondary"><?= e(__('{n} breached address(es) on file', ['n' => $br['addresses']])) ?></span>
    </div>
    <div class="card-body">
        <p class="small"><?= e(__('Once a week, Sentinel reads which addresses of your verified domains (domains you have proved you own in your XposedOrNot account, by a DNS record or email) appear in known data breaches, and adds them to the client whose authorisation lists that domain. A breach in the last 12 months is a Fail, older ones a Warning. Only breach names, dates and what was exposed are kept: never a password.')) ?></p>
        <details class="small mb-3">
            <summary><?= e(__('How to set it up')) ?></summary>
            <ol class="mt-2 mb-0">
                <li><?= e(__('Sign in at xposedornot.com and open the dashboard.')) ?></li>
                <li><?= e(__('Verify each client domain you want to monitor (XposedOrNot proves you control it).')) ?></li>
                <li><?= e(__('Open API Key Management, copy the key into the form below and tick "Check weekly".')) ?></li>
            </ol>
            <p class="mt-2 mb-0"><?= e(__('The free key is meant for personal, low-volume use; for monitoring clients, XposedOrNot offers paid xonAPI+ keys, which work the same way here.')) ?></p>
        </details>
        <form method="post" action="<?= e(url('/admin/integrations/breach')) ?>" autocomplete="off" novalidate>
            <?= Csrf::field() ?>
            <div class="row g-3">
                <div class="col-md-6">
                    <label class="form-label" for="xon-key"><?= e(__('API key')) ?></label>
                    <input class="form-control" type="password" id="xon-key" name="api_key" value="" maxlength="128" autocomplete="new-password" placeholder="<?= e($br['has_key'] ? __('Saved (leave empty to keep)') : '') ?>">
                    <?php if ($br['has_key']): ?>
                    <div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="xon-clear" name="clear_key" value="1"><label class="form-check-label small" for="xon-clear"><?= e(__('Remove the saved key')) ?></label></div>
                    <?php endif; ?>
                </div>
            </div>
            <div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="xon-enabled" name="enabled" value="1" <?= $br['enabled'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="xon-enabled"><?= e(__('Check weekly')) ?></label></div>
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save')) ?></button>
        </form>
        <hr>
        <form method="post" data-confirm="<?= e(__('Check for breached accounts now? Sentinel asks XposedOrNot once (it allows only a few checks a day).')) ?>" action="<?= e(url('/admin/integrations/breach/check')) ?>" class="d-flex flex-wrap align-items-center gap-2">
            <?= Csrf::field() ?>
            <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Check now')) ?></button>
            <?php if ($br['last_result'] !== ''): ?>
            <span class="small <?= $br['last_ok'] ? '' : 'text-danger' ?>"><?= e($br['last_result']) ?> <span class="text-body-secondary">(<?= e($br['last_run']) ?> UTC)</span></span>
            <?php endif; ?>
        </form>
        <?php if ($br['unmatched'] !== []): ?>
        <p class="small mt-2 mb-0"><i class="bi bi-info-circle me-1" aria-hidden="true"></i><?= e(__('Verified domains in no client\'s authorisation (ignored until one lists them): {list}', ['list' => implode(', ', $br['unmatched'])])) ?></p>
        <?php endif; ?>
    </div>
</div>

<?php $so = $sso; ?>
<div class="card mb-3" id="sso">
    <div class="card-header d-flex align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Sign in with Microsoft (Entra ID)')) ?></h2>
        <span class="badge <?= $so['enabled'] ? 'text-bg-success' : 'text-bg-secondary' ?>"><?= e($so['enabled'] ? __('On') : __('Off')) ?></span>
        <span class="ms-auto small text-body-secondary"><?= e(__('{n} user(s) linked', ['n' => $so['linked']])) ?></span>
    </div>
    <div class="card-body">
        <p class="small"><?= e(__('Your team signs in with their Microsoft 365 work account. Only users who already exist in Sentinel can sign in: the first time, by the same email address, then by their Microsoft account. Roles and clients stay managed here. Sentinel\'s own code is skipped only when Microsoft confirms MFA. Password sign-in keeps working as a fallback unless you turn it off for a user.')) ?></p>
        <details class="small mb-3">
            <summary><?= e(__('How to set it up')) ?></summary>
            <ol class="mt-2 mb-0">
                <li><?= e(__('In the Microsoft Entra admin center: App registrations → New registration. Name it (e.g. MSP Sentinel), "Accounts in this organizational directory only".')) ?></li>
                <li><?= e(__('Redirect URI: platform Web, address:')) ?> <code><?= e($so['redirect'] !== '' ? $so['redirect'] : __('(set app.public_url in the config file first)')) ?></code></li>
                <li><?= e(__('Certificates & secrets → New client secret; copy its Value. From Overview, copy the Directory (tenant) ID and Application (client) ID.')) ?></li>
                <li><?= e(__('Recommended: in Conditional Access, require MFA for this app, so Sentinel can skip its own code.')) ?></li>
            </ol>
        </details>
        <form method="post" action="<?= e(url('/admin/integrations/sso')) ?>" autocomplete="off" novalidate>
            <?= Csrf::field() ?>
            <div class="row g-3">
                <div class="col-md-4"><label class="form-label" for="sso-tenant"><?= e(__('Directory (tenant) ID')) ?></label>
                    <input class="form-control font-monospace" id="sso-tenant" name="tenant_id" value="<?= e($so['tenant']) ?>" maxlength="36" spellcheck="false"></div>
                <div class="col-md-4"><label class="form-label" for="sso-client"><?= e(__('Application (client) ID')) ?></label>
                    <input class="form-control font-monospace" id="sso-client" name="client_id" value="<?= e($so['client']) ?>" maxlength="36" spellcheck="false"></div>
                <div class="col-md-4"><label class="form-label" for="sso-secret"><?= e(__('Client secret')) ?></label>
                    <input class="form-control" type="password" id="sso-secret" name="client_secret" value="" maxlength="200" autocomplete="new-password" placeholder="<?= e($so['has_secret'] ? __('Saved (leave empty to keep)') : '') ?>">
                    <?php if ($so['has_secret']): ?><div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="sso-clear" name="clear_secret" value="1"><label class="form-check-label small" for="sso-clear"><?= e(__('Remove the saved secret')) ?></label></div><?php endif; ?></div>
            </div>
            <div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="sso-enabled" name="enabled" value="1" <?= $so['enabled'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="sso-enabled"><?= e(__('Show "Sign in with Microsoft" on the sign-in page')) ?></label></div>
            <button class="btn btn-primary mt-3" type="submit"><?= e(__('Save')) ?></button>
        </form>
    </div>
</div>
