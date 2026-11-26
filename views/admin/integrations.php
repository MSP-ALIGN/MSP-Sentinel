<?php
/**
 * Administration > Integrations: outside systems Sentinel reads from (NinjaOne first).
 * Expects: $itflow (enabled, url, has_key, tested_at, test_result, last_sync, last_result, last_ok, linked, tickets,
 *          tickets_last_run, tickets_last_result, tickets_last_ok, tickets_total), $inventoryTypes (IntegrationsController::inventoryCards: one per registered inventory source), $align (enabled, url, has_key,
 *          tested_at, test_result, linked), $breach (enabled, has_key, last_run, last_result, last_ok, unmatched, addresses: 1.33).
 * Every value is escaped. The client secret is never sent back to the browser.
 */
use Sentinel\Core\Csrf;

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
        <p class="small"><?= e(__('ITFlow is the list of clients: every 15 minutes new ITFlow clients are added to Sentinel, names are kept in step, and clients archived in ITFlow are archived here. A new client is not scanned until its written authorization is recorded. With MSP Align connected, clients are linked to MSP Align by their ITFlow ID too. With tickets on, findings open tickets on the ITFlow board with how to fix them.')) ?></p>
        <details class="small mb-3">
            <summary><?= e(__('How to create the API key in ITFlow')) ?></summary>
            <ol class="mt-2 mb-0">
                <li><?= e(__('In ITFlow, add an agent named MSP Sentinel with a role that can read clients (and tags, to sync only tagged clients) and create tickets and ticket replies, with access to all clients.')) ?></li>
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
            <div class="form-check ms-4"><input class="form-check-input" type="checkbox" id="itflow-tag-filter" name="tag_filter" value="1" <?= $it['tag_filter'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="itflow-tag-filter"><?= e(__('Only sync ITFlow clients with this tag:')) ?></label>
                <label class="visually-hidden" for="itflow-tag-name"><?= e(__('ITFlow tag name')) ?></label>
                <input class="form-control form-control-sm d-inline-block sn-w-20 ms-1" id="itflow-tag-name" name="tag_name" value="<?= e($it['tag_name']) ?>" maxlength="100">
                <div class="form-text"><?= e(__('Uses ITFlow\'s client tags (any case). Tag the clients in ITFlow first: clients without the tag are not added, and ones already here are archived (restored when the tag is added back). If the tag can\'t be read, no client tag has this name, or no client has it, the sync stops and nothing changes.')) ?>
                    <?php if ($it['sync_off'] > 0): ?><?= e(__('{n} client(s) are set to "Don\'t sync with ITFlow" on their Edit page.', ['n' => $it['sync_off']])) ?><?php endif; ?></div></div>
            <div class="form-check"><input class="form-check-input" type="checkbox" id="itflow-tickets" name="tickets" value="1" <?= $it['tickets'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="itflow-tickets"><?= e(__('Open ITFlow tickets for findings')) ?></label>
                <div class="form-text"><?= e(__('Each Fail, and anything known to be exploited, gets its own ticket (High; Urgent when exploited, unless you choose one priority below) with how to fix it. Warnings get one ticket per client a week when there are new ones. Tickets are internal: ITFlow does not email the client. Status goes both ways: fixed in Sentinel resolves the ticket; resolved or closed in ITFlow makes Sentinel check again, and the ticket is reopened (or replaced, if closed) when the problem is still there. Only findings that appear after this is turned on get tickets, unless you open them for the existing ones below.')) ?></div></div>
            <div class="mt-3">
                <label class="form-label" for="itflow-board"><?= e(__('Board for new tickets')) ?></label>
                <?php $alerts = \Sentinel\Itflow\ItflowClient::alertsBoard($it['boards'] ?? []); ?>
                <select class="form-select form-select-sm sn-w-20" id="itflow-board" name="board">
                    <option value="" <?= $it['board'] === '' ? 'selected' : '' ?>><?= e($alerts !== null ? __('Alerts (the board named "Alerts")') : __('The board named "Alerts", when there is one')) ?></option>
                    <option value="0" <?= $it['board'] === '0' ? 'selected' : '' ?>><?= e(__('Leave on ITFlow\'s default board')) ?></option>
                    <?php foreach ($it['boards'] ?? [] as $b): ?>
                    <option value="<?= e($b['id']) ?>" <?= $it['board'] === (string) $b['id'] ? 'selected' : '' ?>><?= e($b['name']) ?><?= $b['is_default'] ? ' ' . e(__('(ITFlow\'s default)')) : '' ?></option>
                    <?php endforeach; ?>
                    <?php if (!in_array($it['board'], ['', '0'], true) && !in_array((int) $it['board'], array_column($it['boards'] ?? [], 'id'), true)): ?>
                    <option value="<?= e($it['board']) ?>" selected><?= e(__('Board #{id} (not listed now)', ['id' => $it['board']])) ?></option>
                    <?php endif; ?>
                </select>
                <div class="form-text"><?= e($it['boards'] === null
                    ? __('For ITFlow builds with service boards: Sentinel moves each new ticket to this board, unassigned, so the board\'s own rules pick it up.') . ' '
                      . ($it['boards_checked'] ? __('This ITFlow lists no boards (stock ITFlow), so tickets stay where ITFlow puts them.') : __('The boards are listed after Test connection or the next sync.'))
                    : __('Sentinel moves each new ticket to this board right after opening it, unassigned, so the board\'s auto-assign and notifications pick it up. If a move fails, the ticket stays on ITFlow\'s default board and the last run says so.')) ?></div>
            </div>
            <div class="row g-3 mt-0">
                <div class="col-md-5">
                    <label class="form-label" for="itflow-priority"><?= e(__('Priority for Sentinel tickets')) ?></label>
                    <select class="form-select form-select-sm" id="itflow-priority" name="ticket_priority">
                        <option value="" <?= $it['priority'] === '' ? 'selected' : '' ?>><?= e(__('Automatic: High, Urgent when known exploited, Medium for the weekly ticket')) ?></option>
                        <?php foreach (['Low' => __('Low'), 'Medium' => __('Medium'), 'High' => __('High'), 'Urgent' => __('Urgent')] as $pv => $pl): ?>
                        <option value="<?= e($pv) ?>" <?= $it['priority'] === $pv ? 'selected' : '' ?>><?= e(__('{p} for every ticket', ['p' => $pl])) ?></option>
                        <?php endforeach; ?>
                    </select>
                    <div class="form-text"><?= e(__('A fixed priority applies to every Sentinel ticket, known-exploited findings included. ITFlow sets a ticket\'s SLA from its priority: to keep SLAs off Sentinel\'s tickets, choose a priority that has no SLA in ITFlow.')) ?></div>
                </div>
                <div class="col-md-4">
                    <label class="form-label" for="itflow-template"><?= e(__('Ticket template (optional)')) ?></label>
                    <input class="form-control form-control-sm" id="itflow-template" name="ticket_template" value="<?= e($it['template']) ?>" inputmode="numeric" maxlength="10" placeholder="<?= e(__('none')) ?>">
                    <div class="form-text"><?= e(__('The number of an ITFlow ticket template (Admin → Ticket Templates). New tickets get its category, and any tags, tasks and due time it has; Sentinel\'s subject, details and priority are kept.')) ?></div>
                </div>
            </div>
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save ITFlow')) ?></button>
        </form>
        <hr>
        <div class="d-flex flex-wrap align-items-center gap-2">
            <form method="post" action="<?= e(url('/admin/integrations/itflow/test')) ?>"><?= Csrf::field() ?>
                <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-plug me-1" aria-hidden="true"></i><?= e(__('Test connection')) ?></button></form>
            <form method="post" data-confirm="<?= e(__('Sync clients with ITFlow now? New ITFlow clients are added here (not scanned until authorized), renames are applied, and clients archived in ITFlow are archived here.')) ?>" action="<?= e(url('/admin/integrations/itflow/sync')) ?>"><?= Csrf::field() ?>
                <button type="submit" class="btn btn-outline-primary btn-sm"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Sync now')) ?></button></form>
            <?php if ($it['tickets']): ?>
            <form method="post" data-confirm="<?= e(__('Open ITFlow tickets now? Tickets are created in ITFlow for open Fail and known-exploited findings that have none yet.')) ?>" action="<?= e(url('/admin/integrations/itflow/tickets')) ?>"><?= Csrf::field() ?>
                <button type="submit" class="btn btn-outline-primary btn-sm"><i class="bi bi-ticket-perforated me-1" aria-hidden="true"></i><?= e(__('Open tickets now')) ?></button></form>
            <form method="post" action="<?= e(url('/admin/integrations/itflow/tickets')) ?>" data-confirm="<?= e(__('Open tickets for every current open Fail finding of linked clients (up to 20 now, the rest every 5 minutes)? Weekly Warnings tickets are not affected.')) ?>"><?= Csrf::field() ?><input type="hidden" name="existing" value="1">
                <button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Also open tickets for existing Fail findings')) ?></button></form>
            <?php endif; ?>
        </div>
        <?php if ($it['test_result'] !== ''): ?><p class="small mb-1 mt-2"><?= e($it['test_result']) ?> <span class="text-body-secondary">(<?= e(when($it['tested_at'])) ?>)</span></p><?php endif; ?>
        <?php if ($it['last_sync'] !== ''): ?><p class="small mb-0 mt-1<?= $it['last_ok'] ? '' : ' text-danger' ?>"><?= e(__('Last sync {t}: {r}', ['t' => when($it['last_sync']), 'r' => $it['last_result']])) ?></p><?php endif; ?>
        <?php if ($it['tickets_last_run'] !== ''): ?><p class="small mb-0 mt-1<?= $it['tickets_last_ok'] ? '' : ' text-danger' ?>"><?= e(__('Tickets {t}: {r} ({n} opened so far)', ['t' => when($it['tickets_last_run']), 'r' => $it['tickets_last_result'], 'n' => $it['tickets_total']])) ?></p><?php endif; ?>
    </div>
</div>
<?php // Inventory sources (1.52): one card per registered RMM, drawn from its SourceType (fields, steps, intro). ?>
<?php foreach ($inventoryTypes as $src): $sn = $src['name']; ?>
<div class="card mb-3" id="<?= e($sn) ?>">
    <div class="card-header d-flex align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e($src['label']) ?></h2>
        <?php if ($src['enabled'] && $src['ready']): ?>
        <span class="badge text-bg-success"><?= e(__('On')) ?></span>
        <?php else: ?>
        <span class="badge text-bg-secondary"><?= e(__('Off')) ?></span>
        <?php endif; ?>
        <span class="ms-auto small text-body-secondary"><?= e(__('{n} client(s) linked', ['n' => $src['linked']])) ?></span>
    </div>
    <div class="card-body">
        <p class="small"><?= e($src['intro']) ?></p>
        <p class="small text-body-secondary"><?= e(__('A client can be linked to one RMM at a time.')) ?></p>
        <details class="small mb-3">
            <summary><?= e(__('How to create the API access in {source}', ['source' => $src['label']])) ?></summary>
            <ol class="mt-2 mb-0">
                <?php foreach ($src['steps'] as $step): ?><li><?= e($step) ?></li><?php endforeach; ?>
            </ol>
        </details>
        <form method="post" action="<?= e(url('/admin/integrations/' . $sn)) ?>" autocomplete="off" novalidate>
            <?= Csrf::field() ?>
            <div class="row g-3">
                <?php foreach ($src['fields'] as $f): $fid = $sn . '-' . $f['key']; ?>
                <div class="col-md-4">
                    <label class="form-label" for="<?= e($fid) ?>"><?= e($f['label']) ?></label>
                    <?php if ($f['secret']): ?>
                    <input class="form-control" type="password" id="<?= e($fid) ?>" name="<?= e($f['key']) ?>" value="" maxlength="<?= (int) $f['maxlength'] ?>" autocomplete="new-password" placeholder="<?= e($f['saved'] ? __('Saved (leave empty to keep)') : '') ?>">
                    <?php if ($f['saved']): ?>
                    <div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="<?= e($fid) ?>-clear" name="clear_<?= e($f['key']) ?>" value="1"><label class="form-check-label small" for="<?= e($fid) ?>-clear"><?= e(__('Remove the saved secret')) ?></label></div>
                    <?php endif; ?>
                    <?php else: ?>
                    <input class="form-control" id="<?= e($fid) ?>" name="<?= e($f['key']) ?>" value="<?= e($f['value']) ?>" maxlength="<?= (int) $f['maxlength'] ?>" spellcheck="false"<?= isset($f['placeholder']) ? ' placeholder="' . e($f['placeholder']) . '"' : '' ?><?= ($f['suggestions'] ?? []) !== [] ? ' list="' . e($fid) . '-list"' : '' ?>>
                    <?php if (($f['suggestions'] ?? []) !== []): ?><datalist id="<?= e($fid) ?>-list"><?php foreach ($f['suggestions'] as $opt): ?><option value="<?= e($opt) ?>"><?php endforeach; ?></datalist><?php endif; ?>
                    <?php endif; ?>
                    <?php if (isset($f['help'])): ?><div class="form-text"><?= e($f['help']) ?></div><?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
            <div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="<?= e($sn) ?>-enabled" name="enabled" value="1" <?= $src['enabled'] ? 'checked' : '' ?>>
                <label class="form-check-label" for="<?= e($sn) ?>-enabled"><?= e(__('Sync linked clients from {source}', ['source' => $src['label']])) ?></label></div>
            <div class="form-text"><?= e(__('When syncing is off, linked clients keep the devices and findings from their last sync until it is turned on again or they are unlinked.')) ?></div>
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save {source}', ['source' => $src['label']])) ?></button>
        </form>
        <hr>
        <form method="post" action="<?= e(url('/admin/integrations/' . $sn . '/test')) ?>" class="d-flex flex-wrap align-items-center gap-2">
            <?= Csrf::field() ?>
            <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-plug me-1" aria-hidden="true"></i><?= e(__('Test connection')) ?></button>
            <?php if ($src['test_result'] !== ''): ?>
            <span class="small"><?= e($src['test_result']) ?> <span class="text-body-secondary">(<?= e(when($src['tested_at'])) ?>)</span></span>
            <?php endif; ?>
        </form>
    </div>
</div>
<?php endforeach; ?>
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
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save MSP Align')) ?></button>
        </form>
        <hr>
        <form method="post" action="<?= e(url('/admin/integrations/mspalign/test')) ?>" class="d-flex flex-wrap align-items-center gap-2">
            <?= \Sentinel\Core\Csrf::field() ?>
            <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-plug me-1" aria-hidden="true"></i><?= e(__('Test connection')) ?></button>
            <?php if ($a['test_result'] !== ''): ?>
            <span class="small"><?= e($a['test_result']) ?> <span class="text-body-secondary">(<?= e(when($a['tested_at'])) ?>)</span></span>
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
        <p class="small"><?= e(__('Once a week, Sentinel reads which addresses of your verified domains (domains you have proved you own in your XposedOrNot account, by a DNS record or email) appear in known data breaches, and adds them to the client whose authorization lists that domain. A breach in the last 12 months is a Fail, older ones a Warning. Only breach names, dates and what was exposed are kept: never a password.')) ?></p>
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
            <button type="submit" class="btn btn-primary btn-sm mt-3"><?= e(__('Save breach monitoring')) ?></button>
        </form>
        <hr>
        <form method="post" data-confirm="<?= e(__('Check for breached accounts now? Sentinel asks XposedOrNot once (it allows only a few checks a day).')) ?>" action="<?= e(url('/admin/integrations/breach/check')) ?>" class="d-flex flex-wrap align-items-center gap-2">
            <?= Csrf::field() ?>
            <button type="submit" class="btn btn-outline-secondary btn-sm"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Check now')) ?></button>
            <?php if ($br['last_result'] !== ''): ?>
            <span class="small <?= $br['last_ok'] ? '' : 'text-danger' ?>"><?= e($br['last_result']) ?> <span class="text-body-secondary">(<?= e(when($br['last_run'])) ?>)</span></span>
            <?php endif; ?>
        </form>
        <?php if ($br['unmatched'] !== []): ?>
        <p class="small mt-2 mb-0"><i class="bi bi-info-circle me-1" aria-hidden="true"></i><?= e(__('Verified domains in no client\'s authorization (ignored until one lists them): {list}', ['list' => implode(', ', $br['unmatched'])])) ?></p>
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
        <p class="small"><?= e(__('Your team signs in with their Microsoft 365 work account. Each user links their own Microsoft account once, under My profile, while signed in with their password and Sentinel\'s code; only linked accounts can sign in, and guests from other directories never can. Roles and clients stay managed here. Sentinel\'s own code is skipped only when Microsoft confirms MFA within the last hour. Password sign-in keeps working as a fallback unless you turn it off for a user.')) ?></p>
        <?php // Connect to Microsoft 365 (1.63): sign in at Microsoft with a code, and Sentinel creates the Entra app itself. ?>
        <?php if ($so['secret_days'] !== null): ?>
        <div class="alert <?= $so['secret_days'] <= 30 ? 'alert-warning' : 'alert-light' ?> small py-2" role="status">
            <?= e($so['secret_days'] < 0 ? __('The client secret expired on {date}. Sign-in with Microsoft fails until it is renewed: click "Connect to Microsoft 365" below.', ['date' => substr($so['secret_expires'], 0, 10)])
                : ($so['secret_days'] <= 30 ? __('The client secret expires on {date} ({n} days). Renew it: click "Connect to Microsoft 365" below.', ['date' => substr($so['secret_expires'], 0, 10), 'n' => $so['secret_days']])
                : __('The client secret expires on {date}. Sentinel reminds admins 30 days before.', ['date' => substr($so['secret_expires'], 0, 10)]))) ?>
        </div>
        <?php endif; ?>
        <?php $cn = $so['connect']; $mine = $cn !== null && (int) $cn['user'] === (int) ($currentUser['id'] ?? 0); ?>
        <?php if ($mine): ?>
        <div class="alert alert-info sso-connect" role="status">
            <p class="mb-2"><strong><?= e(__('Sign in at Microsoft to finish')) ?></strong></p>
            <ol class="small mb-2">
                <li><?= e(__('Open')) ?> <a href="<?= e($cn['verification_uri']) ?>" target="_blank" rel="noopener noreferrer"><?= e(preg_replace('#^https?://#', '', $cn['verification_uri'])) ?></a> <?= e(__('(opens in a new tab).')) ?></li>
                <li><?= e(__('Enter this code:')) ?> <code class="fs-5 user-select-all" data-testid="sso-user-code"><?= e($cn['user_code']) ?></code></li>
                <li><?= e(__('Sign in as an Entra admin (Global Administrator, Application Administrator or Cloud Application Administrator) and accept the permissions. They are used only now, to create the app.')) ?></li>
            </ol>
            <p class="small mb-2" id="sso-connect-status" aria-live="polite"><?= e(__('Waiting for you to sign in at Microsoft… This page checks by itself.')) ?></p>
            <div class="d-flex flex-wrap gap-2">
                <form method="post" action="<?= e(url('/admin/integrations/sso/connect/check')) ?>" data-sso-poll data-status="sso-connect-status"><?= Csrf::field() ?>
                    <button class="btn btn-primary btn-sm" type="submit"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i><?= e(__('Check now')) ?></button></form>
                <form method="post" action="<?= e(url('/admin/integrations/sso/connect/cancel')) ?>"><?= Csrf::field() ?>
                    <button class="btn btn-outline-secondary btn-sm" type="submit"><?= e(__('Cancel')) ?></button></form>
            </div>
            <p class="small text-body-secondary mt-2 mb-0"><?= e(__('The code is valid until {t}.', ['t' => when(gmdate('Y-m-d H:i:s', (int) $cn['expires']))])) ?></p>
        </div>
        <?php else: ?>
        <form method="post" action="<?= e(url('/admin/integrations/sso/connect')) ?>" autocomplete="off" class="mb-3" novalidate>
            <?= Csrf::field() ?>
            <p class="small mb-2"><strong><?= e(__('Set up automatically')) ?></strong>: <?= e(__('Sign in to Microsoft 365 as an Entra admin and Sentinel creates the app registration itself: sign-in permissions only, consent for your organization and a 24-month client secret. Nothing to copy or install. Do it again to renew the secret.')) ?>
                <?php if ($cn !== null): ?><?= e(__('Another admin has a connection in progress; starting a new one replaces it.')) ?><?php endif; ?></p>
            <div class="d-flex flex-wrap align-items-end gap-2">
                <div><label class="form-label small mb-1" for="sso-connect-pw"><?= e(__('Your own password (to confirm)')) ?></label>
                    <input class="form-control form-control-sm sn-w-20" type="password" id="sso-connect-pw" name="my_password" required autocomplete="current-password"></div>
                <button class="btn btn-outline-primary btn-sm" type="submit"<?= $so['public_url'] === '' ? ' disabled' : '' ?>><i class="bi bi-microsoft me-1" aria-hidden="true"></i><?= e(__('Connect to Microsoft 365')) ?></button>
            </div>
            <?php if ($so['tenant'] !== ''): ?>
            <div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="sso-connect-tenant" name="new_tenant" value="1">
                <label class="form-check-label small" for="sso-connect-tenant"><?= e(__('Switch to another Microsoft tenant (every user\'s Microsoft link is cleared, and password sign-in is turned back on for them)')) ?></label></div>
            <div class="form-text"><?= e(__('Without this, you must sign in to the tenant Sentinel uses now ({tenant}), so signing in to the wrong tenant changes nothing.', ['tenant' => $so['tenant']])) ?></div>
            <?php endif; ?>
            <?php if ($so['public_url'] === ''): ?><div class="form-text"><?= e(__('Set app.public_url in the config file first.')) ?></div><?php endif; ?>
            <div class="form-text"><?= e(__('Sentinel\'s server must be able to reach login.microsoftonline.com and graph.microsoft.com. If your tenant blocks sign-in with a code (Conditional Access), set the app up by hand below.')) ?></div>
        </form>
        <?php endif; ?>
        <details class="small mb-3">
            <summary><?= e(__('Or set it up by hand')) ?></summary>
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
            <div class="mt-3"><label class="form-label" for="sso-mine"><?= e(__('Your own password (to confirm)')) ?></label>
                <input class="form-control sn-w-20" type="password" id="sso-mine" name="my_password" required autocomplete="current-password"></div>
            <div class="form-text"><?= e(__('Only an Admin who sees every client can change this. Changing the tenant clears every user\'s Microsoft link.')) ?></div>
            <button class="btn btn-primary mt-3" type="submit"><?= e(__('Save sign-in settings')) ?></button>
        </form>
    </div>
</div>
