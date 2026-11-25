<?php
/**
 * API tokens and the outbound event webhook (admins).
 * Expects: $tokens, $clients, $newToken (shown once, or null), $newSecret (shown once, or null), $events.
 * Every value is escaped. Token hashes are never passed to this view.
 */
use Sentinel\Core\Csrf;

$now = time();
?>
<div class="d-flex justify-content-end mb-2"><a class="btn btn-sm btn-outline-primary" href="<?= e(url('/admin/api/docs')) ?>"><i class="bi bi-book me-1" aria-hidden="true"></i><?= e(__('API reference')) ?></a></div>
<?php if ($newToken !== null): ?>
<div class="alert alert-warning" role="alert">
    <h2 class="h5"><i class="bi bi-key me-1" aria-hidden="true"></i><?= e(__('Your new API token')) ?></h2>
    <p class="mb-2"><?= e(__('Copy it now and store it safely (for example in the other system\'s secret settings). It will not be shown again.')) ?></p>
    <code class="d-block p-2 bg-body border user-select-all text-break" id="new-token"><?= e($newToken) ?></code>
</div>
<?php endif; ?>
<?php if ($newSecret !== null): ?>
<div class="alert alert-warning" role="alert">
    <h2 class="h5"><i class="bi bi-shield-lock me-1" aria-hidden="true"></i><?= e(__('Event signing secret')) ?></h2>
    <p class="mb-2"><?= e(__('Give this to the receiving system so it can check the X-Sentinel-Signature header. It will not be shown again.')) ?></p>
    <code class="d-block p-2 bg-body border user-select-all text-break" id="new-secret"><?= e($newSecret) ?></code>
</div>
<?php endif; ?>

<div class="row g-3">
<div class="col-xl-7">
<div class="card mb-3">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('API tokens')) ?></h2></div>
    <?php if ($tokens === []): ?>
    <div class="card-body"><p class="text-body-secondary mb-0 small"><?= e(__('No tokens yet.')) ?></p></div>
    <?php else: ?>
    <div class="card-body p-0 table-responsive">
        <table class="table align-middle mb-0 small">
            <thead><tr><th><?= e(__('Name')) ?></th><th><?= e(__('Can')) ?></th><th><?= e(__('Clients')) ?></th><th><?= e(__('Expires / last used')) ?></th><th></th></tr></thead>
            <tbody>
            <?php foreach ($tokens as $t):
                $revoked = $t['revoked_at'] !== null;
                $expired = !$revoked && strtotime($t['expires_at'] . ' UTC') <= $now; ?>
            <tr class="<?= $revoked || $expired ? 'text-body-secondary' : '' ?>">
                <td><?= e($t['name']) ?><br><code>snt_<?= e($t['token_prefix']) ?>_…</code><br><span class="text-body-secondary"><?= e(__('by {name}', ['name' => $t['creator']])) ?></span>
                    <?php if ($revoked): ?><span class="badge text-bg-secondary"><?= e(__('Revoked')) ?></span><?php elseif ($expired): ?><span class="badge text-bg-secondary"><?= e(__('Expired')) ?></span><?php endif; ?></td>
                <td><?= e(__('read')) ?><?= (int) $t['can_triage'] === 1 ? ', ' . e(__('triage')) : '' ?><?= (int) $t['can_scan'] === 1 ? ', ' . e(__('queue scans')) : '' ?>
                    <?php if ($t['ip_allowlist'] !== ''): ?><br><span class="text-body-secondary"><?= e(__('Only from: {ips}', ['ips' => str_replace(',', ', ', $t['ip_allowlist'])])) ?></span><?php endif; ?></td>
                <td><?= (int) $t['all_clients'] === 1 ? e(__('All clients')) : e(implode(', ', $t['clients'])) ?></td>
                <td><?= e(substr((string) $t['expires_at'], 0, 10)) ?><br><span class="text-body-secondary"><?= e($t['last_used_at'] !== null ? when($t['last_used_at']) . ' · ' . $t['last_used_ip'] : __('never used')) ?></span></td>
                <td class="text-end"><?php if (!$revoked): ?>
                    <form method="post" action="<?= e(url('/admin/api/tokens/' . (int) $t['id'] . '/revoke')) ?>" data-confirm="<?= e(__('Revoke this token? Systems using it stop working immediately.')) ?>">
                        <?= Csrf::field() ?><button type="submit" class="btn btn-sm btn-outline-danger"><?= e(__('Revoke')) ?></button>
                    </form><?php endif; ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<?php if (($currentUser['client_ids'] ?? null) === null): // events carry every client's changes (1.42) ?>
<div class="card mb-3" id="events">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Outbound events')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/api/events')) ?>" novalidate autocomplete="off">
        <?= Csrf::field() ?>
        <div class="card-body">
            <p class="small text-body-secondary"><?= e(__('Sentinel POSTs signed JSON to this address when findings open, reopen, escalate, resolve or are triaged, when a scan finishes, and when a report is created. Use it to keep MSP Align or another system up to date without polling.')) ?></p>
            <div class="form-check mb-2">
                <input class="form-check-input" type="checkbox" id="event_webhook_enabled" name="event_webhook_enabled" value="1" <?= $events['enabled'] === '1' ? 'checked' : '' ?>>
                <label class="form-check-label" for="event_webhook_enabled"><?= e(__('Send events')) ?></label>
            </div>
            <label class="form-label small mb-0" for="event_webhook_url"><?= e(__('Receiving address (https)')) ?></label>
            <input class="form-control form-control-sm" type="password" id="event_webhook_url" name="event_webhook_url" autocomplete="off" placeholder="<?= e($events['url_set'] ? __('Saved (leave empty to keep)') : 'https://align.msp.example/hooks/sentinel') ?>">
            <p class="small text-body-secondary mt-2 mb-0"><?= e($events['secret_set'] ? __('A signing secret is set. Each request carries X-Sentinel-Signature: t=<time>,v1=<HMAC-SHA256 of "time.body">.') : __('A signing secret is created when you turn events on.')) ?></p>
        </div>
        <div class="card-footer d-flex flex-wrap gap-2">
            <button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save outbound events')) ?></button>
        </div>
    </form>
    <div class="card-body pt-0 d-flex flex-wrap gap-2">
        <form method="post" data-confirm="<?= e(__('Send a test event to the configured webhook address now?')) ?>" action="<?= e(url('/admin/api/events/test')) ?>"><?= Csrf::field() ?><button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Send test event')) ?></button></form>
        <form method="post" action="<?= e(url('/admin/api/events/secret')) ?>" data-confirm="<?= e(__('Create a new signing secret? The receiving system must be updated, or it will reject events.')) ?>"><?= Csrf::field() ?><button type="submit" class="btn btn-outline-warning btn-sm"><?= e(__('New signing secret')) ?></button></form>
    </div>
    <?php if ($events['recent'] !== []): ?>
    <div class="card-body p-0 table-responsive border-top">
        <table class="table table-sm mb-0 small">
            <thead><tr><th><?= e(__('Event')) ?></th><th><?= e(__('Queued')) ?></th><th><?= e(__('Status')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($events['recent'] as $d): ?>
            <tr><td><?= e($d['subject']) ?></td><td><?= e(when($d['created_at'])) ?></td>
                <td><span class="badge text-bg-<?= $d['status'] === 'sent' ? 'success' : ($d['status'] === 'failed' ? 'danger' : 'secondary') ?>"><?= e($d['status']) ?></span>
                    <?php if ($d['last_error'] !== ''): ?><span class="text-body-secondary"><?= e($d['last_error']) ?></span><?php endif; ?></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>
<?php endif; ?>
</div>

<div class="col-xl-5">
<div class="card mb-3">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Add token')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/api/tokens')) ?>" novalidate autocomplete="off">
        <?= Csrf::field() ?>
        <div class="card-body">
            <div class="mb-2"><label class="form-label small mb-0" for="token-name"><?= e(__('Name')) ?></label>
                <input class="form-control form-control-sm" id="token-name" name="name" maxlength="100" placeholder="MSP Align" required></div>
            <fieldset class="mb-2"><legend class="form-label small mb-0"><?= e(__('Clients this token can see')) ?></legend>
                <div class="form-check"><input class="form-check-input" type="checkbox" id="all_clients" name="all_clients" value="1"<?= ($currentUser['client_ids'] ?? null) === null ? '' : ' disabled' ?>><label class="form-check-label small" for="all_clients"><?= e(__('All clients (including ones added later)')) ?></label></div>
                <label class="visually-hidden" for="token-clients"><?= e(__('Chosen clients')) ?></label>
                <select class="form-select form-select-sm mt-1" id="token-clients" name="clients[]" multiple size="5">
                    <?php foreach ($clients as $c): ?><option value="<?= e($c['id']) ?>"><?= e($c['name']) ?></option><?php endforeach; ?>
                </select></fieldset>
            <fieldset class="mb-2"><legend class="form-label small mb-0"><?= e(__('Permissions')) ?></legend>
                <div class="small text-body-secondary"><?= e(__('Every token can read. Changes are opt-in:')) ?></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" id="can_triage" name="can_triage" value="1"<?= can('findings.triage') ? '' : ' disabled' ?>><label class="form-check-label small" for="can_triage"><?= e(__('Triage findings (accept or mark false positive, with a note)')) ?> <span class="text-body-secondary"><?= e(__('needs your "Triage findings" permission')) ?></span></label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" id="can_scan" name="can_scan" value="1"<?= can('scans.run') ? '' : ' disabled' ?>><label class="form-check-label small" for="can_scan"><?= e(__('Queue scans (they still run only in scope and in the scan window)')) ?> <span class="text-body-secondary"><?= e(__('needs your "Run scans and discovery" permission')) ?></span></label></div>
            </fieldset>
            <div class="mb-2"><label class="form-label small mb-0" for="ip_allowlist"><?= e(__('Only allow these IP addresses or networks (optional)')) ?></label>
                <input class="form-control form-control-sm" id="ip_allowlist" name="ip_allowlist" maxlength="1000" placeholder="203.0.113.10, 198.51.100.0/24"></div>
            <div><label class="form-label small mb-0" for="expires_days"><?= e(__('Expires after')) ?></label>
                <select class="form-select form-select-sm" id="expires_days" name="expires_days">
                    <?php foreach ([30, 90, 180, 365] as $d): ?><option value="<?= $d ?>" <?= $d === 90 ? 'selected' : '' ?>><?= e(__('{n} days', ['n' => $d])) ?></option><?php endforeach; ?>
                </select></div>
            <label for="token_mine" class="form-label small mt-2"><?= e(__('Your own password (to confirm)')) ?></label>
            <input type="password" class="form-control form-control-sm" id="token_mine" name="my_password" required autocomplete="current-password">
            <p class="small text-body-secondary mt-2 mb-0"><?= e(__('A token acts as you. It stops working if you are deactivated or are no longer an admin.')) ?> <a href="<?= e(url('/admin/api/docs')) ?>"><?= e(__('API reference')) ?></a></p>
        </div>
        <div class="card-footer"><button type="submit" class="btn btn-primary btn-sm"><?= e(__('Create token')) ?></button></div>
    </form>
</div>
</div>
</div>
