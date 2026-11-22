<?php
/**
 * Alert settings (admins): email via SMTP, team addresses, webhook; test buttons; recent deliveries.
 * Expects: $alerts (values; secrets only as password_set / webhook_set; recent deliveries; public_url).
 * Secrets are never printed: the fields are write-only.
 */
use Sentinel\Core\Csrf;

$a = $alerts;
$statusBadge = ['sent' => 'text-bg-success', 'pending' => 'text-bg-secondary', 'failed' => 'text-bg-danger'];
?>
<div class="card mt-3" id="alerts">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Alerts')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/alerts')) ?>" novalidate autocomplete="off">
    <div class="card-body">
        <?= Csrf::field() ?>
        <?php if ($a['public_url'] === ''): ?>
        <div class="alert alert-info small"><?= e(__('Set app.public_url in config/config.php (e.g. https://sentinel.msp.example) so emails and webhook messages can link back to Sentinel.')) ?></div>
        <?php endif; ?>
        <h3 class="h6"><?= e(__('Email')) ?></h3>
        <div class="form-check mb-2">
            <input class="form-check-input" type="checkbox" id="email_enabled" name="email_enabled" value="1" <?= $a['email_enabled'] === '1' ? 'checked' : '' ?>>
            <label class="form-check-label" for="email_enabled"><?= e(__('Send email alerts')) ?></label>
        </div>
        <div class="row g-2">
            <div class="col-md-6"><label class="form-label small mb-0" for="smtp_host"><?= e(__('Mail server')) ?></label><input class="form-control form-control-sm" id="smtp_host" name="smtp_host" value="<?= e($a['smtp_host']) ?>" maxlength="253" placeholder="smtp.msp.example"></div>
            <div class="col-md-2"><label class="form-label small mb-0" for="smtp_port"><?= e(__('Port')) ?></label><input class="form-control form-control-sm" id="smtp_port" name="smtp_port" value="<?= e($a['smtp_port']) ?>" inputmode="numeric" maxlength="5"></div>
            <div class="col-md-4"><label class="form-label small mb-0" for="smtp_security"><?= e(__('Connection')) ?></label>
                <select class="form-select form-select-sm" id="smtp_security" name="smtp_security">
                    <?php foreach (['starttls' => __('STARTTLS (usually port 587)'), 'tls' => __('TLS (usually port 465)'), 'none' => __('None (local relay only)')] as $k => $l): ?>
                    <option value="<?= e($k) ?>" <?= $a['smtp_security'] === $k ? 'selected' : '' ?>><?= e($l) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-6"><label class="form-label small mb-0" for="smtp_username"><?= e(__('User name (optional)')) ?></label><input class="form-control form-control-sm" id="smtp_username" name="smtp_username" value="<?= e($a['smtp_username']) ?>" maxlength="190" autocomplete="off"></div>
            <div class="col-md-6">
                <label class="form-label small mb-0" for="smtp_password"><?= e(__('Password')) ?></label>
                <input class="form-control form-control-sm" type="password" id="smtp_password" name="smtp_password" autocomplete="new-password" placeholder="<?= e($a['password_set'] ? __('Saved (leave empty to keep)') : __('Not set')) ?>">
                <?php if ($a['password_set']): ?><div class="form-check small"><input class="form-check-input" type="checkbox" id="clear_password" name="clear_password" value="1"><label class="form-check-label" for="clear_password"><?= e(__('Remove the saved password')) ?></label></div><?php endif; ?>
            </div>
            <div class="col-md-6"><label class="form-label small mb-0" for="smtp_from"><?= e(__('Sender address')) ?></label><input class="form-control form-control-sm" type="email" id="smtp_from" name="smtp_from" value="<?= e($a['smtp_from']) ?>" maxlength="254" placeholder="sentinel@msp.example"></div>
            <div class="col-md-6"><label class="form-label small mb-0" for="team_addresses"><?= e(__('Team addresses (optional, up to 5)')) ?></label><input class="form-control form-control-sm" id="team_addresses" name="team_addresses" value="<?= e(str_replace(',', ', ', $a['team_addresses'])) ?>" maxlength="1300" placeholder="alerts@msp.example"></div>
        </div>
        <p class="form-text"><?= e(__('Team addresses get every immediate alert and every scan summary. Each user also chooses their own emails on their profile. The password is stored encrypted and never shown again.')) ?></p>

        <h3 class="h6 mt-3"><?= e(__('Webhook (Teams, Slack or other tools)')) ?></h3>
        <div class="form-check mb-2">
            <input class="form-check-input" type="checkbox" id="webhook_enabled" name="webhook_enabled" value="1" <?= $a['webhook_enabled'] === '1' ? 'checked' : '' ?>>
            <label class="form-check-label" for="webhook_enabled"><?= e(__('Post alerts to a webhook')) ?></label>
        </div>
        <div class="row g-2">
            <div class="col-md-8">
                <label class="form-label small mb-0" for="webhook_url"><?= e(__('Webhook address')) ?></label>
                <input class="form-control form-control-sm" type="password" id="webhook_url" name="webhook_url" autocomplete="off" placeholder="<?= e($a['webhook_set'] ? __('Saved (leave empty to keep)') : 'https://…') ?>">
                <?php if ($a['webhook_set']): ?><div class="form-check small"><input class="form-check-input" type="checkbox" id="clear_webhook" name="clear_webhook" value="1"><label class="form-check-label" for="clear_webhook"><?= e(__('Remove the saved address')) ?></label></div><?php endif; ?>
            </div>
            <div class="col-md-4"><label class="form-label small mb-0" for="webhook_format"><?= e(__('Format')) ?></label>
                <select class="form-select form-select-sm" id="webhook_format" name="webhook_format">
                    <?php foreach (['teams' => __('Microsoft Teams (Workflows)'), 'slack' => __('Slack'), 'json' => __('Generic JSON')] as $k => $l): ?>
                    <option value="<?= e($k) ?>" <?= $a['webhook_format'] === $k ? 'selected' : '' ?>><?= e($l) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
        <p class="form-text"><?= e(__('The address must use https and point to a public service. It contains a secret token, so it is stored encrypted and never shown again. Only alert summaries and links are sent, never scan details.')) ?></p>
    </div>
    <div class="card-footer d-flex flex-wrap gap-2">
        <button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save alert settings')) ?></button>
    </div>
    </form>
    <div class="card-body border-top">
        <div class="d-flex flex-wrap gap-2 mb-3">
            <form method="post" action="<?= e(url('/admin/alerts/test')) ?>"><?= Csrf::field() ?><input type="hidden" name="channel" value="email"><button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Send test email to me')) ?></button></form>
            <form method="post" action="<?= e(url('/admin/alerts/test')) ?>"><?= Csrf::field() ?><input type="hidden" name="channel" value="webhook"><button type="submit" class="btn btn-outline-secondary btn-sm"><?= e(__('Send test webhook message')) ?></button></form>
        </div>
        <?php if ($a['recent'] !== []): ?>
        <h3 class="h6"><?= e(__('Recent deliveries')) ?></h3>
        <table class="table table-sm small mb-0">
            <thead><tr><th scope="col"><?= e(__('When (UTC)')) ?></th><th scope="col"><?= e(__('Channel')) ?></th><th scope="col"><?= e(__('Subject')) ?></th><th scope="col"><?= e(__('Status')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($a['recent'] as $d): ?>
            <tr>
                <td class="text-nowrap"><?= e($d['created_at']) ?></td><td><?= e($d['channel']) ?></td><td><?= e($d['subject']) ?></td>
                <td><span class="badge <?= e($statusBadge[$d['status']] ?? 'text-bg-secondary') ?>"><?= e($d['status']) ?></span><?php if ($d['last_error'] !== ''): ?><div class="text-danger"><?= e($d['last_error']) ?></div><?php endif; ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>
