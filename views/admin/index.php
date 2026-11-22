<?php
/**
 * Administration overview (admins): one card per area with its key status.
 * Expects: $ninja (NinjaOne connected and on), $users, $email, $webhook, $tokens, $events, $problems, $warnings, $newer, $audit. Every value is escaped.
 */
$card = static function (string $href, string $icon, string $title, string $status, string $state, string $text): string {
    return '<a class="admin-card hud" href="' . e(url($href)) . '"><span class="admin-card-icon"><i class="bi ' . e($icon) . '" aria-hidden="true"></i></span>'
        . '<span class="admin-card-body"><span class="admin-card-title">' . e($title) . '</span>'
        . '<span class="admin-card-status is-' . e($state) . '">' . e($status) . '</span>'
        . '<span class="admin-card-text">' . e($text) . '</span></span></a>';
};
?>
<p class="text-body-secondary mb-3"><?= e(__('Manage who can use Sentinel and how it runs. Your day-to-day work stays in the main menu.')) ?></p>
<div class="admin-cards">
    <?= $card('/users', 'bi-people', __('Users'), __('{n} active · {a} admin(s)', ['n' => $users['active'], 'a' => $users['admins']]), 'ok', __('Add technicians and viewers, reset passwords and two-factor, deactivate leavers.')) ?>
    <?= $card('/admin/settings', 'bi-gear', __('Settings'), ($email ? __('Email on') : __('Email off')) . ' · ' . ($webhook ? __('webhook on') : __('webhook off')), $email ? 'ok' : 'warn', __('Product name, alerts (email, Teams, Slack), report branding.')) ?>
    <?= $card('/admin/integrations', 'bi-puzzle', __('Integrations'), $ninja ? __('NinjaOne on') : __('NinjaOne off'), 'ok', __('Read devices, software, patches and antivirus from NinjaOne.')) ?>
    <?= $card('/admin/api', 'bi-plug', __('API'), __('{n} active token(s)', ['n' => $tokens]) . ' · ' . ($events ? __('events on') : __('events off')), 'ok', __('Tokens for MSP Align and other tools, and signed outbound events.')) ?>
    <?= $card('/admin/system', 'bi-heart-pulse', __('System'), $problems > 0 ? __('{n} problem(s)', ['n' => $problems]) : ($warnings > 0 ? __('{n} warning(s)', ['n' => $warnings]) : __('Healthy')), $problems > 0 ? 'bad' : ($warnings > 0 ? 'warn' : 'ok'), $newer !== null ? __('Version {v} is available.', ['v' => $newer]) : __('Health checks, updates and data retention.')) ?>
    <?= $card('/admin/audit', 'bi-journal-text', __('Audit log'), __('{n} entries in the last day', ['n' => $audit]), 'ok', __('Who did what, when and from where. Never deleted.')) ?>
</div>
