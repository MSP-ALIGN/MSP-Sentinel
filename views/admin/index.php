<?php
/**
 * Administration overview: one card per area with its key status, only the areas the user may open (1.40.1).
 * Expects: $inventoryOn (labels of the connected inventory sources, 1.52), $users, $email, $webhook, $tokens, $events, $problems, $warnings, $newer, $audit. Every value is escaped.
 */
$card = static function (string $href, string $icon, string $title, string $status, string $state, string $text): string {
    return '<a class="admin-card hud" href="' . e(url($href)) . '"><span class="admin-card-icon"><i class="bi ' . e($icon) . '" aria-hidden="true"></i></span>'
        . '<span class="admin-card-body"><span class="admin-card-title">' . e($title) . '</span>'
        . '<span class="admin-card-status is-' . e($state) . '">' . e($status) . '</span>'
        . '<span class="admin-card-text">' . e($text) . '</span></span></a>';
};
$everyClient = ($currentUser['client_ids'] ?? null) === null; // org-wide areas need every client (1.42.1)
?>
<p class="text-body-secondary mb-3"><?= e(__('Manage who can use Sentinel and how it runs. Your day-to-day work stays in the main menu.')) ?></p>
<div class="admin-cards">
    <?php if (can('users.manage')): ?><?= $card('/users', 'bi-people', __('Users'), __('{n} active · {a} Admin(s)', ['n' => $users['active'], 'a' => $users['admins']]), 'ok', __('Add users, give them roles, reset passwords and two-factor authentication, deactivate leavers.')) ?><?php endif; ?>
    <?php if (can('users.manage')): ?><?= $card('/admin/roles', 'bi-shield-lock', __('Roles'), __('Built-in and your own'), 'ok', __('What each role may do, and which clients a role sees.')) ?><?php endif; ?>
    <?php if (can('settings.manage') && $everyClient): ?><?= $card('/admin/settings', 'bi-gear', __('Settings'), ($email ? __('Email on') : __('Email off')) . ' · ' . ($webhook ? __('Webhook on') : __('Webhook off')), $email ? 'ok' : 'warn', __('Product name and time zone, alerts (email, Teams, Slack), fix due dates, pen-test engagement approval, report branding, vulnerability data.')) ?><?php endif; ?>
    <?php if (can('integrations.manage') && $everyClient): ?><?= $card('/admin/integrations', 'bi-puzzle', __('Integrations'), $inventoryOn !== [] ? __('{list} on', ['list' => implode(', ', $inventoryOn)]) : __('No RMM connected'), 'ok', __('ITFlow (clients and tickets), NinjaOne (devices), MSP Align (compliance), breach monitoring and Sign in with Microsoft.')) ?><?php endif; ?>
    <?php if (can('api.manage')): ?><?= $card('/admin/api', 'bi-plug', __('API'), __('{n} active token(s)', ['n' => $tokens]) . ' · ' . ($events ? __('Events on') : __('Events off')), 'ok', __('Tokens for MSP Align and other tools, and signed outbound events.')) ?><?php endif; ?>
    <?php if ((can('system.manage') || can('release.manage')) && $everyClient): ?><?= $card('/admin/system', 'bi-heart-pulse', __('System'), $problems > 0 ? __('{n} problem(s)', ['n' => $problems]) : ($warnings > 0 ? __('{n} warning(s)', ['n' => $warnings]) : __('Healthy')), $problems > 0 ? 'bad' : ($warnings > 0 ? 'warn' : 'ok'), $newer !== null ? __('Version {v} is available.', ['v' => $newer]) : __('Health checks, updates and data retention.')) ?><?php endif; ?>
    <?php if (can('audit.view') && $everyClient): ?><?= $card('/admin/audit', 'bi-journal-text', __('Audit log'), __('{n} entries in the last day', ['n' => $audit]), 'ok', __('Who did what, when and from where. Never deleted.')) ?><?php endif; ?>
</div>
