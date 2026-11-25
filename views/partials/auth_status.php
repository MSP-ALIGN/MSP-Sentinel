<?php
/**
 * Badge for an authorisation status. Expects: $status ('active'|'scheduled'|'expired'|'revoked'|'none').
 * Each status has a label and an icon as well as a colour (never colour alone).
 */
$badges = [
    'active' => ['text-bg-success', 'bi-check-circle', __('Active')],
    'scheduled' => ['text-bg-info', 'bi-calendar-event', __('Starts later')],
    'expired' => ['text-bg-warning', 'bi-calendar-x', __('Expired')],
    'revoked' => ['text-bg-secondary', 'bi-x-circle', __('Revoked')],
    'none' => ['text-bg-danger', 'bi-exclamation-triangle', __('No authorization')],
];
[$badgeClass, $badgeIcon, $badgeLabel] = $badges[$status] ?? $badges['none'];
?>
<span class="badge <?= e($badgeClass) ?>"><i class="bi <?= e($badgeIcon) ?> me-1" aria-hidden="true"></i><?= e($badgeLabel) ?></span>
