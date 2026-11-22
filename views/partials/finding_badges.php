<?php
/**
 * Helpers for finding severity and status badges (colour + icon + text, never colour alone).
 * Defines $findingSeverityBadge(string) and $findingStatusBadge(string, bool $reappeared).
 */
$findingSeverityBadge = static function (string $severity): string {
    return $severity === 'fail'
        ? '<span class="badge text-bg-danger"><i class="bi bi-x-octagon me-1" aria-hidden="true"></i>' . e(__('Fail')) . '</span>'
        : '<span class="badge text-bg-warning"><i class="bi bi-exclamation-triangle me-1" aria-hidden="true"></i>' . e(__('Warning')) . '</span>';
};
$findingStatusBadge = static function (string $status, bool $reappeared = false): string {
    [$cls, $icon, $label] = match ($status) {
        'open' => ['text-bg-light border', 'bi-circle', __('Open')],
        'accepted' => ['text-bg-info', 'bi-hand-thumbs-up', __('Accepted risk')],
        'false_positive' => ['text-bg-secondary', 'bi-slash-circle', __('False positive')],
        default => ['text-bg-success', 'bi-check-circle', __('Resolved')],
    };
    return '<span class="badge ' . e($cls) . '"><i class="bi ' . e($icon) . ' me-1" aria-hidden="true"></i>' . e($label) . '</span>'
        . ($reappeared && $status !== 'resolved' ? ' <span class="badge text-bg-dark"><i class="bi bi-arrow-counterclockwise me-1" aria-hidden="true"></i>' . e(__('Reappeared')) . '</span>' : '');
};
