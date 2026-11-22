<?php
/**
 * Helpers for finding severity and status badges (colour + icon + text, never colour alone).
 * Defines $findingSeverityBadge(string), $findingStatusBadge(string, bool $reappeared) and
 * $findingDueBadge(array $finding): overdue / due soon / due date, for open findings only ('' otherwise).
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
$findingDueBadge = static function (array $f): string {
    if (($f['status'] ?? '') !== 'open' || empty($f['due_at'])) {
        return '';
    }
    $due = (int) strtotime($f['due_at'] . ' UTC');
    $days = (int) floor(($due - time()) / 86400);
    if ($due < time()) {
        $late = max(1, (int) floor((time() - $due) / 86400)); // whole days late (at least 1)
        return '<span class="badge text-bg-danger"><i class="bi bi-alarm me-1" aria-hidden="true"></i>' . e(__('Overdue {n} day(s)', ['n' => $late])) . '</span>';
    }
    if ($due < time() + \Sentinel\Findings\FixWorkflow::DUE_SOON_DAYS * 86400) {
        return '<span class="badge text-bg-warning"><i class="bi bi-hourglass-split me-1" aria-hidden="true"></i>' . e(__('Due {date}', ['date' => gmdate('Y-m-d', $due)])) . '</span>';
    }
    return '<span class="badge text-bg-light border"><i class="bi bi-calendar-event me-1" aria-hidden="true"></i>' . e(__('Due {date}', ['date' => gmdate('Y-m-d', $due)])) . '</span>';
};
