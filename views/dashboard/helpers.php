<?php
/**
 * Small display helpers shared by the dashboard panels (included once per render).
 * Every value they print is escaped.
 */
$levelWord ??= static fn (string $l): string => ['risk' => __('At risk'), 'attention' => __('Needs attention'), 'good' => __('Good')][$l] ?? $l;
$levelIcon ??= static fn (string $l): string => ['risk' => 'bi-x-octagon', 'attention' => 'bi-exclamation-triangle', 'good' => 'bi-check-circle'][$l] ?? 'bi-circle';
$ago ??= static function (?int $seconds): string {
    if ($seconds === null) {
        return __('never');
    }
    return match (true) {
        $seconds < 90 => __('just now'),
        $seconds < 5400 => __('{n} min ago', ['n' => (int) round($seconds / 60)]),
        $seconds < 172800 => __('{n} h ago', ['n' => (int) round($seconds / 3600)]),
        default => __('{n} days ago', ['n' => (int) round($seconds / 86400)]),
    };
};
$duration ??= static function (int $seconds): string {
    $h = intdiv($seconds, 3600);
    $m = intdiv($seconds % 3600, 60);
    return $h > 0 ? __('{h} h {m} min', ['h' => $h, 'm' => $m]) : __('{m} min', ['m' => max(1, $m)]);
};
$eventWord ??= static fn (string $k): string => [
    'opened' => __('New'), 'reopened' => __('Back'), 'resolved' => __('Resolved'), 'triaged_accepted' => __('Accepted'),
    'triaged_false_positive' => __('False positive'), 'triaged_open' => __('Reopened'), 'scan_done' => __('Scan done'),
    'scan_partial' => __('Scan partial'), 'scan_failed' => __('Scan failed'), 'scan_cancelled' => __('Scan canceled'),
][$k] ?? $k;
$eventClass ??= static fn (string $k, ?string $sev): string => match (true) {
    $k === 'resolved' => 'ev-ok', $k === 'scan_failed' => 'ev-bad', str_starts_with($k, 'scan_') => 'ev-scan',
    str_starts_with($k, 'triaged_') => 'ev-triage', $sev === 'fail' => 'ev-bad', default => 'ev-warn',
};
