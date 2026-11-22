<?php

declare(strict_types=1);

namespace Sentinel\Dashboard;

/**
 * Small server-side SVG charts for the dashboards (no JavaScript chart
 * library, nothing loaded from elsewhere): a risk gauge, a Fail/Warning
 * trend and horizontal bars.
 *
 * Colours come from CSS classes (theme tokens), so the charts follow the
 * dark and light themes. Every chart has role="img" and a text label; the
 * numbers are also printed next to it, so nothing depends on colour alone.
 *
 * Security assumptions: numeric inputs are cast to int; any text is escaped with e().
 */
final class Svg
{
    /** A 240-degree gauge for a 0-100 risk score. */
    public static function gauge(int $score, string $level, string $label): string
    {
        $score = max(0, min(100, $score));
        $cx = 100;
        $cy = 100;
        $r = 80;
        $arc = static function (float $from, float $to) use ($cx, $cy, $r): string {
            // Angles in degrees, 0 = straight up, clockwise; the gauge runs from -120 to +120.
            $p = static fn (float $a): array => [$cx + $r * sin(deg2rad($a)), $cy - $r * cos(deg2rad($a))];
            [$x1, $y1] = $p($from);
            [$x2, $y2] = $p($to);
            return sprintf('M %.2f %.2f A %d %d 0 %d 1 %.2f %.2f', $x1, $y1, $r, $r, ($to - $from) > 180 ? 1 : 0, $x2, $y2);
        };
        $end = -120 + 240 * $score / 100;
        $ticks = '';
        foreach ([0, 25, 50, 75, 100] as $t) {
            $a = deg2rad(-120 + 240 * $t / 100);
            $ticks .= sprintf('<line class="g-tick" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>', $cx + 66 * sin($a), $cy - 66 * cos($a), $cx + 72 * sin($a), $cy - 72 * cos($a));
        }
        $out = '<svg class="gauge gauge-' . e($level) . '" viewBox="0 0 200 170" role="img" aria-label="' . e($label . ': ' . $score . ' / 100') . '" xmlns="http://www.w3.org/2000/svg">';
        $out .= '<path class="g-track" d="' . $arc(-120, 120) . '"/>';
        if ($score > 0) {
            $out .= '<path class="g-value" pathLength="100" d="' . $arc(-120, max(-119.5, $end)) . '"/>';
        }
        $out .= $ticks;
        $out .= '<text class="g-num" x="100" y="108" text-anchor="middle">' . $score . '</text>';
        $out .= '<text class="g-cap" x="100" y="130" text-anchor="middle">' . e(__('RISK / 100')) . '</text>';
        return $out . '</svg>';
    }

    /**
     * Fail and Warning lines over time (area under Fail), with the latest values labelled.
     *
     * @param list<array{day:string, fail:int, warn:int}> $points
     */
    public static function trend(array $points, string $label): string
    {
        $w = 600;
        $h = 180;
        $l = 34;
        $r = 12;
        $t = 14;
        $b = 26;
        $n = count($points);
        $max = max(1, ...array_map(static fn (array $p): int => max($p['fail'], $p['warn']), $points));
        $x = static fn (int $i): float => $n <= 1 ? $l + ($w - $l - $r) : $l + $i * ($w - $l - $r) / ($n - 1);
        $y = static fn (int $v): float => $t + ($h - $t - $b) * (1 - $v / $max);
        $out = '<svg class="trend" viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . e($label) . '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none">';
        foreach ([0, 0.5, 1] as $f) {
            $gy = $t + ($h - $t - $b) * $f;
            $out .= sprintf('<line class="t-grid" x1="%d" y1="%.1f" x2="%d" y2="%.1f"/>', $l, $gy, $w - $r, $gy);
            $out .= sprintf('<text class="t-axis" x="%d" y="%.1f" text-anchor="end">%d</text>', $l - 6, $gy + 4, (int) round($max * (1 - $f)));
        }
        foreach (['warn' => 't-warn', 'fail' => 't-fail'] as $key => $cls) {
            $pts = [];
            foreach ($points as $i => $p) {
                $pts[] = sprintf('%.1f,%.1f', $x($i), $y((int) $p[$key]));
            }
            if ($n === 1) {
                $pts[] = sprintf('%.1f,%.1f', $x(0) - 1, $y((int) $points[0][$key]));
            }
            if ($key === 'fail') {
                $out .= '<polygon class="t-fail-area" points="' . sprintf('%.1f,%.1f ', $x(0), $y(0)) . implode(' ', $pts) . sprintf(' %.1f,%.1f', $x($n - 1), $y(0)) . '"/>';
            }
            $out .= '<polyline class="' . $cls . '" points="' . implode(' ', $pts) . '"/>';
            $last = $points[$n - 1];
            $out .= sprintf('<circle class="%s-dot" cx="%.1f" cy="%.1f" r="4"/>', $cls, $x($n - 1), $y((int) $last[$key]));
        }
        if ($n > 1) {
            $out .= sprintf('<text class="t-axis" x="%d" y="%d">%s</text>', $l, $h - 6, e(substr($points[0]['day'], 5)));
        }
        $out .= sprintf('<text class="t-axis" x="%d" y="%d" text-anchor="end">%s</text>', $w - $r, $h - 6, e(__('today')));
        return $out . '</svg>';
    }

    /**
     * Horizontal bars with the count written at the end of each bar.
     *
     * @param list<array{label:string, count:int, risk:bool}> $rows
     */
    public static function bars(array $rows, string $label): string
    {
        $max = max(1, ...array_map(static fn (array $r): int => $r['count'], $rows));
        $rowH = 26;
        $h = $rowH * count($rows);
        $out = '<svg class="bars" viewBox="0 0 400 ' . $h . '" role="img" aria-label="' . e($label) . '" xmlns="http://www.w3.org/2000/svg">';
        foreach ($rows as $i => $row) {
            $y = $i * $rowH;
            $bw = 220 * $row['count'] / $max;
            $out .= sprintf('<text class="b-label" x="0" y="%d">%s</text>', $y + 17, e($row['label']));
            $out .= sprintf('<rect class="b-track" x="130" y="%d" width="220" height="12"/>', $y + 7);
            if ($row['count'] > 0) {
                $out .= sprintf('<rect class="%s" x="130" y="%d" width="%.1f" height="12"/>', $row['risk'] ? 'b-risk' : 'b-bar', $y + 7, max(2, $bw));
            }
            $out .= sprintf('<text class="b-num" x="358" y="%d">%d</text>', $y + 17, (int) $row['count']);
        }
        return $out . '</svg>';
    }
}
