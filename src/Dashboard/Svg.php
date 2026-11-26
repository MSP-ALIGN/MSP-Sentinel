<?php

declare(strict_types=1);

namespace Sentinel\Dashboard;

/**
 * Small server-side SVG charts for the dashboards (no JavaScript chart
 * library, nothing loaded from elsewhere): a risk gauge, the dashboard's sonar
 * (1.57), a Fail/Warning trend and horizontal bars.
 *
 * Colours come from CSS classes (theme tokens), so the charts follow the
 * dark and light themes. Every chart has role="img" and a text label; the
 * numbers are also printed next to it, so nothing depends on colour alone.
 *
 * Security assumptions: numeric inputs are cast to int; any text is escaped with e().
 */
final class Svg
{
    /** At most this many clients are drawn on the sonar (worst first); the rest are counted below it. */
    public const SONAR_MAX = 60;

    /**
     * The main dashboard's sonar (1.57): every client is a dot in the band of its level (red core = at risk, amber =
     * needs attention, green rim = good); within its band, the higher its score, the closer to the center. Clients are
     * spaced evenly around the scope in ID order (1.57.1), so dots keep their place between refreshes and never overlap,
     * and each links to the client with its name, level and score as the hover text. The sweep turns and each dot pings as it passes;
     * both are CSS animations in theme.css (class sn-d0..sn-d23 = the dot's 15-degree slice), with no inline style or
     * script (strict CSP), and both stop for people who prefer reduced motion.
     *
     * Untrusted: client names (escaped with e()). Numbers are cast to int.
     *
     * @param list<array{id:int, name:string, score:int, level:string}> $clients worst first (DashboardData::clients)
     * @param array<string,string> $levelWords level => word for the hover text
     */
    public static function sonar(array $clients, int $centerScore, string $centerLevel, string $label, array $levelWords): string
    {
        $c = 150;
        $r = 130;
        // Bands as fractions of the radius: risk 0-0.4, attention 0.4-0.7, good 0.7-1 (the dot stays inside its band).
        // The risk band starts outside the center disc (r 24 = 0.185), so even a score of 100 is never hidden behind it.
        $bands = ['risk' => [0.25, 0.37], 'attention' => [0.44, 0.67], 'good' => [0.74, 0.95]];
        $out = '<svg class="sonar" viewBox="0 0 300 300" role="img" aria-label="' . e($label) . '" xmlns="http://www.w3.org/2000/svg">';
        $out .= '<circle class="sn-band sn-good" cx="150" cy="150" r="130"/><circle class="sn-band sn-attention" cx="150" cy="150" r="91"/>'
            . '<circle class="sn-band sn-risk" cx="150" cy="150" r="52"/>';
        foreach ([130, 91, 52] as $i => $rr) {
            $out .= '<circle class="sn-ring' . ($i === 0 ? ' sn-ring-outer' : '') . '" cx="150" cy="150" r="' . $rr . '"/>';
        }
        $out .= '<line class="sn-cross" x1="20" y1="150" x2="280" y2="150"/><line class="sn-cross" x1="150" y1="20" x2="150" y2="280"/>';
        for ($a = 0; $a < 360; $a += 15) {
            $t = deg2rad($a);
            $len = $a % 45 === 0 ? 8 : 4;
            $out .= sprintf('<line class="sn-tick" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>', $c + $r * sin($t), $c - $r * cos($t), $c + ($r - $len) * sin($t), $c - ($r - $len) * cos($t));
        }
        // The sweep: a 50-degree wedge trailing a bright edge, pointing up; the group turns (CSS).
        $tail = deg2rad(-50);
        $out .= '<g class="sn-sweep"><path class="sn-wedge" d="M150 150 L' . sprintf('%.1f %.1f', $c + $r * sin($tail), $c - $r * cos($tail)) . ' A130 130 0 0 1 150 20 Z"/>'
            . '<line class="sn-edge" x1="150" y1="150" x2="150" y2="20"/></g>';
        // Band labels left of the vertical axis; the first dot is placed just right of it (7 degrees).
        $out .= '<text class="sn-lbl" x="146" y="110" text-anchor="end">' . e(__('RISK')) . '</text><text class="sn-lbl" x="146" y="71" text-anchor="end">' . e(__('ATTENTION')) . '</text>'
            . '<text class="sn-lbl" x="146" y="32" text-anchor="end">' . e(__('GOOD')) . '</text>';
        $drawn = array_slice($clients, 0, self::SONAR_MAX);
        // 1.57.1: clients are spread evenly around the scope in ID order (a stable order: dots only move when a client is
        // added or removed), and neighbours are staggered across three depths of their band, so dots never sit on top of
        // each other, also when many share a score (Good clients score 0-14 and many share one).
        $ids = array_map(static fn (array $x): int => (int) $x['id'], $drawn);
        sort($ids);
        $slot = array_flip($ids);
        $n = max(1, count($ids));
        foreach ($drawn as $cl) {
            $level = isset($bands[$cl['level']]) ? $cl['level'] : 'good';
            [$lo, $hi] = $bands[$level];
            $score = max(0, min(100, (int) $cl['score']));
            $pos = $slot[(int) $cl['id']];
            $depth = ($pos % 3) / 2; // 0, 0.5 or 1 across the band
            $dist = $r * ($hi - ($hi - $lo) * ($level === 'good' ? $depth : 0.6 * $score / 100 + 0.4 * $depth));
            $angle = fmod($pos * 360.0 / $n + 7.0, 360.0); // 7 degrees off, so no dot sits on the band labels
            $t = deg2rad($angle);
            $x = $c + $dist * sin($t);
            $y = $c - $dist * cos($t);
            // The ping fires as the sweep's edge reaches the dot, never before it (end of the dot's 15-degree slice).
            $slice = (int) ceil($angle / 15) % 24;
            $title = $cl['name'] . ' · ' . ($levelWords[$level] ?? $level) . ' · ' . $score . '%';
            // A mouse shortcut only (1.57.1): the svg is one image to screen readers, and the client risk grid next to it
            // links every client for the keyboard, so the dots are left out of the tab order.
            $out .= '<a href="' . e(url('/clients/' . (int) $cl['id'])) . '" class="sn-dot sn-' . $level . '" tabindex="-1"><title>' . e($title) . '</title>'
                . sprintf('<circle class="sn-ping sn-d%d" cx="%.1f" cy="%.1f" r="6"/><circle class="sn-blip" cx="%.1f" cy="%.1f" r="%.1f"/>', $slice, $x, $y, $x, $y, $level === 'risk' ? 6.5 : 5.5)
                . '</a>';
        }
        $out .= '<circle class="sn-core" cx="150" cy="150" r="24"/>';
        $out .= '<text class="sn-num sn-num-' . e($centerLevel) . '" x="150" y="157" text-anchor="middle">' . max(0, min(100, $centerScore)) . '</text>';
        return $out . '</svg>';
    }

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
        $first = $points[0];
        $last = $points[$n - 1];
        $spoken = $label . ': ' . __('now {f} Fail and {w} Warning; {d}: {f0} Fail and {w0} Warning', ['f' => $last['fail'], 'w' => $last['warn'], 'd' => $first['day'], 'f0' => $first['fail'], 'w0' => $first['warn']]);
        $out = '<svg class="trend" viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . e($spoken) . '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">';
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
     * Risk score over time (1.62): a 0-100 line over the three level bands (Good 0-14, Needs attention 15-49, At risk
     * 50-100), placed by date so gaps show as gaps in time. Estimated days (before exact scores were recorded) are
     * drawn dashed; exact days solid. The first and last scores are written on the chart, and the label says them too.
     * Classes only (no inline styles), so it works under the app's CSP and in report documents.
     *
     * @param list<array{day:string, score:int, level:string, estimated:bool}> $points oldest first, at least one
     */
    public static function scoreHistory(array $points, string $label, int $days): string
    {
        $w = 600;
        $h = 190;
        $l = 34;
        $r = 34;
        $t = 10;
        $b = 24;
        $end = strtotime(gmdate('Y-m-d') . ' 00:00:00 UTC');
        $start = $end - max(1, $days) * 86400;
        $x = static fn (string $day): float => $l + ($w - $l - $r) * max(0, min(1, (strtotime($day . ' 00:00:00 UTC') - $start) / max(1, $end - $start)));
        $y = static fn (int $v): float => $t + ($h - $t - $b) * (1 - max(0, min(100, $v)) / 100);
        $first = $points[0];
        $last = $points[count($points) - 1];
        $spoken = $label . ': ' . __('now {s}; {d}: {s0}', ['s' => $last['score'], 'd' => $first['day'], 's0' => $first['score']])
            . ($first['estimated'] ? ' (' . __('estimated') . ')' : '');
        $out = '<svg class="score-history" viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . e($spoken) . '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">';
        // Level bands behind the line.
        foreach ([['sh-band-risk', 100, 50], ['sh-band-attention', 50, 15], ['sh-band-good', 15, 0]] as [$cls, $top, $bottom]) {
            $out .= sprintf('<rect class="%s" x="%d" y="%.1f" width="%d" height="%.1f"/>', $cls, $l, $y($top), $w - $l - $r, $y($bottom) - $y($top));
        }
        foreach ([0, 15, 50, 100] as $v) {
            $out .= sprintf('<text class="sh-axis" x="%d" y="%.1f" text-anchor="end">%d</text>', $l - 6, $y($v) + 4, $v);
        }
        // Estimated part dashed, exact part solid; the dashed part runs up to the first exact point so the line is unbroken.
        $est = [];
        $exact = [];
        foreach ($points as $p) {
            $xy = sprintf('%.1f,%.1f', $x($p['day']), $y($p['score']));
            if ($p['estimated']) {
                $est[] = $xy;
            } else {
                if ($exact === [] && $est !== []) {
                    $est[] = $xy;
                }
                $exact[] = $xy;
            }
        }
        if (count($est) > 1) {
            $out .= '<polyline class="sh-line sh-est" points="' . implode(' ', $est) . '"/>';
        }
        if (count($exact) > 1) {
            $out .= '<polyline class="sh-line" points="' . implode(' ', $exact) . '"/>';
        }
        $out .= sprintf('<circle class="sh-dot sh-%s" cx="%.1f" cy="%.1f" r="5"/>', e($last['level']), $x($last['day']), $y($last['score']));
        $out .= sprintf('<text class="sh-val" x="%.1f" y="%.1f">%d</text>', $x($last['day']) + 8, $y($last['score']) + 4, $last['score']);
        if (count($points) > 1) {
            $out .= sprintf('<text class="sh-val sh-val-first" x="%.1f" y="%.1f" text-anchor="middle">%d</text>', $x($first['day']), max(12.0, $y($first['score']) - 8), $first['score']);
        }
        $out .= sprintf('<text class="sh-axis" x="%d" y="%d">%s</text>', $l, $h - 6, e(gmdate('Y-m-d', $start)));
        $out .= sprintf('<text class="sh-axis" x="%d" y="%d" text-anchor="end">%s</text>', $w - $r, $h - 6, e(__('today')));
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
        $spoken = implode(', ', array_map(static fn (array $r): string => $r['label'] . ' ' . (int) $r['count'], $rows));
        $out = '<svg class="bars" viewBox="0 0 400 ' . $h . '" role="img" aria-label="' . e($label . ': ' . $spoken) . '" xmlns="http://www.w3.org/2000/svg">';
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
