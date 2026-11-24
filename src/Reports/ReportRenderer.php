<?php

declare(strict_types=1);

namespace Sentinel\Reports;

/**
 * Turns a report snapshot into one self-contained HTML document: inline CSS,
 * an inline SVG trend chart and the logo as a data: URI, so it can be saved,
 * emailed and printed to PDF without Sentinel.
 *
 * Security assumptions:
 * - Every snapshot value is untrusted and escaped with e() in the template.
 * - The only values placed in CSS are the brand colour (validated #rrggbb in
 *   ReportBuilder and here again) and the paper size (A4 or Letter).
 * - The document contains no scripts. It is served with a CSP that forbids them.
 */
final class ReportRenderer
{
    /** @param string $templateDir views/reports */
    public function __construct(private readonly string $templateDir)
    {
    }

    /** @param array<string,mixed> $r Snapshot from ReportBuilder::build(). */
    public function render(array $r): string
    {
        if (!preg_match('/^#[0-9a-f]{6}$/i', (string) $r['brand']['color'])) {
            $r['brand']['color'] = '#1f4e79';
        }
        $r['brand']['paper'] = $r['brand']['paper'] === 'Letter' ? 'Letter' : 'A4';
        $chart = self::trendChart($r['trend']);
        ob_start();
        try {
            (static function (array $r, string $chart, string $file): void {
                require $file;
            })($r, $chart, $this->templateDir . '/document.php');
            return (string) ob_get_clean();
        } catch (\Throwable $ex) {
            ob_end_clean();
            throw $ex;
        }
    }

    /**
     * An accessible SVG line chart of open Fail and Warning counts. Lines differ by
     * colour AND dash pattern AND marker shape, and every point carries its number,
     * so it reads in black and white.
     *
     * @param list<array{label:string, fail:int, warn:int}> $points
     */
    public static function trendChart(array $points): string
    {
        $w = 640;
        $h = 220;
        $left = 40;
        $right = 20;
        $top = 20;
        $bottom = 40;
        $n = count($points);
        $max = max(1, ...array_map(static fn (array $p): int => max($p['fail'], $p['warn']), $points));
        $x = static fn (int $i): float => $n === 1 ? ($left + ($w - $left - $right) / 2) : $left + $i * ($w - $left - $right) / ($n - 1);
        $y = static fn (int $v): float => $top + ($h - $top - $bottom) * (1 - $v / $max);
        $out = '<svg class="chart" viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . e(__('Open problems over time')) . '" xmlns="http://www.w3.org/2000/svg">';
        $out .= '<line x1="' . $left . '" y1="' . $y(0) . '" x2="' . ($w - $right) . '" y2="' . $y(0) . '" class="axis"/>';
        foreach (['warn' => ['#a15c00', '6 4', 'square'], 'fail' => ['#b00020', '', 'circle']] as $key => [$color, $dash, $shape]) {
            $pts = [];
            foreach ($points as $i => $p) {
                $pts[] = round($x($i), 1) . ',' . round($y($p[$key]), 1);
            }
            if ($n > 1) {
                $out .= '<polyline fill="none" stroke="' . $color . '" stroke-width="2.5"' . ($dash !== '' ? ' stroke-dasharray="' . $dash . '"' : '') . ' points="' . implode(' ', $pts) . '"/>';
            }
            foreach ($points as $i => $p) {
                $cx = round($x($i), 1);
                $cy = round($y($p[$key]), 1);
                $out .= $shape === 'circle'
                    ? '<circle cx="' . $cx . '" cy="' . $cy . '" r="4" fill="' . $color . '"/>'
                    : '<rect x="' . ($cx - 4) . '" y="' . ($cy - 4) . '" width="8" height="8" fill="' . $color . '"/>';
                $out .= '<text x="' . $cx . '" y="' . ($cy - 8) . '" text-anchor="middle" class="val" fill="' . $color . '">' . (int) $p[$key] . '</text>';
            }
        }
        foreach ($points as $i => $p) {
            $out .= '<text x="' . round($x($i), 1) . '" y="' . ($h - 15) . '" text-anchor="middle" class="lbl">' . e($p['label']) . '</text>';
        }
        return $out . '</svg>';
    }
}
