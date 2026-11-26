<?php

declare(strict_types=1);

namespace Sentinel\Reports;

/**
 * The shared look of every report document (1.59): executive summary, technical findings, pen-test report and retest
 * letter. One stylesheet, a cover page, a risk-score gauge, the contact block and the sign-off, so all documents carry
 * the same branding.
 *
 * Print: the cover is a full page with no margins (named page "cover"); other pages carry a running header (the
 * confidential label) and footer (brand, document, page X of Y) in the page margins, which browsers that support CSS
 * page margin boxes print (Chrome and Edge 131+); others print without them. On screen each part looks like a sheet.
 *
 * Untrusted: every brand value (an admin typed it) and every client or report value. HTML output is escaped with e().
 * The only values placed in CSS are colors that match #rrggbb (else the default), the paper size (A4 or Letter) and
 * text in margin boxes, which goes through cssString(): every character except letters, digits and spaces is written
 * as a CSS escape, so nothing can end the string, the rule or the <style> element.
 */
final class ReportTheme
{
    public const DEFAULT_COLOR = '#1f4e79';
    public const DEFAULT_ACCENT = '#5aa9e6';
    public const CONFIDENTIAL_DEFAULT = 'Confidential: prepared for {client}';

    /** Brand text fields with their defaults (older snapshots lack the 1.59 ones). */
    private const TEXT = ['name' => '', 'footer' => '', 'address' => '', 'phone' => '', 'email' => '', 'website' => '',
        'prepared_by' => '', 'prepared_title' => '', 'signoff' => '', 'confidential' => '', 'logo' => ''];

    /**
     * The brand with every key present and every CSS-bound value checked: colors #rrggbb (else the defaults), cover
     * 'color' or 'white', paper 'A4' or 'Letter'. Text stays as typed (escaped on output).
     *
     * @param array<string,mixed> $b ReportBuilder::brand() or an older snapshot's brand.
     * @return array<string,mixed>
     */
    public static function brand(array $b): array
    {
        $out = [];
        foreach (self::TEXT as $k => $default) {
            $out[$k] = is_string($b[$k] ?? null) ? $b[$k] : $default;
        }
        $hex = static fn ($v, string $d): string => is_string($v) && preg_match('/^#[0-9a-f]{6}$/i', $v) ? strtolower($v) : $d;
        $out['color'] = $hex($b['color'] ?? null, self::DEFAULT_COLOR);
        $out['accent'] = $hex($b['accent'] ?? null, self::DEFAULT_ACCENT);
        $out['cover'] = ($b['cover'] ?? 'color') === 'white' ? 'white' : 'color';
        $out['paper'] = ($b['paper'] ?? 'A4') === 'Letter' ? 'Letter' : 'A4';
        $out['powered_by'] = !empty($b['powered_by']);
        return $out;
    }

    /**
     * A quoted CSS string that shows $text literally. Every character other than ASCII letters, digits and spaces is a
     * 6-digit hex escape, so quotes, backslashes, "<" and line breaks can never end the string or the stylesheet.
     */
    public static function cssString(string $text): string
    {
        $text = mb_substr((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', mb_check_encoding($text, 'UTF-8') ? $text : ''), 0, 200);
        $out = '';
        foreach (mb_str_split($text) as $ch) {
            $out .= preg_match('/^[A-Za-z0-9 ]$/', $ch) ? $ch : sprintf('\\%06X', mb_ord($ch));
        }
        return '"' . $out . '"';
    }

    /** The confidential label for one client ('' when the admin left it empty). */
    public static function confidential(array $brand, string $client): string
    {
        return trim(str_replace('{client}', $client, (string) $brand['confidential']));
    }

    /**
     * The stylesheet (without the <style> tags). $footer is the running footer text, $header the running header text;
     * both are plain text (escaped for CSS here).
     *
     * @param array<string,mixed> $b brand() output.
     */
    public static function css(array $b, string $footer, string $header): string
    {
        $b = self::brand($b);
        [$w, $h] = $b['paper'] === 'Letter' ? ['215.9mm', '279.4mm'] : ['210mm', '297mm'];
        $foot = self::cssString($footer);
        $head = self::cssString($header);
        $pageWord = self::cssString(__('Page') . ' ');
        $ofWord = self::cssString(' ' . __('of') . ' ');
        return <<<CSS
@page { size: {$b['paper']}; margin: 20mm 16mm 20mm;
  @top-left { content: {$head}; font: 8pt "Segoe UI", Roboto, Arial, sans-serif; color: #6b7480; vertical-align: bottom; padding-bottom: 4mm; }
  @bottom-left { content: {$foot}; font: 8pt "Segoe UI", Roboto, Arial, sans-serif; color: #6b7480; vertical-align: top; padding-top: 4mm; }
  @bottom-right { content: {$pageWord} counter(page) {$ofWord} counter(pages); font: 8pt "Segoe UI", Roboto, Arial, sans-serif; color: #6b7480; vertical-align: top; padding-top: 4mm; }
}
@page cover { margin: 0; @top-left { content: none; } @bottom-left { content: none; } @bottom-right { content: none; } }
:root { --brand: {$b['color']}; --accent: {$b['accent']}; --ink: #1b2430; --muted: #5d6673; --line: #dde1e7; --soft: #f4f6f9;
  --fail: #b00020; --warn: #a15c00; --ok: #1b6e3a; --paper-w: {$w}; --paper-h: {$h}; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font: 10pt/1.5 "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: var(--ink); background: #fff; counter-reset: sec; }
.muted { color: var(--muted); } .small { font-size: 8.5pt; } .label { font-weight: 600; } .nowrap { white-space: nowrap; } .pre { white-space: pre-line; }
.c-fail { color: var(--fail); } .c-warn { color: var(--warn); } .c-ok { color: var(--ok); }
h1, h2, h3 { color: var(--ink); line-height: 1.25; }
h1 { font-size: 22pt; margin: 0 0 4px; font-weight: 700; letter-spacing: -.01em; }
h2 { font-size: 14pt; margin: 26px 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--line); break-after: avoid; page-break-after: avoid; }
h2.sec::before { counter-increment: sec; content: counter(sec, decimal-leading-zero); color: var(--accent); font-weight: 700; margin-right: 10px; }
h3 { font-size: 11pt; margin: 16px 0 6px; break-after: avoid; page-break-after: avoid; }
.eyebrow { font-size: 8pt; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; color: var(--accent); margin: 0 0 6px; }
/* Cover */
.cover { page: cover; position: relative; width: var(--paper-w); height: calc(var(--paper-h) - 1mm); overflow: hidden; break-after: page; page-break-after: always;
  display: flex; flex-direction: column; padding: 22mm 20mm 18mm; color: #fff; background: var(--brand); }
.cover::before { content: ""; position: absolute; right: -40mm; top: -30mm; width: 140mm; height: 140mm; border-radius: 50%; border: 18mm solid rgba(255,255,255,.06); }
.cover::after { content: ""; position: absolute; left: 0; bottom: 0; width: 100%; height: 5mm; background: var(--accent); }
.cover .brandrow { display: flex; align-items: center; gap: 14px; position: relative; }
.cover .plate { background: #fff; border-radius: 8px; padding: 8px 12px; display: inline-flex; }
.cover .plate img { max-height: 46px; max-width: 190px; display: block; }
.cover .bname { font-size: 13pt; font-weight: 600; }
.cover .middle { margin-top: auto; position: relative; }
.cover .eyebrow { color: var(--accent); }
.cover .title { color: inherit; font-size: 30pt; font-weight: 700; line-height: 1.1; margin: 0 0 10px; letter-spacing: -.015em; }
.cover .client { font-size: 17pt; font-weight: 400; margin: 0 0 4px; opacity: .95; }
.cover .period { font-size: 10.5pt; opacity: .8; margin: 0; }
.cover .scorecard { display: flex; align-items: center; gap: 16px; margin-top: 16mm; padding: 10px 16px 10px 10px; border-radius: 10px; background: rgba(255,255,255,.1); width: max-content; max-width: 100%; }
.cover .scorecard .gauge { width: 150px; }
.cover .lvl { font-size: 15pt; font-weight: 700; }
.cover .lvl-note { font-size: 9pt; opacity: .85; max-width: 70mm; }
.cover .bottom { margin-top: auto; display: flex; gap: 12mm; align-items: flex-end; font-size: 8.5pt; position: relative; padding-bottom: 4mm; }
.cover .bottom > div:not(.conf) { max-width: 60mm; } .cover .bottom .d { white-space: nowrap; }
.cover .bottom .k { display: block; font-size: 7pt; letter-spacing: .14em; text-transform: uppercase; opacity: .7; margin-bottom: 2px; }
.cover .conf { margin-left: auto; text-align: right; font-weight: 600; letter-spacing: .04em; max-width: 70mm; }
.cover.white { background: #fff; color: var(--ink); border-top: 16mm solid var(--brand); }
.cover.white::before { border-color: var(--soft); }
.cover.white .scorecard { background: var(--soft); }
.cover.white .plate { padding: 0; }
.cover.white .title { color: var(--brand); }
.cover.white .bname { color: var(--brand); }
/* Gauge */
.gauge .trk { fill: none; stroke-width: 16; }
.gauge .g-good { stroke: #2f9e5b; } .gauge .g-attention { stroke: #e0a100; } .gauge .g-risk { stroke: #d6334a; }
.gauge .mark { fill: #fff; stroke: var(--ink); stroke-width: 3; }
.gauge .num { font: 700 34px "Segoe UI", Roboto, Arial, sans-serif; fill: currentColor; }
.gauge .cap { font: 600 9px "Segoe UI", Roboto, Arial, sans-serif; fill: currentColor; opacity: .75; letter-spacing: .12em; }
/* Content pages */
.sheet { max-width: 178mm; margin: 0 auto; }
.doc-head { display: flex; align-items: flex-end; gap: 12px; padding-bottom: 10px; margin-bottom: 14px; border-bottom: 3px solid var(--brand); }
.doc-head .who { margin-left: auto; text-align: right; }
.doc-head img { max-height: 34px; max-width: 150px; }
.glance { display: grid; grid-template-columns: 62mm 1fr; gap: 14px; align-items: center; background: var(--soft); border-radius: 10px; padding: 12px 16px; margin: 8px 0 12px; break-inside: avoid; }
.glance .gauge { width: 100%; color: var(--ink); }
.verdict { font-size: 16pt; font-weight: 700; margin: 0 0 4px; }
.verdict-risk { color: var(--fail); } .verdict-attention { color: var(--warn); } .verdict-good { color: var(--ok); }
.bands { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 8px; font-size: 8pt; color: var(--muted); }
.bands i { display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 4px; vertical-align: -1px; }
.bands .b-good { background: #2f9e5b; } .bands .b-attention { background: #e0a100; } .bands .b-risk { background: #d6334a; }
.tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 6px 0 4px; }
.tiles.three { grid-template-columns: repeat(3, 1fr); }
.tile { border: 1px solid var(--line); border-top: 3px solid var(--line); border-radius: 6px; padding: 8px 10px; break-inside: avoid; font-size: 8.5pt; color: var(--muted); }
.tile .n { font-size: 20pt; font-weight: 700; display: block; color: var(--ink); line-height: 1.15; }
.tile.t-fail { border-top-color: var(--fail); } .tile.t-fail .n { color: var(--fail); }
.tile.t-warn { border-top-color: var(--warn); } .tile.t-warn .n { color: var(--warn); }
.tile.t-ok { border-top-color: var(--ok); } .tile.t-ok .n { color: var(--ok); }
.tile.t-brand { border-top-color: var(--brand); }
.sev { font-weight: 700; font-size: 7.5pt; letter-spacing: .04em; padding: 1px 6px; border: 1.5px solid currentColor; border-radius: 3px; white-space: nowrap; }
.sev-fail { color: var(--fail); } .sev-warn { color: var(--warn); } .sev-info { color: var(--muted); }
.risk { border: 1px solid var(--line); border-left: 4px solid var(--line); border-radius: 6px; padding: 9px 12px; margin: 10px 0; break-inside: avoid; }
.risk.fail { border-left-color: var(--fail); } .risk.warn { border-left-color: var(--warn); }
.risk h3 { margin: 0 0 4px; display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; font-size: 10.5pt; }
.risk p { margin: 3px 0; }
.rank { font-weight: 700; color: var(--accent); min-width: 1.6em; }
code { font-family: Consolas, "Liberation Mono", monospace; font-size: 8.5pt; background: var(--soft); padding: 0 3px; border-radius: 2px; overflow-wrap: anywhere; }
pre { font-family: Consolas, "Liberation Mono", monospace; font-size: 8pt; background: var(--soft); padding: 6px 8px; border-radius: 4px; white-space: pre-wrap; overflow-wrap: anywhere; margin: 4px 0; }
table.data { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 9pt; }
.data th, .data td { text-align: left; vertical-align: top; padding: 5px 7px; border-bottom: 1px solid var(--line); }
.data thead th { background: var(--brand); color: #fff; font-weight: 600; font-size: 8.5pt; }
.data tbody th { background: var(--soft); font-weight: 600; width: 26%; }
.data tr { break-inside: avoid; }
.chart { width: 100%; max-height: 66mm; }
.chart .axis { stroke: #8a929c; stroke-width: 1; } .chart .val { font-size: 11px; font-weight: 700; } .chart .lbl { font-size: 10px; fill: #5b6470; }
.legend span { margin-right: 14px; }
.note { background: var(--soft); border-left: 3px solid var(--accent); border-radius: 4px; padding: 8px 12px; break-inside: avoid; }
.asset { margin-top: 14px; } .asset > .label { break-after: avoid; page-break-after: avoid; color: var(--brand); }
.signoff { margin-top: 24px; padding: 14px 16px; border: 1px solid var(--line); border-radius: 10px; break-inside: avoid; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.signoff .sig { border-top: 1px solid var(--ink); padding-top: 4px; margin-top: 26px; max-width: 70mm; }
.contact { font-size: 8.5pt; color: var(--muted); }
.contact b { color: var(--ink); }
.doc-footer { display: none; }
/* Screen: each part looks like a sheet of paper; the running footer becomes a line at the end. */
@media screen {
  body { background: #e9ecf1; padding: 12px 0; }
  .cover { margin: 0 auto 14px; box-shadow: 0 2px 10px rgba(0,0,0,.18); max-width: 100%; height: auto; min-height: min(var(--paper-h), 150vw); }
  .sheet { background: #fff; padding: 16mm 16mm 18mm; box-shadow: 0 2px 10px rgba(0,0,0,.12); max-width: var(--paper-w); }
  .doc-footer { display: flex; gap: 12px; max-width: var(--paper-w); margin: 0 auto; padding: 8px 4px; font-size: 8pt; color: var(--muted); }
  .doc-footer .right { margin-left: auto; }
}
@media (max-width: 760px) {
  .cover { padding: 18px; } .cover .title { font-size: 22pt; } .cover .bottom { flex-wrap: wrap; gap: 10px; } .cover .conf { margin-left: 0; text-align: left; }
  .sheet { padding: 16px; } .tiles { grid-template-columns: repeat(2, 1fr); } .glance, .signoff { grid-template-columns: 1fr; }
}
@media print { a { color: inherit; text-decoration: none; } }
CSS;
    }

    /**
     * A half-circle gauge for a score of 0-100 with the three level bands (Good 0-14, Needs attention 15-49,
     * At risk 50-100) and a marker at the score. Accessible: role img with a text label; the number is printed too.
     */
    public static function gauge(int $score, string $levelWord): string
    {
        $score = max(0, min(100, $score));
        $pt = static function (float $v): string {
            $t = M_PI * (1 - $v / 100);
            return sprintf('%.2f %.2f', 100 + 80 * cos($t), 100 - 80 * sin($t));
        };
        $arc = static fn (float $a, float $b, string $cls): string => '<path class="trk ' . $cls . '" d="M' . $pt($a) . ' A80 80 0 0 1 ' . $pt($b) . '"/>';
        [$mx, $my] = explode(' ', $pt($score));
        return '<svg class="gauge" viewBox="0 0 200 118" role="img" aria-label="' . e(__('Risk score {s} of 100: {l}', ['s' => $score, 'l' => $levelWord])) . '">'
            . $arc(0, 14.6, 'g-good') . $arc(15.4, 49.6, 'g-attention') . $arc(50.4, 100, 'g-risk')
            . '<circle class="mark" cx="' . $mx . '" cy="' . $my . '" r="9"/>'
            . '<text class="num" x="100" y="96" text-anchor="middle">' . $score . '</text>'
            . '<text class="cap" x="100" y="114" text-anchor="middle">' . e(mb_strtoupper(__('Risk score'))) . '</text></svg>';
    }

    /** The legend under a gauge: what each band means. */
    public static function bands(): string
    {
        return '<div class="bands"><span><i class="b-good"></i>' . e(__('0-14 Good')) . '</span><span><i class="b-attention"></i>' . e(__('15-49 Needs attention'))
            . '</span><span><i class="b-risk"></i>' . e(__('50-100 At risk')) . '</span></div>';
    }

    /**
     * The cover page.
     *
     * @param array<string,mixed> $b brand() output.
     * @param array{eyebrow:string, title:string, client:string, period:string, date:string, score?:?int, level?:string, level_word?:string, level_note?:string} $o
     */
    public static function cover(array $b, array $o): string
    {
        $b = self::brand($b);
        $logo = str_starts_with($b['logo'], 'data:image/png;base64,') ? '<span class="plate"><img src="' . e($b['logo']) . '" alt="' . e($b['name']) . '"></span>' : '';
        $html = '<section class="cover' . ($b['cover'] === 'white' ? ' white' : '') . '">'
            . '<div class="brandrow">' . $logo . '<span class="bname">' . e($b['name']) . '</span></div>'
            . '<div class="middle"><p class="eyebrow">' . e($o['eyebrow']) . '</p><h1 class="title">' . e($o['title']) . '</h1>'
            . '<p class="client">' . e($o['client']) . '</p><p class="period">' . e($o['period']) . '</p>';
        if (isset($o['level_word']) && $o['level_word'] !== '') {
            $html .= '<div class="scorecard">' . (isset($o['score']) ? self::gauge((int) $o['score'], $o['level_word']) : '')
                . '<div><div class="lvl">' . e($o['level_word']) . '</div>'
                . (($o['level_note'] ?? '') !== '' ? '<div class="lvl-note">' . e($o['level_note']) . '</div>' : '') . '</div></div>';
        }
        $html .= '</div><div class="bottom">'
            . '<div><span class="k">' . e(__('Prepared for')) . '</span>' . e($o['client']) . '</div>'
            . '<div><span class="k">' . e(__('Prepared by')) . '</span>' . e($b['prepared_by'] !== '' ? $b['prepared_by'] . ', ' . $b['name'] : $b['name']) . '</div>'
            . '<div class="d"><span class="k">' . e(__('Date')) . '</span>' . e($o['date']) . '</div>';
        $conf = self::confidential($b, $o['client']);
        if ($conf !== '') {
            $html .= '<div class="conf">' . e($conf) . '</div>';
        }
        return $html . '</div></section>';
    }

    /** Small header at the top of the first content page: logo or name, and the document. */
    public static function docHead(array $b, string $title, string $sub): string
    {
        $b = self::brand($b);
        $mark = str_starts_with($b['logo'], 'data:image/png;base64,') ? '<img src="' . e($b['logo']) . '" alt="' . e($b['name']) . '">' : '<span class="label">' . e($b['name']) . '</span>';
        return '<header class="doc-head">' . $mark . '<div class="who small muted"><span class="label">' . e($title) . '</span><br>' . e($sub) . '</div></header>';
    }

    /** The contact block ('' when no contact details are set). */
    public static function contact(array $b): string
    {
        $b = self::brand($b);
        $lines = array_values(array_filter([$b['address'], $b['phone'], $b['email'], $b['website']], static fn (string $s): bool => trim($s) !== ''));
        if ($lines === []) {
            return '';
        }
        return '<div class="contact"><b>' . e($b['name']) . '</b><br><span class="pre">' . implode('<br>', array_map('e', $lines)) . '</span></div>';
    }

    /**
     * The sign-off on the last page: the closing note and who prepared the report, with the contact block.
     * Only what the admin filled in is shown; with nothing set, just the company name and the date.
     */
    public static function signoff(array $b, string $date): string
    {
        $b = self::brand($b);
        $left = '<div>' . ($b['signoff'] !== '' ? '<p class="pre">' . e($b['signoff']) . '</p>' : '<p>' . e(__('Questions about this report? Contact us and we will walk you through it.')) . '</p>')
            . '<div class="sig"><b>' . e($b['prepared_by'] !== '' ? $b['prepared_by'] : $b['name']) . '</b>'
            . ($b['prepared_title'] !== '' ? '<br><span class="small muted">' . e($b['prepared_title']) . '</span>' : '')
            . ($b['prepared_by'] !== '' ? '<br><span class="small muted">' . e($b['name']) . '</span>' : '')
            . '<br><span class="small muted">' . e($date) . '</span></div></div>';
        $contact = self::contact($b);
        return '<section class="signoff">' . $left . '<div>' . ($contact !== '' ? $contact : '') . '</div></section>';
    }

    /** The screen-only footer line (print shows the same text in the page margins). */
    public static function footer(array $b, string $leftText, string $rightText): string
    {
        return '<footer class="doc-footer"><span>' . e($leftText) . '</span><span class="right">' . e($rightText) . '</span></footer>';
    }
}
