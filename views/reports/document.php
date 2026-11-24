<?php
/**
 * A complete, self-contained report document (executive summary or technical findings).
 * Expects: $r (snapshot from ReportBuilder), $chart (SVG built by ReportRenderer::trendChart).
 * Every snapshot value is untrusted and escaped with e(). No scripts.
 * Severity is never shown by colour alone: each mark has an icon and a word.
 */
$b = $r['brand'];
$c = $r['counts'];
$exec = $r['kind'] === 'executive';
$sev = static fn (string $s): string => $s === 'fail'
    ? '<span class="sev sev-fail">&#10006; ' . e(__('FAIL')) . '</span>'
    : '<span class="sev sev-warn">&#9650; ' . e(__('WARNING')) . '</span>';
$rating = [
    'risk' => ['&#10006;', __('At risk')],
    'attention' => ['&#9650;', __('Needs attention')],
    'good' => ['&#10004;', __('Good')],
][$r['rating']['level']];
$docTitle = $exec ? __('Security summary') : __('Technical findings');
$pct = static fn ($v): string => $v === null ? '—' : rtrim(rtrim(number_format((float) $v * 100, 1), '0'), '.') . '%';
$date = static fn ($v): string => $v === null || $v === '' ? '—' : substr((string) $v, 0, 10);
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($docTitle . ' – ' . $r['client']['name'] . ' – ' . $r['period']['end']) ?></title>
<style>
@page { size: <?= $b['paper'] ?>; margin: 16mm 14mm 20mm; }
:root { --brand: <?= $b['color'] ?>; --fail: #b00020; --warn: #a15c00; --ok: #1b6e3a; --muted: #5b6470; --line: #d9dde3; }
* { box-sizing: border-box; }
body { margin: 0; font: 10.5pt/1.45 "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #1d232b; background: #fff; }
.page { max-width: 190mm; margin: 0 auto; padding: 8mm 0 18mm; }
header.top { display: flex; align-items: center; gap: 12px; border-bottom: 3px solid var(--brand); padding-bottom: 8px; margin-bottom: 14px; }
header.top img { max-height: 48px; max-width: 200px; }
header.top .brand { font-weight: 600; font-size: 12pt; color: var(--brand); }
header.top .doc { margin-left: auto; text-align: right; }
h1 { font-size: 20pt; margin: 0 0 2px; color: var(--brand); }
h2 { font-size: 13.5pt; margin: 20px 0 8px; color: var(--brand); border-bottom: 1px solid var(--line); padding-bottom: 3px; break-after: avoid; }
h3 { font-size: 11pt; margin: 14px 0 6px; break-after: avoid; }
.muted { color: var(--muted); }
.small { font-size: 9pt; }
.rating { display: flex; gap: 14px; align-items: center; border: 2px solid currentColor; border-radius: 6px; padding: 10px 14px; margin: 10px 0 14px; }
.rating .big { font-size: 18pt; font-weight: 700; }
.rating-risk { color: var(--fail); } .rating-attention { color: var(--warn); } .rating-good { color: var(--ok); }
.rating p { margin: 0; color: #1d232b; }
.tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 8px 0 4px; }
.tile { border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; break-inside: avoid; }
.tile .n { font-size: 18pt; font-weight: 700; display: block; }
.sev { font-weight: 700; font-size: 8.5pt; padding: 1px 6px; border: 1.5px solid currentColor; border-radius: 3px; white-space: nowrap; }
.sev-fail { color: var(--fail); } .sev-warn { color: var(--warn); }
.risk { border-left: 4px solid var(--line); padding: 6px 0 6px 12px; margin: 10px 0; break-inside: avoid; }
.risk.fail { border-left-color: var(--fail); } .risk.warn { border-left-color: var(--warn); }
.risk h3 { margin: 0 0 4px; display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
.risk p { margin: 3px 0; }
.label { font-weight: 600; }
code { font-family: Consolas, "Liberation Mono", monospace; font-size: 9pt; background: #f2f4f7; padding: 0 3px; border-radius: 2px; overflow-wrap: anywhere; }
table.data { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 9.5pt; }
.data th, .data td { text-align: left; vertical-align: top; padding: 4px 6px; border-bottom: 1px solid var(--line); }
.data th { background: #f2f4f7; }
.data tr { break-inside: avoid; }
/* Print layout: the empty table footer repeats on every page and keeps room for the fixed page footer. */
table.layout { width: 100%; border-collapse: collapse; } table.layout > tbody > tr > td, table.layout > tfoot > tr > td { padding: 0; border: 0; }
.footer-space { height: 14mm; }
.chart { width: 100%; max-height: 70mm; }
.chart .axis { stroke: #8a929c; stroke-width: 1; } .chart .val { font-size: 11px; font-weight: 700; } .chart .lbl { font-size: 10px; fill: #5b6470; }
.legend span { margin-right: 14px; }
.note { background: #f6f7f9; border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; break-inside: avoid; }
.asset { margin-top: 16px; } .asset > .label { break-after: avoid; page-break-after: avoid; }
footer.doc-footer { position: fixed; bottom: 0; left: 0; right: 0; font-size: 8pt; color: var(--muted); border-top: 1px solid var(--line); padding: 4px 14mm; background: #fff; display: flex; gap: 12px; }
footer.doc-footer .right { margin-left: auto; }
@media screen { .footer-space { display: none; } body { background: #eef0f3; } .page { background: #fff; padding: 12mm 14mm 22mm; margin: 10px auto; box-shadow: 0 1px 4px rgba(0,0,0,.15); } footer.doc-footer { position: static; max-width: 190mm; margin: 0 auto 20px; } }
@media (max-width: 700px) { .tiles { grid-template-columns: repeat(2, 1fr); } .page { padding: 16px; } header.top { flex-wrap: wrap; } }
@media print { a { color: inherit; text-decoration: none; } }
</style>
</head>
<body>
<table class="layout"><tbody><tr><td>
<div class="page">
<header class="top">
    <?php if ($b['logo'] !== ''): ?><img src="<?= e($b['logo']) ?>" alt="<?= e($b['name']) ?>"><?php endif; ?>
    <span class="brand"><?= e($b['name']) ?></span>
    <div class="doc small muted">
        <?= e(__('Generated {date} UTC', ['date' => $r['generated_at']])) ?><br>
        <?= e(__('Period {start} to {end}', ['start' => $r['period']['start'], 'end' => $r['period']['end']])) ?>
    </div>
</header>

<h1><?= e($docTitle) ?></h1>
<p class="muted"><?= e($r['client']['name']) ?> · <?= e(__('External security checks')) ?></p>

<div class="rating rating-<?= e($r['rating']['level']) ?>">
    <span class="big"><?= $rating[0] ?> <?= e($rating[1]) ?></span>
    <p><?= e($r['rating']['reason']) ?></p>
</div>

<div class="tiles">
    <div class="tile"><span class="n" style="color:var(--fail)"><?= (int) $c['fail'] ?></span><?= $sev('fail') ?> <?= e(__('serious, fix now')) ?></div>
    <div class="tile"><span class="n" style="color:var(--warn)"><?= (int) $c['warn'] ?></span><?= $sev('warn') ?> <?= e(__('fix soon')) ?></div>
    <div class="tile"><span class="n" style="color:var(--ok)"><?= (int) $c['fixed'] ?></span>&#10004; <?= e(__('fixed this period')) ?></div>
    <div class="tile"><span class="n"><?= (int) $c['certs_expiring'] ?></span><?= e(__('certificates expiring or expired')) ?></div>
</div>
<p class="small muted"><?= e(__('Status on {now} UTC (last scan finished {date}). In the period: {n} new problem(s) found, {x} fixed.', ['now' => $r['generated_at'], 'date' => $r['last_checked'] ?? __('not yet'), 'n' => $c['new'], 'x' => $c['fixed']])) ?></p>

<?php if ($exec): ?>
<h2><?= e(__('Top risks')) ?></h2>
<?php if ($r['top'] === []): ?>
<p><?= e(__('No open problems. We keep checking.')) ?></p>
<?php endif; ?>
<?php foreach ($r['top'] as $f): ?>
<div class="risk <?= e($f['severity']) ?>">
    <h3><?= $sev((string) $f['severity']) ?> <?= e($f['title']) ?></h3>
    <p class="small muted"><?= e(__('Where: {target}', ['target' => implode(', ', array_slice($f['targets'] ?? [$f['target']], 0, 5)) . (count($f['targets'] ?? []) > 5 ? ' ' . __('and {n} more', ['n' => count($f['targets']) - 5]) : '')])) ?></p>
    <p><span class="label"><?= e(__('What it means for you:')) ?></span> <?= e($f['meaning']) ?></p>
    <p><span class="label"><?= e(__('What we\'re doing:')) ?></span> <?= e($f['fix']) ?></p>
</div>
<?php endforeach; ?>
<?php $issues = $r['open_issues'] ?? $r['top']; if (count($issues) > count($r['top'])): ?>
<p class="small muted"><?= e(__('{n} more open issue(s) are listed in the Technical findings report.', ['n' => count($issues) - count($r['top'])])) ?></p>
<?php endif; ?>
<?php else: ?>
<h2><?= e(__('Open findings')) ?></h2>
<?php if ($r['open'] === []): ?><p><?= e(__('No open findings.')) ?></p><?php endif; ?>
<?php foreach (['fail' => __('Fail: fix now'), 'warn' => __('Warning: fix soon')] as $level => $heading):
    // Each issue once, with every target it was found on (1.31); per-target evidence in a small table.
    $issues = array_values(array_filter($r['open_issues'] ?? \Sentinel\Reports\ReportBuilder::byIssue($r['open']), static fn (array $f): bool => $f['severity'] === $level));
    if ($issues === []) { continue; }
    $count = array_sum(array_map(static fn (array $f): int => count($f['items']), $issues));
?>
<h3><?= $sev($level) ?> <?= e($heading) ?> (<?= e(__('{i} issue(s) on {n} target(s)', ['i' => count($issues), 'n' => $count])) ?>)</h3>
<?php foreach ($issues as $f): ?>
<div class="risk <?= e($level) ?>">
    <h3><?= $sev($level) ?> <?= e($f['title']) ?><?= count($f['items']) > 1 ? ' · ' . e(__('{n} targets', ['n' => count($f['items'])])) : '' ?></h3>
    <table class="data">
        <?php if ($f['finding_type'] === 'vuln'): ?>
        <tr><th style="width:28%"><?= e(__('Vulnerability')) ?></th><td><?= e($f['cve_id']) ?> · <?= e(__('Known exploited (CISA KEV): {v}', ['v' => (int) $f['in_kev'] === 1 ? __('yes') . ($f['kev_due'] ? ', ' . __('due {d}', ['d' => $f['kev_due']]) : '') : __('no')])) ?> · <?= e(__('EPSS: {p}', ['p' => $pct($f['epss'])])) ?></td></tr>
        <?php endif; ?>
        <tr><th style="width:28%"><?= e(__('Why it matters')) ?></th><td><?= e($f['meaning']) ?></td></tr>
        <tr><th><?= e(__('How to fix')) ?></th><td><?= e($f['fix']) ?></td></tr>
    </table>
    <table class="data">
        <tr><th><?= e(__('Target')) ?></th><th><?= e(__('Details and evidence')) ?></th><th><?= e(__('First / last seen')) ?></th></tr>
        <?php foreach ($f['items'] as $it): ?>
        <tr><td><code><?= e($it['target']) ?></code></td>
            <td><?= e($it['detail']) ?><?php if ((string) $it['evidence'] !== ''): ?><br><code><?= e($it['evidence']) ?></code><?php endif; ?>
                <?php if ($it['finding_type'] === 'vuln'): ?><br><span class="small muted"><?= e(match ($it['confidence']) { 'confirmed' => __('Confirmed for the reported version'), 'distro' => __('Possible: distribution build, the fix may be backported'), default => __('Possible: version unknown') }) ?></span><?php endif; ?></td>
            <td><?= e($date($it['first_seen'])) ?> / <?= e($date($it['last_seen'])) ?><?= (int) $it['reappeared'] === 1 ? ' · ' . e(__('reappeared after being fixed')) : '' ?></td></tr>
        <?php endforeach; ?>
    </table>
</div>
<?php endforeach; ?>
<?php endforeach; ?>

<?php if ($r['fixed'] !== []): ?>
<h2><?= e(__('Fixed this period')) ?></h2>
<table class="data">
    <tr><th><?= e(__('Finding')) ?></th><th><?= e(__('Target')) ?></th><th><?= e(__('Fixed on')) ?></th></tr>
    <?php foreach ($r['fixed_issues'] ?? \Sentinel\Reports\ReportBuilder::byIssue($r['fixed']) as $f): ?>
    <tr><td>&#10004; <?= e($f['title']) ?></td><td><code><?= e(implode(', ', $f['targets'])) ?></code></td><td><?= e($date((string) max(array_column($f['items'], 'resolved_at')))) ?></td></tr>
    <?php endforeach; ?>
</table>
<?php endif; ?>
<?php endif; ?>

<h2><?= e(__('Trend')) ?></h2>
<?php if (count($r['trend']) < 2): ?>
<p class="small muted"><?= e(__('The trend chart appears once Sentinel has recorded at least one full month for this client.')) ?></p>
<?php else: ?>
<?= $chart ?>
<p class="small legend"><span style="color:var(--fail)">&#9679; <?= e(__('Fail (solid line)')) ?></span><span style="color:var(--warn)">&#9632; <?= e(__('Warning (dashed line)')) ?></span><span class="muted"><?= e(__('Open items at the end of each month, from when Sentinel started recording.')) ?></span></p>
<?php endif; ?>

<?php if ($r['decided'] !== []): ?>
<h2><?= e(__('Accepted risks and false positives')) ?></h2>
<p class="small muted"><?= e(__('These items were reviewed. They are listed so nothing is hidden, but they do not count towards the totals above.')) ?></p>
<table class="data">
    <tr><th><?= e(__('Finding')) ?></th><th><?= e(__('Target')) ?></th><th><?= e(__('Decision')) ?></th><th><?= e(__('Note')) ?></th></tr>
    <?php foreach ($r['decided'] as $f): ?>
    <tr>
        <td><?= $sev((string) $f['severity']) ?> <?= e($f['title']) ?></td>
        <td><code><?= e($f['target']) ?></code></td>
        <td><?= e($f['status'] === 'accepted' ? __('Accepted risk') : __('False positive')) ?><br><span class="small muted"><?= e(trim(($f['triaged_by_name'] ?? '') . ' ' . $date($f['triaged_at']))) ?></span></td>
        <td><?= e($f['triage_note']) ?></td>
    </tr>
    <?php endforeach; ?>
</table>
<?php endif; ?>

<h2><?= e($exec ? __('What we checked') : __('Appendix: scope and method')) ?></h2>
<p><?= e(__('We checked the following internet-facing addresses and names, which you authorised us to test:')) ?></p>
<p><?php if ($r['scope'] === []): ?><span class="muted"><?= e(__('No active authorisation.')) ?></span><?php else: ?><?php foreach ($r['scope'] as $s): ?><code><?= e($s) ?></code> <?php endforeach; ?><?php endif; ?></p>
<?php if (!$exec): ?>
<h3><?= e(__('Recent scans')) ?></h3>
<?php if ($r['scans'] === []): ?><p class="muted"><?= e(__('No completed scans.')) ?></p><?php else: ?>
<table class="data">
    <tr><th><?= e(__('Scan')) ?></th><th><?= e(__('Started (UTC)')) ?></th><th><?= e(__('Finished (UTC)')) ?></th><th><?= e(__('Result')) ?></th></tr>
    <?php foreach ($r['scans'] as $s): ?>
    <tr><td>#<?= (int) $s['id'] ?></td><td><?= e($s['started_at']) ?></td><td><?= e($s['finished_at']) ?></td><td><?= e($s['status']) ?></td></tr>
    <?php endforeach; ?>
</table>
<?php endif; ?>
<h3><?= e(__('Methods')) ?></h3>
<ul>
    <li><?= e(__('Port scan: a gentle TCP connect scan of common ports, rate-limited and run inside the agreed scan window.')) ?></li>
    <li><?= e(__('Certificates and encryption: each HTTPS service is checked for expiry, trust, name match, key strength and old TLS versions.')) ?></li>
    <li><?= e(__('Web pages: the first page of each web service is fetched once to spot exposed admin and login portals.')) ?></li>
    <li><?= e(__('Vulnerabilities: reported software versions are matched against the NVD, the CISA known-exploited list and EPSS. "Possible" means the version could not be confirmed.')) ?></li>
</ul>
<?php endif; ?>
<p class="note small"><?= e(__('Limits: these are external, non-intrusive checks of the addresses listed above at the times shown. They do not prove that systems are secure, they do not test internal networks, and this is not a PCI ASV scan.')) ?></p>
<?php if ($b['footer'] !== ''): ?><p class="small muted" style="white-space:pre-line"><?= e($b['footer']) ?></p><?php endif; ?>
</div>
</td></tr></tbody><tfoot><tr><td><div class="footer-space"></div></td></tr></tfoot></table>
<footer class="doc-footer">
    <span><?= e($b['name']) ?> · <?= e($r['client']['name']) ?> · <?= e($docTitle) ?></span>
    <span class="right"><?= e(__('Generated {date} UTC', ['date' => $r['generated_at']])) ?><?php if ($b['powered_by']): ?> · <?= e(__('Generated by MSP Sentinel {v}', ['v' => $r['version']])) ?><?php endif; ?></span>
</footer>
</body>
</html>
