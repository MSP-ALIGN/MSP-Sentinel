<?php
/**
 * A complete, self-contained report document (executive summary or technical findings), in the shared report design
 * (ReportTheme, 1.59): a branded cover, an "at a glance" summary with the risk-score gauge, numbered sections and a
 * sign-off with the contact block.
 * Expects: $r (snapshot from ReportBuilder), $chart (SVG built by ReportRenderer::trendChart).
 * Every snapshot value is untrusted and escaped with e(); text in the page margins goes through ReportTheme::cssString().
 * No scripts. Severity is never shown by color alone: each mark has an icon and a word.
 */
use Sentinel\Reports\ReportTheme;

$b = ReportTheme::brand($r['brand']);
// Times in the client's time zone, each labelled (1.48); snapshots made before have none: UTC.
try {
    $rz = new DateTimeZone((string) ($r['client']['timezone'] ?? 'UTC'));
} catch (\Exception) {
    $rz = new DateTimeZone('UTC');
}
$c = $r['counts'];
$exec = $r['kind'] === 'executive';
$sev = static fn (string $s): string => $s === 'fail'
    ? '<span class="sev sev-fail">&#10006; ' . e(__('FAIL')) . '</span>'
    : '<span class="sev sev-warn">&#9650; ' . e(__('WARNING')) . '</span>';
$levelWord = ['risk' => __('At risk'), 'attention' => __('Needs attention'), 'good' => __('Good')][$r['rating']['level']] ?? '';
$levelIcon = ['risk' => '&#10006;', 'attention' => '&#9650;', 'good' => '&#10004;'][$r['rating']['level']] ?? '';
$score = isset($r['rating']['score']) ? (int) $r['rating']['score'] : null; // reports made before 1.58.2 have no score
$docTitle = $exec ? __('Security summary') : __('Technical findings');
$pct = static fn ($v): string => $v === null ? '—' : rtrim(rtrim(number_format((float) $v * 100, 1), '0'), '.') . '%';
$date = static fn ($v): string => $v === null || $v === '' ? '—' : substr(when((string) $v, $rz), 0, 10); // the client's date (1.48.1)
$client = (string) $r['client']['name'];
$generated = $date($r['generated_at']);
$period = __('Reporting period {start} to {end}', ['start' => $r['period']['start'], 'end' => $r['period']['end']]);
// What the report covers (1.59): older snapshots were external only.
$cov = $r['coverage'] ?? ['external' => true, 'internal' => false];
$conf = ReportTheme::confidential($b, $client);
$footLine = $b['name'] . ' · ' . $client . ' · ' . $docTitle;
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($docTitle . ' – ' . $client . ' – ' . $r['period']['end']) ?></title>
<style>
<?= ReportTheme::css($b, $footLine, $conf !== '' ? $conf : $b['name']) ?>
</style>
</head>
<body>
<?= ReportTheme::cover($b, [
    'eyebrow' => __('Security assessment') . ' · ' . ($exec ? __('Executive summary') : __('Technical report')),
    'title' => $docTitle,
    'client' => $client,
    'period' => $period,
    'date' => $generated,
    'score' => $score,
    'level_word' => $levelWord,
    'level_note' => (string) $r['rating']['reason'],
]) ?>
<main class="sheet">
<?= ReportTheme::docHead($b, $docTitle, $client . ' · ' . $period) ?>

<h2 class="sec"><?= e(__('At a glance')) ?></h2>
<div class="glance">
    <div><?= $score !== null ? ReportTheme::gauge($score, $levelWord) : '' ?></div>
    <div>
        <p class="verdict verdict-<?= e($r['rating']['level']) ?>"><?= $levelIcon ?> <?= e($levelWord) ?></p>
        <p><?= e($r['rating']['reason']) ?></p>
        <?php if ($score !== null): ?><p class="small muted"><?= e(__('Risk score {s} of 100', ['s' => $score])) ?>. <?= e(__('Problems that can be reached from the internet count in full, those inside the network count less, and known-exploited weaknesses count double.')) ?></p><?= ReportTheme::bands() ?><?php endif; ?>
    </div>
</div>

<div class="tiles">
    <div class="tile t-fail"><span class="n"><?= (int) $c['fail'] ?></span><?= $sev('fail') ?> <?= e(__('serious, fix first')) ?></div>
    <div class="tile t-warn"><span class="n"><?= (int) $c['warn'] ?></span><?= $sev('warn') ?> <?= e(__('fix soon')) ?></div>
    <div class="tile t-ok"><span class="n"><?= (int) $c['fixed'] ?></span>&#10004; <?= e(__('fixed this period')) ?></div>
    <div class="tile t-brand"><span class="n"><?= (int) $c['certs_expiring'] ?></span><?= e(__('certificates expiring or expired')) ?></div>
</div>
<p class="small muted"><?= e(__('Status on {now} (last scan finished {date}). In the period: {n} new finding(s), {x} fixed.', ['now' => when($r['generated_at'], $rz), 'date' => when($r['last_checked'] ?? null, $rz, __('not yet')), 'n' => $c['new'], 'x' => $c['fixed']])) ?></p>

<?php if ($exec): ?>
<h2 class="sec"><?= e(__('Top risks')) ?></h2>
<?php if ($r['top'] === []): ?>
<p><?= e(__('No open problems. We keep checking.')) ?></p>
<?php endif; ?>
<?php foreach ($r['top'] as $i => $f): ?>
<div class="risk <?= e($f['severity']) ?>">
    <h3><span class="rank"><?= (int) $i + 1 ?>.</span> <?= $sev((string) $f['severity']) ?> <?= e($f['title']) ?></h3>
    <p class="small muted"><?= e(__('Where: {target}', ['target' => implode(', ', array_slice($f['targets'] ?? [$f['target']], 0, 5)) . (count($f['targets'] ?? []) > 5 ? ' ' . __('and {n} more', ['n' => count($f['targets']) - 5]) : '')])) ?></p>
    <p><span class="label"><?= e(__('What it means for you:')) ?></span> <?= e($f['meaning']) ?></p>
    <p><span class="label"><?= e(__('What we\'re doing:')) ?></span> <?= e($f['fix']) ?></p>
</div>
<?php endforeach; ?>
<?php $issueCount = (int) ($r['open_issue_count'] ?? count(\Sentinel\Reports\ReportBuilder::byIssue($r['open']))); if ($issueCount > count($r['top'])): ?>
<p class="small muted"><?= e(__('{n} more open issue(s) are listed in the Technical findings report.', ['n' => $issueCount - count($r['top'])])) ?></p>
<?php endif; ?>
<?php else: ?>
<h2 class="sec"><?= e(__('Open findings')) ?></h2>
<?php if ($r['open'] === []): ?><p><?= e(__('No open findings.')) ?></p><?php endif; ?>
<?php foreach (['fail' => __('Fail: fix now'), 'warn' => __('Warning: fix soon')] as $level => $heading):
    // Each issue once, with every target it was found on (1.31); per-target evidence in a small table.
    $issues = array_values(array_filter(\Sentinel\Reports\ReportBuilder::byIssue($r['open']), static fn (array $f): bool => $f['severity'] === $level));
    if ($issues === []) { continue; }
    $count = array_sum(array_map(static fn (array $f): int => count($f['items']), $issues));
?>
<h3><?= $sev($level) ?> <?= e($heading) ?> (<?= e(__('{i} issue(s), {n} finding(s)', ['i' => count($issues), 'n' => $count])) ?>)</h3>
<?php foreach ($issues as $f): ?>
<div class="risk <?= e($level) ?>">
    <h3><?= $sev($level) ?> <?= e($f['title']) ?><?= count($f['items']) > 1 ? ' · ' . e(__('{n} targets', ['n' => count($f['items'])])) : '' ?></h3>
    <table class="data"><tbody>
        <?php if ($f['finding_type'] === 'vuln'): ?>
        <tr><th><?= e(__('Vulnerability')) ?></th><td><?= e($f['cve_id']) ?> · <?= e(__('Known exploited (CISA KEV): {v}', ['v' => (int) $f['in_kev'] === 1 ? __('yes') . ($f['kev_due'] ? ', ' . __('due {d}', ['d' => $f['kev_due']]) : '') : __('no')])) ?> · <?= e(__('EPSS: {p}', ['p' => $pct($f['epss'])])) ?></td></tr>
        <?php endif; ?>
        <tr><th><?= e(__('Why it matters')) ?></th><td><?= e($f['meaning']) ?></td></tr>
        <tr><th><?= e(__('How to fix')) ?></th><td><?= e($f['fix']) ?></td></tr>
    </tbody></table>
    <table class="data">
        <thead><tr><th><?= e(__('Target')) ?></th><th><?= e(__('Details')) ?></th><th><?= e(__('First / last seen')) ?></th></tr></thead>
        <tbody>
        <?php foreach ($f['items'] as $it): ?>
        <tr><td><code><?= e($it['target']) ?></code><?php if (isset($it['source'])): ?><br><span class="small muted"><?= e((string) $it['source'] === 'external' ? __('from the internet') : __('inside the network')) ?></span><?php endif; ?></td>
            <td><?= e($it['detail']) ?><?php $ev = \Sentinel\Reports\ReportBuilder::readableEvidence((string) $it['finding_type'], (string) $it['evidence']); if ($ev !== ''): ?><br><span class="small"><?= e($ev) ?></span><?php endif; ?>
                <?php if ($it['finding_type'] === 'vuln'): ?><br><span class="small muted"><?= e(match ($it['confidence']) { 'confirmed' => __('Confirmed for the reported version'), 'distro' => __('Possible: distribution build, the fix may be backported'), default => __('Possible: version unknown') }) ?></span><?php endif; ?></td>
            <td class="nowrap"><?= e($date($it['first_seen'])) ?> / <?= e($date($it['last_seen'])) ?><?= (int) $it['reappeared'] === 1 ? '<br>' . e(__('reappeared after being fixed')) : '' ?></td></tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endforeach; ?>
<?php endforeach; ?>

<?php if ($r['fixed'] !== []): ?>
<h2 class="sec"><?= e(__('Fixed this period')) ?></h2>
<table class="data">
    <thead><tr><th><?= e(__('Finding')) ?></th><th><?= e(__('Target')) ?></th><th><?= e(__('Fixed on')) ?></th></tr></thead>
    <tbody>
    <?php foreach (\Sentinel\Reports\ReportBuilder::byIssue($r['fixed']) as $f): ?>
    <tr><td><span class="c-ok">&#10004;</span> <?= e($f['title']) ?></td><td><code><?= e(implode(', ', $f['targets'])) ?></code></td><td class="nowrap"><?= e($date((string) max(array_column($f['items'], 'resolved_at')))) ?></td></tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>
<?php endif; ?>

<h2 class="sec"><?= e(__('Trend')) ?></h2>
<?php if (count($r['trend']) < 2): ?>
<p class="small muted"><?= e(__('The trend chart appears once Sentinel has recorded at least one full month for this client.')) ?></p>
<?php else: ?>
<?= $chart ?>
<p class="small legend"><span class="c-fail">&#9679; <?= e(__('Fail (solid line)')) ?></span><span class="c-warn">&#9632; <?= e(__('Warning (dashed line)')) ?></span><span class="muted"><?= e(__('Open items at the end of each month, from when Sentinel started recording.')) ?></span></p>
<?php endif; ?>

<?php if ($r['decided'] !== []): ?>
<h2 class="sec"><?= e(__('Accepted risks and false positives')) ?></h2>
<p class="small muted"><?= e(__('These items were reviewed. They are listed so nothing is hidden, but they do not count towards the totals above.')) ?></p>
<table class="data">
    <thead><tr><th><?= e(__('Finding')) ?></th><th><?= e(__('Target')) ?></th><th><?= e(__('Decision')) ?></th><th><?= e(__('Note')) ?></th></tr></thead>
    <tbody>
    <?php foreach ($r['decided'] as $f): ?>
    <tr>
        <td><?= $sev((string) $f['severity']) ?> <?= e($f['title']) ?></td>
        <td><code><?= e($f['target']) ?></code></td>
        <td><?= e($f['status'] === 'accepted' ? __('Accepted risk') : __('False positive')) ?><br><span class="small muted"><?= e(trim(($f['triaged_by_name'] ?? '') . ' ' . $date($f['triaged_at']))) ?></span></td>
        <td><?= e($f['triage_note']) ?></td>
    </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<h2 class="sec"><?= e($exec ? __('What we checked') : __('Appendix: scope and method')) ?></h2>
<?php if ($cov['external'] || !$cov['internal']): ?>
<p><?= e(__('From the internet, we checked the following addresses and names, which you authorized us to test:')) ?></p>
<p><?php if ($r['scope'] === []): ?><span class="muted"><?= e(__('No active authorization.')) ?></span><?php else: ?><?php foreach ($r['scope'] as $s): ?><code><?= e($s) ?></code> <?php endforeach; ?><?php endif; ?></p>
<?php endif; ?>
<?php if ($cov['internal']): ?>
<p><?= e(__('Inside your network, we checked the devices our agent could reach, and device health from your management tools: antivirus, disk encryption, updates and operating system support.')) ?></p>
<?php endif; ?>
<?php if (!$exec): ?>
<h3><?= e(__('Recent scans')) ?></h3>
<?php if ($r['scans'] === []): ?><p class="muted"><?= e(__('No completed scans.')) ?></p><?php else: ?>
<table class="data">
    <thead><tr><th><?= e(__('Scan')) ?></th><th><?= e(__('Started')) ?></th><th><?= e(__('Finished')) ?></th><th><?= e(__('Result')) ?></th></tr></thead>
    <tbody>
    <?php foreach ($r['scans'] as $s): ?>
    <tr><td>#<?= (int) $s['id'] ?></td><td><?= e(when($s['started_at'], $rz)) ?></td><td><?= e(when($s['finished_at'], $rz)) ?></td><td><?= e($s['status']) ?></td></tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>
<h3><?= e(__('Methods')) ?></h3>
<ul>
    <?php if ($cov['external'] || !$cov['internal']): ?>
    <li><?= e(__('Port scan: a gentle TCP connect scan of common ports, rate-limited and run inside the agreed scan window.')) ?></li>
    <li><?= e(__('Certificates and encryption: each HTTPS service is checked for expiry, trust, name match, key strength and old TLS versions.')) ?></li>
    <li><?= e(__('Web pages: the first page of each web service is fetched once to spot exposed admin and login portals.')) ?></li>
    <?php endif; ?>
    <?php if ($cov['internal']): ?>
    <li><?= e(__('Internal network: an agent on your network checks the devices it can reach for risky services and weak settings, without changing anything.')) ?></li>
    <li><?= e(__('Device health: antivirus, disk encryption, missing updates and operating system support, read from your remote management tool.')) ?></li>
    <?php endif; ?>
    <li><?= e(__('Vulnerabilities: reported software versions are matched against the NVD, the CISA known-exploited list and EPSS. "Possible" means the version could not be confirmed.')) ?></li>
</ul>
<?php endif; ?>
<p class="note small"><?= e($cov['internal']
    ? __('Limits: these checks are non-intrusive and show the state at the times shown. Internal checks cover only the devices our agent and your management tools could see. They do not prove that systems are secure, and this is not a PCI ASV scan.')
    : __('Limits: these are external, non-intrusive checks of the addresses listed above at the times shown. They do not prove that systems are secure, they do not test internal networks, and this is not a PCI ASV scan.')) ?></p>
<?php if ($b['footer'] !== ''): ?><p class="small muted pre"><?= e($b['footer']) ?></p><?php endif; ?>

<?= ReportTheme::signoff($b, $generated) ?>
<?php if ($b['powered_by']): ?><p class="small muted"><?= e(__('Generated by MSP Sentinel {v}', ['v' => $r['version']])) ?></p><?php endif; ?>
</main>
<?= ReportTheme::footer($b, $footLine, __('Generated {date}', ['date' => when($r['generated_at'], $rz)])) ?>
</body>
</html>
