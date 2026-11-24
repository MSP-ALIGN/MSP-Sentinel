<?php
/**
 * Client overview console on the client's overview (also served alone for the 60-second refresh).
 * Expects: $client, $ov (array from ClientController::overviewData()). Every value is escaped.
 */
use Sentinel\Dashboard\Svg;

require __DIR__ . '/../dashboard/helpers.php';
$c = $ov['summary'];
$w = $ov['window'];
?>
<div class="client-console">
    <section class="hud hud-gauge" aria-labelledby="h-c-risk">
        <h2 id="h-c-risk" class="hud-title"><?= e(__('Risk')) ?></h2>
        <?php if (($c['last_scan'] ?? null) === null && (int) $c['fail'] === 0 && (int) $c['warn'] === 0): ?>
        <?php // Never scanned: no score (an empty client is not a "good" one, 1.34). ?>
        <p class="gauge-level mt-3"><i class="bi bi-hourglass" aria-hidden="true"></i> <?= e(__('Not scanned yet')) ?></p>
        <p class="small text-body-secondary mb-0"><?= e(__('The risk score appears after the first scan.')) ?></p>
        <?php else: ?>
        <?= Svg::gauge($c['score'], $c['level'], __('Client risk')) ?>
        <p class="gauge-level level-<?= e($c['level']) ?>"><i class="bi <?= e($levelIcon($c['level'])) ?>" aria-hidden="true"></i> <?= e($levelWord($c['level'])) ?></p>
        <?php endif; ?>
    </section>
    <section class="hud hud-kpis" aria-label="<?= e(__('Totals')) ?>">
        <a class="kpi kpi-fail" href="<?= e(url('/clients/' . (int) $client['id'] . '/findings')) ?>"><span class="kpi-n"><?= (int) $c['fail'] ?></span><span class="kpi-l"><i class="bi bi-x-octagon" aria-hidden="true"></i> <?= e(__('Open Fail')) ?></span></a>
        <a class="kpi kpi-warn" href="<?= e(url('/clients/' . (int) $client['id'] . '/findings')) ?>"><span class="kpi-n"><?= (int) $c['warn'] ?></span><span class="kpi-l"><i class="bi bi-exclamation-triangle" aria-hidden="true"></i> <?= e(__('Open Warning')) ?></span></a>
        <a class="kpi kpi-kev" href="<?= e(url('/clients/' . (int) $client['id'] . '/vulnerabilities')) ?>"><span class="kpi-n"><?= (int) $c['kev'] ?></span><span class="kpi-l"><i class="bi bi-bug" aria-hidden="true"></i> <?= e(__('Known exploited')) ?></span></a>
        <a class="kpi" href="<?= e(url('/clients/' . (int) $client['id'] . '/scans')) ?>"><span class="kpi-n"><?= (int) $ov['surface']['hosts'] ?></span><span class="kpi-l"><i class="bi bi-hdd-network" aria-hidden="true"></i> <?= e(__('Hosts')) ?></span></a>
        <a class="kpi" href="<?= e(url('/clients/' . (int) $client['id'] . '/scans')) ?>"><span class="kpi-n"><?= (int) $ov['surface']['services'] ?></span><span class="kpi-l"><i class="bi bi-door-open" aria-hidden="true"></i> <?= e(__('Open services')) ?></span></a>
        <?php if ($ov['paused']): ?>
        <div class="kpi kpi-window is-paused"><span class="kpi-n kpi-small"><?= e(__('Paused')) ?></span><span class="kpi-l"><i class="bi bi-pause-circle" aria-hidden="true"></i> <?= e(__('Scanning is paused')) ?></span></div>
        <?php else: ?>
        <div class="kpi kpi-window <?= $w !== null && $w['open'] ? 'is-open' : '' ?>"><span class="kpi-n kpi-small"><?= e($w === null ? '—' : $duration($w['in'])) ?></span><span class="kpi-l"><i class="bi bi-clock" aria-hidden="true"></i> <?= e($w === null ? ((int) ($client['is_demo'] ?? 0) === 1 ? __('Demo client: never scanned') : __('No valid scan window')) : ($w['open'] ? __('Window open, closes in') : __('Window opens in'))) ?></span></div>
        <?php endif; ?>
    </section>
    <section class="hud hud-trend" aria-labelledby="h-c-trend">
        <h2 id="h-c-trend" class="hud-title"><?= e(__('Open problems, last 90 days')) ?></h2>
        <?php if (count($ov['trend']) < 2): ?>
        <p class="trend-note"><i class="bi bi-graph-up" aria-hidden="true"></i><?= e(__('The trend builds up day by day: check back tomorrow.')) ?></p>
        <?php else: ?>
        <?= Svg::trend($ov['trend'], __('Open Fail and Warning findings for this client over the last 90 days')) ?>
        <p class="legend-line"><span class="lg-fail">━ <?= e(__('Fail')) ?></span> <span class="lg-warn">┅ <?= e(__('Warning')) ?></span>
            <span class="hud-meta ms-2"><?= e(__('Last scan: {t}', ['t' => $c['last_scan'] !== null ? substr((string) $c['last_scan'], 0, 16) . ' UTC' : __('never')])) ?></span></p>
        <?php endif; ?>
        
    </section>
    <section class="hud hud-surface" aria-labelledby="h-c-surface">
        <h2 id="h-c-surface" class="hud-title"><?= e(__('Attack surface')) ?></h2>
        <?= Svg::bars($ov['surface']['categories'], __('Open services by type for this client')) ?>
    </section>
    <section class="hud hud-feed" aria-labelledby="h-c-feed">
        <h2 id="h-c-feed" class="hud-title"><?= e(__('Recent activity')) ?></h2>
        <?php if ($ov['activity'] === []): ?><p class="hud-empty"><?= e(__('No activity yet.')) ?></p><?php endif; ?>
        <ol class="feed">
            <?php foreach ($ov['activity'] as $a): ?>
            <li class="<?= e($eventClass($a['kind'], $a['severity'])) ?>">
                <span class="feed-time"><?= e(substr($a['at'], 5, 11)) ?></span>
                <span class="feed-kind"><?= e($eventWord($a['kind'])) ?></span>
                <a href="<?= e(url($a['link'])) ?>"><?= e(str_starts_with($a['kind'], 'scan_') ? __('{type} scan', ['type' => strtoupper($a['title'])]) : $a['title']) ?></a>
            </li>
            <?php endforeach; ?>
        </ol>
        <?php if ($ov['certs'] !== []): ?>
        <h3 class="hud-title hud-title-sm"><?= e(__('Certificates, next 30 days')) ?></h3>
        <ul class="cert-line">
            <?php foreach ($ov['certs'] as $ct): ?>
            <li class="<?= $ct['days'] < 0 ? 'c-expired' : ($ct['days'] <= 14 ? 'c-soon' : 'c-later') ?>"><span class="c-days"><?= e($ct['days'] < 0 ? __('expired') : __('{n} d', ['n' => $ct['days']])) ?></span><span class="c-name"><?= e($ct['name']) ?></span><span class="hud-meta"><code><?= e($ct['endpoint']) ?></code></span></li>
            <?php endforeach; ?>
        </ul>
        <?php endif; ?>
    </section>
</div>
