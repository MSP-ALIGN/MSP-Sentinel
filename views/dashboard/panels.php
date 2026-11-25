<?php
/**
 * Main dashboard panels (also served alone for the 60-second refresh).
 * Expects: $d (array from PageController::dashboardData()).
 * Every value is escaped; charts are built by Sentinel\Dashboard\Svg (escaped inside).
 * Severity is shown with an icon and a word as well as colour.
 */
use Sentinel\Dashboard\Svg;

require __DIR__ . '/helpers.php';
$o = $d['ops'];
$worst = $d['clients'][0] ?? null;
$atRisk = count(array_filter($d['clients'], static fn (array $c): bool => $c['level'] === 'risk'));
$feedOk = static fn (?int $age): bool => $age !== null && $age <= 2 * 86400;
?>
<div class="ops-strip" role="status">
    <span class="ops-chip <?= $o['paused'] ? 'is-bad' : 'is-ok' ?>"><i class="bi <?= $o['paused'] ? 'bi-pause-circle' : 'bi-broadcast' ?>" aria-hidden="true"></i><?= e($o['paused'] ? __('Scanning PAUSED') : __('Scanning armed')) ?></span>
    <span class="ops-chip <?= $o['worker_age'] !== null && $o['worker_age'] <= 300 ? 'is-ok' : 'is-bad' ?>"><i class="bi bi-cpu" aria-hidden="true"></i><?= e(__('Worker')) ?> <b><?= e($ago($o['worker_age'])) ?></b></span>
    <span class="ops-chip <?= $feedOk($o['feed_age']['kev']) && $feedOk($o['feed_age']['epss']) ? 'is-ok' : 'is-warn' ?>"><i class="bi bi-database-down" aria-hidden="true"></i><?= e(__('Threat feeds')) ?> <b><?= e($ago($o['feed_age']['kev'])) ?></b></span>
    <span class="ops-chip <?= $o['running'] > 0 ? 'is-live' : '' ?>"><i class="bi bi-radar" aria-hidden="true"></i><?= e(__('{r} running · {q} queued', ['r' => $o['running'], 'q' => $o['queued']])) ?></span>
    <span class="ops-chip"><i class="bi bi-clock" aria-hidden="true"></i><?= e($o['paused'] ? __('Scan windows on hold (paused)') : ($o['windows_open'] > 0 ? __('{n} scan window(s) open', ['n' => $o['windows_open']]) : ($o['next_window'] !== null ? __('Next window: {c} in {t}', ['c' => $o['next_window']['client'], 't' => $duration($o['next_window']['in'])]) : __('No scan windows')))) ?></span>
    <span class="ops-chip <?= $d['authorisations']['ending'] > 0 ? 'is-warn' : '' ?>"><i class="bi bi-file-earmark-check" aria-hidden="true"></i><?= e(__('{a} active scan authorizations', ['a' => $d['authorisations']['active']])) ?><?= $d['authorisations']['ending'] > 0 ? ' · ' . e(__('{n} ending within 30 days', ['n' => $d['authorisations']['ending']])) : '' ?></span>
    <span class="ops-time ms-auto"><?= e(__('Updated {t}', ['t' => (new DateTimeImmutable('now', display_zone()))->format('H:i:s T')])) ?></span>
</div>

<div class="dash-grid">
    <section class="hud hud-gauge" aria-labelledby="h-threat">
        <h2 id="h-threat" class="hud-title"><?= e(__('Threat level')) ?></h2>
        <?php if ($worst === null): ?>
        <p class="hud-empty"><?= e(__('No clients yet.')) ?>
            <?php if (can('clients.manage')): ?><a class="btn btn-primary btn-sm ms-1" href="<?= e(url('/clients/new')) ?>"><i class="bi bi-plus-lg me-1" aria-hidden="true"></i><?= e(__('Add your first client')) ?></a>
            <?php else: ?><?= e(__('An admin adds clients.')) ?><?php endif; ?></p>
        <?php else: ?>
        <?= Svg::gauge($worst['score'], $worst['level'], __('Highest client risk')) ?>
        <p class="gauge-level level-<?= e($worst['level']) ?>"><i class="bi <?= e($levelIcon($worst['level'])) ?>" aria-hidden="true"></i> <?= e($levelWord($worst['level'])) ?></p>
        <p class="hud-sub"><?= e(__('Highest: {c}', ['c' => $worst['name']])) ?> · <?= e(__('{n} of {t} clients at risk', ['n' => $atRisk, 't' => count($d['clients'])])) ?></p>
        <?php endif; ?>
    </section>

    <section class="hud hud-kpis" aria-label="<?= e(__('Totals')) ?>">
        <a class="kpi kpi-fail" href="<?= e(url('/findings', ['severity' => 'fail'])) ?>"><span class="kpi-n"><?= (int) $d['totals']['fail'] ?></span><span class="kpi-l"><i class="bi bi-x-octagon" aria-hidden="true"></i> <?= e(__('Open Fail')) ?></span></a>
        <a class="kpi kpi-warn" href="<?= e(url('/findings', ['severity' => 'warn'])) ?>"><span class="kpi-n"><?= (int) $d['totals']['warn'] ?></span><span class="kpi-l"><i class="bi bi-exclamation-triangle" aria-hidden="true"></i> <?= e(__('Open Warning')) ?></span></a>
        <a class="kpi kpi-kev" href="<?= e(url('/findings', ['type' => 'vuln', 'severity' => 'fail'])) ?>"><span class="kpi-n"><?= (int) $d['totals']['kev'] ?></span><span class="kpi-l"><i class="bi bi-bug" aria-hidden="true"></i> <?= e(__('Known exploited (open Fail findings)')) ?><?php if ($d['kevPossible'] > 0): ?><br><?= e(__('+{n} possible CVE(s), version unknown', ['n' => $d['kevPossible']])) ?><?php endif; ?></span></a>
        <div class="kpi kpi-cert"><span class="kpi-n"><?= (int) $d['certsSoon'] ?></span><span class="kpi-l"><i class="bi bi-shield-exclamation" aria-hidden="true"></i> <?= e(__('Certs ≤ 14 days')) ?></span></div>
        <div class="kpi"><span class="kpi-n"><?= (int) $d['surface']['hosts'] ?></span><span class="kpi-l"><i class="bi bi-hdd-network" aria-hidden="true"></i> <?= e(__('Hosts watched')) ?></span></div>
        <div class="kpi"><span class="kpi-n"><?= (int) $d['surface']['services'] ?></span><span class="kpi-l"><i class="bi bi-door-open" aria-hidden="true"></i> <?= e(__('Open services')) ?></span></div>
    </section>

    <section class="hud hud-trend" aria-labelledby="h-trend">
        <h2 id="h-trend" class="hud-title"><?= e(__('Open problems, last 90 days')) ?></h2>
        <?php if (count($d['trend']) < 2): ?>
        <p class="trend-note"><i class="bi bi-graph-up" aria-hidden="true"></i><?= e(__('The trend builds up day by day: check back tomorrow.')) ?></p>
        <?php else: ?>
        <?= Svg::trend($d['trend'], __('Open Fail and Warning findings over the last 90 days')) ?>
        <p class="legend-line"><span class="lg-fail">━ <?= e(__('Fail')) ?></span> <span class="lg-warn">┅ <?= e(__('Warning')) ?></span></p>
        <?php endif; ?>
        
    </section>

    <section class="hud hud-clients" aria-labelledby="h-clients">
        <h2 id="h-clients" class="hud-title"><?= e(__('Client risk grid')) ?></h2>
        <?php if ($d['clients'] === []): ?><p class="hud-empty"><?= e(__('No clients yet.')) ?></p><?php endif; ?>
        <div class="risk-grid">
            <?php foreach ($d['clients'] as $c): ?>
            <a class="risk-tile level-<?= e($c['level']) ?>" href="<?= e(url('/clients/' . $c['id'])) ?>">
                <span class="rt-score"><?= (int) $c['score'] ?></span>
                <span class="rt-name"><?= e($c['name']) ?></span>
                <span class="rt-meta"><i class="bi <?= e($levelIcon($c['level'])) ?>" aria-hidden="true"></i> <?= e(($c['last_scan'] ?? null) === null && (int) $c['fail'] === 0 && (int) $c['warn'] === 0 ? __('Not scanned yet') : $levelWord($c['level'])) ?> · <?= e(__('{f} Fail, {w} Warning', ['f' => $c['fail'], 'w' => $c['warn']])) ?><?= $c['paused'] ? ' · ' . e(__('paused')) : '' ?></span>
                <svg class="rt-bar" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true"><rect class="rt-track" width="100" height="4"/><rect class="rt-fill" width="<?= max(1, (int) $c['score']) ?>" height="4"/></svg>
            </a>
            <?php endforeach; ?>
        </div>
    </section>

    <section class="hud hud-exposures" aria-labelledby="h-top">
        <h2 id="h-top" class="hud-title"><?= e(__('Top exposures')) ?></h2>
        <?php if ($d['top'] === []): ?><p class="hud-empty"><?= e(__('Nothing open. Good.')) ?></p><?php endif; ?>
        <ul class="hud-list">
            <?php foreach ($d['top'] as $f): ?>
            <li><span class="sev-tag sev-<?= e($f['severity']) ?>"><i class="bi <?= $f['severity'] === 'fail' ? 'bi-x-octagon' : 'bi-exclamation-triangle' ?>" aria-hidden="true"></i> <?= e($f['severity'] === 'fail' ? __('Fail') : __('Warning')) ?></span>
                <a href="<?= e(url('/findings/' . (int) $f['id'])) ?>"><?= e($f['title']) ?></a><?php if ((int) $f['kev'] === 1): ?> <span class="kev-tag"><?= e(__('KEV')) ?></span><?php endif; ?>
                <span class="hud-meta"><?= e($f['client']) ?> · <code><?= e($f['target']) ?></code></span></li>
            <?php endforeach; ?>
        </ul>
    </section>

    <section class="hud hud-feed" aria-labelledby="h-feed">
        <h2 id="h-feed" class="hud-title"><?= e(__('Activity')) ?> <span class="live-dot" aria-hidden="true"></span></h2>
        <?php if ($d['activity'] === []): ?><p class="hud-empty"><?= e(__('No activity yet.')) ?></p><?php endif; ?>
        <ol class="feed">
            <?php foreach ($d['activity'] as $a): ?>
            <li class="<?= e($eventClass($a['kind'], $a['severity'])) ?>">
                <span class="feed-time"><?= e(substr(when((string) $a['at']), 5, 11)) ?></span>
                <span class="feed-kind"><?= e($eventWord($a['kind'])) ?></span>
                <a href="<?= e(url($a['link'])) ?>"><?= e(str_starts_with($a['kind'], 'scan_') ? __('{type} scan', ['type' => strtoupper($a['title'])]) : $a['title']) ?></a>
                <span class="hud-meta"><?= e($a['client']) ?></span>
            </li>
            <?php endforeach; ?>
        </ol>
    </section>

    <section class="hud hud-surface" aria-labelledby="h-surface">
        <h2 id="h-surface" class="hud-title"><?= e(__('Attack surface')) ?></h2>
        <?= Svg::bars($d['surface']['categories'], __('Open services by type')) ?>
        <p class="hud-sub"><?= e(__('{t} TLS endpoints · {w} web pages checked', ['t' => $d['surface']['tls'], 'w' => $d['surface']['web']])) ?></p>
    </section>

    <section class="hud hud-certs" aria-labelledby="h-certs">
        <h2 id="h-certs" class="hud-title"><?= e(__('Certificates, next 30 days')) ?></h2>
        <?php if ($d['certs'] === []): ?><p class="hud-empty"><?= e(__('None expiring.')) ?></p><?php endif; ?>
        <ul class="cert-line">
            <?php foreach ($d['certs'] as $c): ?>
            <li class="<?= $c['days'] < 0 ? 'c-expired' : ($c['days'] <= 14 ? 'c-soon' : 'c-later') ?>">
                <span class="c-days"><?= e($c['days'] < 0 ? __('expired') : __('{n} d', ['n' => $c['days']])) ?></span>
                <span class="c-name"><?= e($c['name']) ?></span>
                <span class="hud-meta"><?= e($c['client']) ?> · <code><?= e($c['endpoint']) ?></code></span>
            </li>
            <?php endforeach; ?>
        </ul>
    </section>
</div>
