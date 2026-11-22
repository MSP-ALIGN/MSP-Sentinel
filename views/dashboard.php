<?php
/**
 * Dashboard.
 * Expects: $currentUser, $version, $clientCount, $activeAuthorisations, $expiringAuthorisations, $expiringCerts, $kevCounts, $globallyPaused.
 */
?>
<?php if ($globallyPaused): ?>
<?php require __DIR__ . '/partials/kill_switch.php'; ?>
<?php endif; ?>
<div class="row g-3">
    <div class="col-md-6 col-xl-3">
        <a class="text-decoration-none" href="<?= e(url('/clients')) ?>">
        <div class="small-box text-bg-primary">
            <div class="inner"><h3><?= e($clientCount) ?></h3><p><?= e(__('Clients')) ?></p></div>
            <i class="small-box-icon bi bi-building" aria-hidden="true"></i>
        </div>
        </a>
    </div>
    <div class="col-md-6 col-xl-3">
        <div class="small-box <?= $activeAuthorisations > 0 ? 'text-bg-success' : 'text-bg-secondary' ?>">
            <div class="inner"><h3><?= e($activeAuthorisations) ?></h3><p><?= e(__('Active scan authorisations')) ?></p></div>
            <i class="small-box-icon bi bi-file-earmark-check" aria-hidden="true"></i>
        </div>
    </div>
    <div class="col-md-6 col-xl-3">
        <div class="small-box <?= $expiringAuthorisations > 0 ? 'text-bg-warning' : 'text-bg-secondary' ?>">
            <div class="inner"><h3><?= e($expiringAuthorisations) ?></h3><p><?= e(__('Authorisations ending within 30 days')) ?></p></div>
            <i class="small-box-icon bi bi-calendar-x" aria-hidden="true"></i>
        </div>
    </div>
    <div class="col-md-6 col-xl-3">
        <div class="small-box <?= $kevCounts['confirmed_kev'] > 0 ? 'text-bg-danger' : ($kevCounts['possible_kev'] > 0 ? 'text-bg-warning' : 'text-bg-secondary') ?>">
            <div class="inner"><h3><?= e($kevCounts['confirmed_kev']) ?></h3><p><?= e(__('Known exploited vulnerabilities (confirmed)')) ?><?php if ($kevCounts['possible_kev'] > 0): ?><br><span class="small"><?= e(__('+{n} possible (version unknown)', ['n' => $kevCounts['possible_kev']])) ?></span><?php endif; ?></p></div>
            <i class="small-box-icon bi bi-bug" aria-hidden="true"></i>
        </div>
    </div>
    <div class="col-md-6 col-xl-3">
        <div class="small-box <?= $expiringCerts > 0 ? 'text-bg-danger' : 'text-bg-secondary' ?>">
            <div class="inner"><h3><?= e($expiringCerts) ?></h3><p><?= e(__('Certificates expired or expiring within 14 days')) ?></p></div>
            <i class="small-box-icon bi bi-shield-exclamation" aria-hidden="true"></i>
        </div>
    </div>
</div>
<div class="card mt-3">
    <div class="card-header d-flex align-items-center flex-wrap gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Welcome, {name}', ['name' => $currentUser['display_name']])) ?></h2>
        <?php if (!$globallyPaused): ?><div class="ms-auto"><?php require __DIR__ . '/partials/kill_switch.php'; ?></div><?php endif; ?>
    </div>
    <div class="card-body">
        <p><?= e(__('Version {version}: clients, sites and the "authorised to scan" register. Every scan Sentinel will ever run must fall inside an active authorisation.', ['version' => $version])) ?></p>
        <p class="mb-0"><?= e(__('External scanning arrives in the next releases. Nothing is scanned yet.')) ?></p>
    </div>
</div>
