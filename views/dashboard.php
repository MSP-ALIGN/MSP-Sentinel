<?php
/** Dashboard placeholder for the skeleton release. Expects: $currentUser, $version. */
?>
<div class="row g-3">
    <div class="col-md-4">
        <div class="small-box text-bg-secondary">
            <div class="inner"><h3>0</h3><p><?= e(__('Clients')) ?></p></div>
            <i class="small-box-icon bi bi-building" aria-hidden="true"></i>
        </div>
    </div>
    <div class="col-md-4">
        <div class="small-box text-bg-secondary">
            <div class="inner"><h3>0</h3><p><?= e(__('Open findings')) ?></p></div>
            <i class="small-box-icon bi bi-exclamation-octagon" aria-hidden="true"></i>
        </div>
    </div>
    <div class="col-md-4">
        <div class="small-box text-bg-secondary">
            <div class="inner"><h3>—</h3><p><?= e(__('Last scan')) ?></p></div>
            <i class="small-box-icon bi bi-clock-history" aria-hidden="true"></i>
        </div>
    </div>
</div>
<div class="card mt-3">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Welcome, {name}', ['name' => $currentUser['display_name']])) ?></h2></div>
    <div class="card-body">
        <p><?= e(__('This is the foundation release ({version}): sign-in with two-factor authentication, user roles, audit log and settings.', ['version' => $version])) ?></p>
        <p class="mb-0"><?= e(__('Client management, the "authorised to scan" register and external scanning arrive in the next releases. Nothing is scanned yet.')) ?></p>
    </div>
</div>
