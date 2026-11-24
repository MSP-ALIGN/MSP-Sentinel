<?php
/**
 * Settings (admins), in tabs: General, Alerts, Fix due dates, Report branding, Vulnerability data.
 * Expects: $values (untrusted strings), $errors, $alerts, $duePolicy, $branding, $feeds, $nvdKeySet, $nvdKeyUsable,
 * $feedsRefresh (FeedSchedule::status()). Each tab pane's id is its address (#alerts, #due-dates, ...): the page
 * opens that tab (sentinel.js), so redirects after saving land on the right one. Every value is escaped.
 */
use Sentinel\Core\Csrf;

$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<ul class="nav nav-tabs mb-3" role="tablist" data-hash-tabs>
    <?php foreach (['general' => [__('General'), 'bi-sliders'], 'alerts' => [__('Alerts'), 'bi-bell'], 'due-dates' => [__('Fix due dates'), 'bi-calendar-check'], 'engagements' => [__('Pen-test engagements'), 'bi-shield-lock'],
                    'branding' => [__('Report branding'), 'bi-palette'], 'feeds' => [__('Vulnerability data'), 'bi-database']] as $id => [$label, $icon]): ?>
    <li class="nav-item" role="presentation"><button class="nav-link<?= $id === 'general' ? ' active' : '' ?>" id="<?= e($id) ?>-tab" data-bs-toggle="tab" data-bs-target="#<?= e($id) ?>" type="button" role="tab"
        aria-controls="<?= e($id) ?>" aria-selected="<?= $id === 'general' ? 'true' : 'false' ?>"><i class="bi <?= e($icon) ?> me-1" aria-hidden="true"></i><?= e($label) ?></button></li>
    <?php endforeach; ?>
</ul>
<div class="row"><div class="col-xl-8"><div class="tab-content">
<div class="tab-pane fade show active" id="general" role="tabpanel" aria-labelledby="general-tab" tabindex="0">
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('General')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/settings')) ?>" novalidate>
    <div class="card-body">
        <?= Csrf::field() ?>
        <div class="mb-3">
            <label for="product_name" class="form-label"><?= e(__('Product name')) ?></label>
            <input type="text" class="form-control<?= $invalid('product_name') ?>" id="product_name" name="product_name" value="<?= e($values['product_name']) ?>" maxlength="60" required>
            <div class="form-text"><?= e(__('Shown in the menu, page titles and authenticator apps. Change it to use your own brand (white-label).')) ?></div>
            <?php $field = 'product_name'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
        <div class="mb-3">
            <label for="source_url" class="form-label"><?= e(__('Source code address')) ?></label>
            <input type="url" class="form-control<?= $invalid('source_url') ?>" id="source_url" name="source_url" value="<?= e($values['source_url']) ?>" maxlength="255" required>
            <div class="form-text"><?= e(__('The AGPL-3.0 licence requires that users can get the source code of the version you run. If you change the code, point this at your copy.')) ?></div>
            <?php $field = 'source_url'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
    </div>
    <div class="card-footer"><button type="submit" class="btn btn-primary"><?= e(__('Save settings')) ?></button></div>
    </form>
</div>
</div>
<div class="tab-pane fade" id="alerts" role="tabpanel" aria-labelledby="alerts-tab" tabindex="0"><?php require __DIR__ . '/alerts.php'; ?></div>
<div class="tab-pane fade" id="due-dates" role="tabpanel" aria-labelledby="due-dates-tab" tabindex="0"><?php require __DIR__ . '/due.php'; ?></div>
<div class="tab-pane fade" id="engagements" role="tabpanel" aria-labelledby="engagements-tab" tabindex="0"><?php require __DIR__ . '/engagements.php'; ?></div>
<div class="tab-pane fade" id="branding" role="tabpanel" aria-labelledby="branding-tab" tabindex="0"><?php require __DIR__ . '/branding.php'; ?></div>
<div class="tab-pane fade" id="feeds" role="tabpanel" aria-labelledby="feeds-tab" tabindex="0">
<div class="card">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Vulnerability data')) ?></h2></div>
    <div class="card-body small">
        <table class="table table-sm mb-2">
            <thead><tr><th scope="col"><?= e(__('Feed')) ?></th><th scope="col"><?= e(__('Last success (UTC)')) ?></th><th scope="col"><?= e(__('Last attempt')) ?></th></tr></thead>
            <tbody>
            <?php foreach (['kev' => __('CISA Known Exploited Vulnerabilities'), 'nvd' => __('NVD (product queries)'), 'epss' => __('FIRST EPSS scores')] as $key => $label): ?>
            <?php $f = $feeds[$key] ?? null; ?>
            <tr>
                <td><?= e($label) ?></td>
                <td><?= e($f['last_success'] ?? __('never')) ?></td>
                <td><?= e($f['last_attempt'] ?? '—') ?><?php if ($f !== null && $f['message'] !== ''): ?><div class="text-body-secondary"><?= e($f['message']) ?></div><?php endif; ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <p class="mb-0"><?= e(match (true) {
            $nvdKeySet && $nvdKeyUsable => __('An NVD API key is configured (faster NVD queries).'),
            $nvdKeySet => __('The NVD API key in the config file is not used: it is malformed, or nvd.base_url is not https.'),
            default => __('No NVD API key configured: NVD queries are limited to about 5 per 30 seconds. Add nvd.api_key to config/config.php to speed them up.'),
        }) ?></p>
        <?php require __DIR__ . '/../partials/feeds_refresh.php'; ?>
    </div>
</div>
</div>
</div></div></div>
