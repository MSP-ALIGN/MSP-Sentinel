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
        <div class="mb-3">
            <?php // 1.48: how times are shown (users can pick their own under My profile) and where new clients start. ?>
            <label for="display_timezone" class="form-label"><?= e(__('Time zone')) ?></label>
            <input class="form-control<?= $invalid('display_timezone') ?>" id="display_timezone" name="display_timezone" list="org-timezone-list" value="<?= e($values['display_timezone'] ?? 'UTC') ?>" required autocomplete="off" spellcheck="false" placeholder="<?= e(__('Type a city, e.g. Los_Angeles')) ?>">
            <datalist id="org-timezone-list">
                <?php foreach (\DateTimeZone::listIdentifiers() as $tz): ?><option value="<?= e($tz) ?>"></option><?php endforeach; ?>
            </datalist>
            <div class="form-text"><?= e(__('Times in Sentinel are shown in this time zone (each user can choose their own under My profile), and new clients start in it, also those added from ITFlow. Sentinel still stores and compares times in UTC, so daylight-saving changes never shift a scan.')) ?></div>
            <?php $field = 'display_timezone'; require __DIR__ . '/../partials/field_error.php'; ?>
        </div>
    </div>
    <div class="card-footer"><button type="submit" class="btn btn-primary"><?= e(__('Save settings')) ?></button></div>
    </form>
</div>
<?php if (($utcClients ?? []) !== [] && ($mayEditClients ?? false)): ?>
<div class="card mt-3">
    <div class="card-header"><h2 class="card-title h5 mb-0"><?= e(__('Clients still on UTC')) ?></h2></div>
    <form method="post" action="<?= e(url('/admin/settings/clients-timezone')) ?>" data-confirm="<?= e(__('Move these clients to {zone}? Their scan windows keep the same times, now in that time zone.', ['zone' => $values['display_timezone'] ?? ''])) ?>">
    <div class="card-body">
        <?= Csrf::field() ?>
        <p class="small mb-2"><?= e(__('These clients use UTC, so their scan windows count in UTC. Move them to {zone} to count their windows in your time; the window times (for example 22:00 to 06:00) stay the same numbers.', ['zone' => $values['display_timezone'] ?? ''])) ?></p>
        <p class="small text-body-secondary mb-0"><?= e(implode(', ', array_map(static fn (array $c): string => (string) $c['name'], $utcClients))) ?></p>
    </div>
    <div class="card-footer"><button type="submit" class="btn btn-outline-primary btn-sm"><?= e(__('Move {n} client(s) to {zone}', ['n' => count($utcClients), 'zone' => $values['display_timezone'] ?? ''])) ?></button></div>
    </form>
</div>
<?php endif; ?>
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
            <thead><tr><th scope="col"><?= e(__('Feed')) ?></th><th scope="col"><?= e(__('Last success')) ?></th><th scope="col"><?= e(__('Last attempt')) ?></th></tr></thead>
            <tbody>
            <?php foreach (['kev' => __('CISA Known Exploited Vulnerabilities'), 'nvd' => __('NVD (product queries)'), 'epss' => __('FIRST EPSS scores')] as $key => $label): ?>
            <?php $f = $feeds[$key] ?? null; ?>
            <tr>
                <td><?= e($label) ?></td>
                <td><?= e(when($f['last_success'] ?? null, null, __('never'))) ?></td>
                <td><?= e(when($f['last_attempt'] ?? null, null, '—')) ?><?php if ($f !== null && $f['message'] !== ''): ?><div class="text-body-secondary"><?= e($f['message']) ?></div><?php endif; ?></td>
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
