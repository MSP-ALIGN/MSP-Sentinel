<?php
/**
 * Report branding card (admins). Expects: $branding (values, logo data: URI preview).
 * Every value is escaped. The logo is re-encoded by the server before it is stored. The preview links open a made-up
 * report with the saved branding (GET /admin/branding/preview, admins only).
 */
use Sentinel\Core\Csrf;

$bv = $branding;
/** One labelled text input for a branding field; every value is escaped. */
$text = static function (string $name, string $label, int $max, string $placeholder = '', string $help = '') use ($bv): string {
    return '<label class="form-label small mb-0" for="' . e($name) . '">' . e($label) . '</label>'
        . '<input class="form-control form-control-sm" id="' . e($name) . '" name="' . e($name) . '" value="' . e($bv[$name]) . '" maxlength="' . $max . '"'
        . ($placeholder !== '' ? ' placeholder="' . e($placeholder) . '"' : '') . ($help !== '' ? ' aria-describedby="' . e($name) . '-help"' : '') . '>'
        . ($help !== '' ? '<div class="form-text" id="' . e($name) . '-help">' . e($help) . '</div>' : '');
};
?>
<div class="card">
    <div class="card-header d-flex flex-wrap align-items-center gap-2">
        <h2 class="card-title h5 mb-0"><?= e(__('Report branding')) ?></h2>
        <div class="ms-auto d-flex flex-wrap gap-2">
            <a class="btn btn-outline-secondary btn-sm" href="<?= e(url('/admin/branding/preview?kind=executive')) ?>" target="_blank" rel="noopener"><i class="bi bi-eye me-1" aria-hidden="true"></i><?= e(__('Preview executive summary')) ?></a>
            <a class="btn btn-outline-secondary btn-sm" href="<?= e(url('/admin/branding/preview?kind=technical')) ?>" target="_blank" rel="noopener"><i class="bi bi-eye me-1" aria-hidden="true"></i><?= e(__('Preview technical report')) ?></a>
        </div>
    </div>
    <form method="post" action="<?= e(url('/admin/branding')) ?>" enctype="multipart/form-data" novalidate>
        <?= Csrf::field() ?>
        <div class="card-body">
            <h3 class="h6 mb-2"><?= e(__('Look')) ?></h3>
            <div class="row g-2 mb-3">
                <div class="col-12"><?= $text('brand_name', __('Company name on reports'), 100, (string) $bv['product_name']) ?></div>
                <div class="col-4"><label class="form-label small mb-0" for="brand_color"><?= e(__('Brand color')) ?></label>
                    <input class="form-control form-control-sm form-control-color w-100" type="color" id="brand_color" name="brand_color" value="<?= e($bv['brand_color']) ?>"></div>
                <div class="col-4"><label class="form-label small mb-0" for="brand_accent"><?= e(__('Accent color')) ?></label>
                    <input class="form-control form-control-sm form-control-color w-100" type="color" id="brand_accent" name="brand_accent" value="<?= e($bv['brand_accent']) ?>"></div>
                <div class="col-4"><label class="form-label small mb-0" for="report_cover"><?= e(__('Cover page')) ?></label>
                    <select class="form-select form-select-sm" id="report_cover" name="report_cover">
                        <option value="color" <?= $bv['report_cover'] === 'color' ? 'selected' : '' ?>><?= e(__('Full color')) ?></option>
                        <option value="white" <?= $bv['report_cover'] === 'white' ? 'selected' : '' ?>><?= e(__('White')) ?></option>
                    </select></div>
                <div class="col-8"><label class="form-label small mb-0" for="brand_logo"><?= e(__('Logo (PNG or JPEG, up to 2 MB)')) ?></label>
                    <input class="form-control form-control-sm" type="file" id="brand_logo" name="brand_logo" accept="image/png,image/jpeg">
                    <?php if ($bv['logo'] !== ''): ?>
                    <div class="mt-2 d-flex align-items-center gap-2"><img src="<?= e($bv['logo']) ?>" alt="<?= e(__('Current logo')) ?>" class="branding-logo">
                        <div class="form-check small"><input class="form-check-input" type="checkbox" id="remove_logo" name="remove_logo" value="1"><label class="form-check-label" for="remove_logo"><?= e(__('Remove logo')) ?></label></div></div>
                    <?php endif; ?>
                    <div class="form-text"><?= e(__('On a full-color cover the logo sits on a white panel, so dark logos stay readable.')) ?></div></div>
                <div class="col-4"><label class="form-label small mb-0" for="report_paper"><?= e(__('Paper size')) ?></label>
                    <select class="form-select form-select-sm" id="report_paper" name="report_paper">
                        <?php foreach (['A4', 'Letter'] as $p): ?><option value="<?= e($p) ?>" <?= $bv['report_paper'] === $p ? 'selected' : '' ?>><?= e($p) ?></option><?php endforeach; ?>
                    </select></div>
            </div>

            <h3 class="h6 mb-2"><?= e(__('Contact details')) ?></h3>
            <div class="row g-2 mb-3">
                <div class="col-12"><label class="form-label small mb-0" for="brand_address"><?= e(__('Address')) ?></label>
                    <textarea class="form-control form-control-sm" id="brand_address" name="brand_address" rows="2" maxlength="200" placeholder="<?= e(__("100 Example Street\nExample City")) ?>"><?= e($bv['brand_address']) ?></textarea></div>
                <div class="col-12"><div class="row g-2">
                    <div class="col-6"><?= $text('brand_phone', __('Phone'), 40, '555-0100') ?></div>
                    <div class="col-6"><?= $text('brand_email', __('Email'), 120, 'support@msp.example') ?></div>
                    <div class="col-12"><?= $text('brand_website', __('Website'), 120, 'www.msp.example') ?></div>
                </div></div>
            </div>

            <h3 class="h6 mb-2"><?= e(__('Sign-off')) ?></h3>
            <div class="row g-2 mb-3">
                <div class="col-6"><?= $text('report_prepared_by', __('Prepared by'), 100, __('Jo Example')) ?></div>
                <div class="col-6"><?= $text('report_prepared_title', __('Job title'), 100, __('Security lead')) ?></div>
                <div class="col-12"><label class="form-label small mb-0" for="report_signoff"><?= e(__('Closing note on the last page')) ?></label>
                    <textarea class="form-control form-control-sm" id="report_signoff" name="report_signoff" rows="2" maxlength="600" placeholder="<?= e(__('Questions about this report? Contact us and we will walk you through it.')) ?>"><?= e($bv['report_signoff']) ?></textarea></div>
            </div>

            <h3 class="h6 mb-2"><?= e(__('Every page')) ?></h3>
            <div class="row g-2">
                <div class="col-12"><?= $text('report_confidential', __('Confidential label'), 120, \Sentinel\Reports\ReportTheme::CONFIDENTIAL_DEFAULT, __('Shown on the cover and at the top of every printed page. {client} becomes the client\'s name. Leave empty for none.')) ?></div>
                <div class="col-12"><label class="form-label small mb-0" for="brand_footer"><?= e(__('Footer note')) ?></label>
                    <textarea class="form-control form-control-sm" id="brand_footer" name="brand_footer" rows="2" maxlength="500" placeholder="<?= e(__('For example a registration number or a legal note.')) ?>"><?= e($bv['brand_footer']) ?></textarea></div>
                <div class="col-12 form-check ms-2">
                    <input class="form-check-input" type="checkbox" id="report_powered_by" name="report_powered_by" value="1" <?= $bv['report_powered_by'] === '1' ? 'checked' : '' ?>>
                    <label class="form-check-label small" for="report_powered_by"><?= e(__('Show a small "Generated by MSP Sentinel" line at the end of reports')) ?></label>
                </div>
            </div>
            <p class="small text-body-secondary mt-2 mb-0"><?= e(__('Branding is copied into each report when it is created, so saved reports never change. The previews use the saved branding: save first, then preview. Print a report to PDF from your browser for a page-numbered document.')) ?></p>
        </div>
        <div class="card-footer"><button type="submit" class="btn btn-primary btn-sm"><?= e(__('Save branding')) ?></button></div>
    </form>
</div>
