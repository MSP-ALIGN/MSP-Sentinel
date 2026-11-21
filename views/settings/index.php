<?php
/** General settings. Expects: $values (untrusted strings), $errors. */
use Sentinel\Core\Csrf;

$invalid = static fn (string $f): string => !empty($errors[$f]) ? ' is-invalid' : '';
?>
<div class="row"><div class="col-lg-7">
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
</div></div>
