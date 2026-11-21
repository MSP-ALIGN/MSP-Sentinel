<?php
/**
 * Minimal layout for sign-in pages and errors shown to signed-out visitors.
 * Expects: $title, $content (trusted rendered HTML). Everything else is escaped.
 */

use Sentinel\Core\App;

$product = App::productName();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($title ?? '') ?> · <?= e($product) ?></title>
    <link rel="stylesheet" href="<?= e(asset('vendor/bootstrap-icons/bootstrap-icons.min.css')) ?>">
    <link rel="stylesheet" href="<?= e(asset('vendor/adminlte/adminlte.min.css')) ?>">
    <link rel="stylesheet" href="<?= e(asset('css/sentinel.css')) ?>">
</head>
<body class="login-page bg-body-secondary">
<div class="login-box auth-box">
    <div class="text-center mb-3">
        <i class="bi bi-shield-check auth-logo" aria-hidden="true"></i>
        <div class="h3 fw-light mt-1"><?= e($product) ?></div>
    </div>
    <div class="card card-outline card-primary">
        <div class="card-body login-card-body">
            <?= $content ?>
        </div>
    </div>
    <p class="text-center text-body-secondary small mt-3"><?= e(__('Authorised users only. Activity is logged.')) ?></p>
</div>
<script src="<?= e(asset('vendor/bootstrap/bootstrap.bundle.min.js')) ?>"></script>
<script src="<?= e(asset('vendor/qrcode/qrcode.js')) ?>"></script>
<script src="<?= e(asset('js/sentinel.js')) ?>"></script>
</body>
</html>
