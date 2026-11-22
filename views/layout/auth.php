<?php
/**
 * Minimal layout for sign-in pages and errors shown to signed-out visitors.
 * Expects: $title, $content (trusted rendered HTML). Everything else is escaped.
 */

use Sentinel\Core\App;

$product = App::productName();
?>
<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($title ?? '') ?> · <?= e($product) ?></title>
    <link rel="stylesheet" href="<?= e(asset('vendor/bootstrap-icons/bootstrap-icons.min.css')) ?>">
    <link rel="icon" href="<?= e(asset('img/favicon.svg')) ?>" type="image/svg+xml">
    <link rel="stylesheet" href="<?= e(asset('vendor/adminlte/adminlte.min.css')) ?>">
    <link rel="stylesheet" href="<?= e(asset('css/theme.css')) ?>">
    <link rel="stylesheet" href="<?= e(asset('css/sentinel.css')) ?>">
</head>
<body class="login-page bg-body-secondary">
<div class="login-box auth-box">
    <div class="text-center mb-3">
        <img src="<?= e(asset('img/logo.svg')) ?>" alt="" class="auth-mark" width="92" height="92">
        <div class="h3 auth-product mt-2 mb-0"><?= e($product) ?></div>
        <div class="auth-tagline"><?= e(__('External exposure monitoring')) ?></div>
    </div>
    <div class="card card-outline card-primary">
        <div class="card-body login-card-body">
            <?= $content ?>
        </div>
    </div>
    <p class="text-center text-body-secondary auth-warning mt-3"><i class="bi bi-shield-lock me-1" aria-hidden="true"></i><?= e(__('Authorised users only. Activity is logged.')) ?></p>
</div>
<script src="<?= e(asset('vendor/bootstrap/bootstrap.bundle.min.js')) ?>"></script>
<script src="<?= e(asset('vendor/qrcode/qrcode.js')) ?>"></script>
<script src="<?= e(asset('js/sentinel.js')) ?>"></script>
</body>
</html>
