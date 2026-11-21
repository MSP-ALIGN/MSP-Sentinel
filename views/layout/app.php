<?php
/**
 * Main signed-in layout (AdminLTE 4).
 * Expects: $title, $content (already rendered HTML from a view), $currentUser (public fields).
 * Security: $content is trusted rendered output. Every other value is escaped.
 */

use Sentinel\Auth\Role;
use Sentinel\Core\App;
use Sentinel\Core\Csrf;

$product = App::productName();
$isAdmin = isset($currentUser['role']) && Role::atLeast((string) $currentUser['role'], Role::ADMIN);
$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
$path = substr($path, strlen(App::basePath())) ?: '/';
$navItem = static function (string $href, string $icon, string $label) use ($path): string {
    $active = ($href === '/' ? $path === '/' : str_starts_with($path, $href)) ? ' active' : '';
    return '<li class="nav-item"><a href="' . e(url($href)) . '" class="nav-link' . $active . '">'
        . '<i class="nav-icon bi ' . e($icon) . '" aria-hidden="true"></i><p>' . e($label) . '</p></a></li>';
};
try {
    $sourceUrl = App::settings()->get('source_url');
} catch (\Throwable) {
    $sourceUrl = \Sentinel\Core\Settings::DEFAULTS['source_url'];
}
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
<body class="layout-fixed sidebar-expand-lg bg-body-tertiary">
<div class="app-wrapper">
    <nav class="app-header navbar navbar-expand bg-body">
        <div class="container-fluid">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" data-lte-toggle="sidebar" href="#" role="button" aria-label="<?= e(__('Toggle menu')) ?>"><i class="bi bi-list" aria-hidden="true"></i></a>
                </li>
            </ul>
            <ul class="navbar-nav ms-auto">
                <?php if ($currentUser !== null): ?>
                <li class="nav-item dropdown">
                    <a href="#" class="nav-link dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="bi bi-person-circle me-1" aria-hidden="true"></i><?= e($currentUser['display_name']) ?>
                        <span class="badge text-bg-secondary ms-1"><?= e(Role::labels()[$currentUser['role']] ?? '') ?></span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li><a class="dropdown-item" href="<?= e(url('/profile')) ?>"><i class="bi bi-person me-2" aria-hidden="true"></i><?= e(__('My profile')) ?></a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li>
                            <form method="post" action="<?= e(url('/logout')) ?>" class="px-0">
                                <?= Csrf::field() ?>
                                <button type="submit" class="dropdown-item"><i class="bi bi-box-arrow-right me-2" aria-hidden="true"></i><?= e(__('Sign out')) ?></button>
                            </form>
                        </li>
                    </ul>
                </li>
                <?php endif; ?>
            </ul>
        </div>
    </nav>

    <aside class="app-sidebar bg-body-secondary shadow" data-bs-theme="dark">
        <div class="sidebar-brand">
            <a href="<?= e(url('/')) ?>" class="brand-link">
                <i class="bi bi-shield-check brand-icon" aria-hidden="true"></i>
                <span class="brand-text fw-light"><?= e($product) ?></span>
            </a>
        </div>
        <div class="sidebar-wrapper">
            <nav class="mt-2" aria-label="<?= e(__('Main menu')) ?>">
                <ul class="nav sidebar-menu flex-column" role="menu">
                    <?= $navItem('/', 'bi-speedometer2', __('Dashboard')) ?>
                    <?= $navItem('/clients', 'bi-building', __('Clients')) ?>
                    <?php if ($isAdmin): ?>
                    <li class="nav-header"><?= e(__('ADMINISTRATION')) ?></li>
                    <?= $navItem('/users', 'bi-people', __('Users')) ?>
                    <?= $navItem('/admin/audit', 'bi-journal-text', __('Audit log')) ?>
                    <?= $navItem('/admin/settings', 'bi-gear', __('Settings')) ?>
                    <?php endif; ?>
                    <li class="nav-header"><?= e(__('SUPPORT')) ?></li>
                    <?= $navItem('/help', 'bi-question-circle', __('Help')) ?>
                </ul>
            </nav>
        </div>
    </aside>

    <main class="app-main">
        <div class="app-content-header">
            <div class="container-fluid">
                <h1 class="h3 mb-0"><?= e($title ?? '') ?></h1>
            </div>
        </div>
        <div class="app-content">
            <div class="container-fluid">
                <?php require __DIR__ . '/../partials/flashes.php'; ?>
                <?= $content ?>
            </div>
        </div>
    </main>

    <footer class="app-footer small">
        <div class="float-end d-none d-sm-inline">
            <a href="<?= e($sourceUrl) ?>" rel="noopener noreferrer" target="_blank"><?= e(__('Source code')) ?></a> · AGPL-3.0
        </div>
        <?= e($product) ?> <?= e(__('version')) ?> <?= e(App::version()) ?>
    </footer>
</div>
<script src="<?= e(asset('vendor/bootstrap/bootstrap.bundle.min.js')) ?>"></script>
<script src="<?= e(asset('vendor/adminlte/adminlte.min.js')) ?>"></script>
<script src="<?= e(asset('js/sentinel.js')) ?>"></script>
</body>
</html>
