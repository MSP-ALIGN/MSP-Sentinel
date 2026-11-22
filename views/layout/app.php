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
// Normalise the path exactly as Request::fromGlobals does (decode, strip the base path only if it is
// a prefix, drop a trailing slash), so menu state always matches the page the router served.
$path = rawurldecode((string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?? '/'));
$base = App::basePath();
if ($base !== '' && str_starts_with($path, $base)) {
    $path = substr($path, strlen($base));
}
$path = $path === '' || $path[0] !== '/' ? '/' . $path : $path;
if ($path !== '/') {
    $path = rtrim($path, '/') ?: '/';
}
$navItem = static function (string $href, string $icon, string $label) use ($path): string {
    // "/" and "/admin" (the overview) are active only on exactly that page; others on any page below them.
    $active = (in_array($href, ['/', '/admin'], true) ? $path === $href : ($path === $href || str_starts_with($path, $href . '/'))) ? ' active' : '';
    return '<li class="nav-item"><a href="' . e(url($href)) . '" class="nav-link' . $active . '"' . ($active !== '' ? ' aria-current="page"' : '') . '>'
        . '<i class="nav-icon bi ' . e($icon) . '" aria-hidden="true"></i><p>' . e($label) . '</p></a></li>';
};
// Administration is a separate section: its own left menu on admin pages, reached from the user drop-down.
$inAdmin = $isAdmin && ($path === '/admin' || str_starts_with($path, '/admin/') || $path === '/users' || str_starts_with($path, '/users/'));
$adminItems = [
    ['/admin', 'bi-grid-1x2', __('Overview')],
    ['/users', 'bi-people', __('Users')],
    ['/admin/settings', 'bi-gear', __('Settings')],
    ['/admin/api', 'bi-plug', __('API')],
    ['/admin/system', 'bi-heart-pulse', __('System')],
    ['/admin/audit', 'bi-journal-text', __('Audit log')],
];
try {
    $sourceUrl = App::settings()->get('source_url');
} catch (\Throwable) {
    $sourceUrl = \Sentinel\Core\Settings::DEFAULTS['source_url'];
}
?>
<!doctype html>
<html lang="en" data-bs-theme="<?= ($currentUser['ui_theme'] ?? 'dark') === 'light' ? 'light' : 'dark' ?>">
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
<body class="layout-fixed sidebar-expand-lg bg-body-tertiary">
<div class="app-wrapper">
    <nav class="app-header navbar navbar-expand bg-body">
        <div class="container-fluid">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" data-lte-toggle="sidebar" href="#" role="button" aria-label="<?= e(__('Toggle menu')) ?>"><i class="bi bi-list" aria-hidden="true"></i></a>
                </li>
            </ul>
            <?php $build = App::build(); if ($build !== null && $build['development']): ?>
            <span class="badge text-bg-warning ms-2" title="<?= e(__('Installed from the {b} branch at commit {c}: newest changes, not a release. Use it for testing, not for production.', ['b' => $build['branch'], 'c' => $build['commit']])) ?>"><i class="bi bi-cone-striped" aria-hidden="true"></i> <?= e(__('Development build')) ?> · <?= e($build['branch']) ?></span>
            <?php endif; ?>
            <ul class="navbar-nav ms-auto">
                <?php if ($currentUser !== null): ?>
                <?php
                try {
                    $unreadStmt = App::db()->prepare('SELECT COUNT(*) FROM notifications WHERE user_id = :u AND read_at IS NULL');
                    $unreadStmt->execute(['u' => (int) $currentUser['id']]);
                    $unread = (int) $unreadStmt->fetchColumn();
                } catch (\Throwable) {
                    $unread = 0;
                }
                ?>
                <li class="nav-item">
                    <a class="nav-link position-relative" href="<?= e(url('/notifications')) ?>" aria-label="<?= e(__('Notifications ({n} unread)', ['n' => $unread])) ?>">
                        <i class="bi bi-bell" aria-hidden="true"></i>
                        <?php if ($unread > 0): ?><span class="badge text-bg-danger notification-count"><?= e($unread > 99 ? '99+' : $unread) ?></span><?php endif; ?>
                    </a>
                </li>
                <li class="nav-item dropdown">
                    <a href="#" class="nav-link dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="bi bi-person-circle me-1" aria-hidden="true"></i><?= e($currentUser['display_name']) ?>
                        <span class="badge text-bg-secondary ms-1"><?= e(Role::labels()[$currentUser['role']] ?? '') ?></span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li><a class="dropdown-item" href="<?= e(url('/profile')) ?>"><i class="bi bi-person me-2" aria-hidden="true"></i><?= e(__('My profile')) ?></a></li>
                        <?php if ($isAdmin): ?>
                        <li><hr class="dropdown-divider"></li>
                        <li><h6 class="dropdown-header"><?= e(__('Administration')) ?></h6></li>
                        <?php foreach ($adminItems as [$href, $icon, $label]): ?>
                        <li><a class="dropdown-item" href="<?= e(url($href)) ?>"><i class="bi <?= e($icon) ?> me-2" aria-hidden="true"></i><?= e($label) ?></a></li>
                        <?php endforeach; ?>
                        <?php endif; ?>
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

    <aside class="app-sidebar bg-body-secondary shadow<?= $inAdmin ? ' is-admin' : (isset($clientNav) ? ' is-client' : '') ?>" data-bs-theme="dark">
        <div class="sidebar-brand">
            <a href="<?= e(url('/')) ?>" class="brand-link" title="<?= e($product) ?>">
                <img src="<?= e(asset('img/logo.svg')) ?>" alt="" class="brand-logo" width="34" height="34">
                <span class="brand-text"><?= e($product) ?></span>
            </a>
        </div>
        <div class="sidebar-wrapper">
            <?php if ($inAdmin): ?>
            <div class="admin-mode"><i class="bi bi-shield-lock" aria-hidden="true"></i><?= e(__('Administration')) ?></div>
            <nav class="mt-2" aria-label="<?= e(__('Administration menu')) ?>">
                <ul class="nav sidebar-menu flex-column">
                    <?php foreach ($adminItems as [$href, $icon, $label]): ?>
                    <?= $navItem($href, $icon, $label) ?>
                    <?php endforeach; ?>
                    <li class="nav-header"><?= e(__('LEAVE')) ?></li>
                    <li class="nav-item"><a href="<?= e(url('/')) ?>" class="nav-link admin-exit"><i class="nav-icon bi bi-arrow-left-circle" aria-hidden="true"></i><p><?= e(__('Back to Sentinel')) ?></p></a></li>
                    <?= $navItem('/help', 'bi-question-circle', __('Help')) ?>
                </ul>
            </nav>
            <?php elseif (isset($clientNav) && is_array($clientNav)): ?>
            <?php // A client's own menu (ClientController::nav): its sections, with the way back to all clients. ?>
            <nav class="mt-2" aria-label="<?= e(__('Client menu')) ?>">
                <ul class="nav sidebar-menu flex-column">
                    <li class="nav-item"><a href="<?= e(url('/clients')) ?>" class="nav-link admin-exit"><i class="nav-icon bi bi-arrow-left-circle" aria-hidden="true"></i><p><?= e(__('All clients')) ?></p></a></li>
                </ul>
            </nav>
            <div class="client-mode" title="<?= e($clientNav['name']) ?>"><i class="bi bi-building" aria-hidden="true"></i><span><?= e($clientNav['name']) ?></span>
                <?php if ($clientNav['demo']): ?><span class="badge text-bg-info"><?= e(__('Demo')) ?></span><?php endif; ?>
                <?php if ($clientNav['archived']): ?><span class="badge text-bg-secondary"><?= e(__('Archived')) ?></span><?php endif; ?></div>
            <nav aria-label="<?= e(__('Client sections')) ?>">
                <ul class="nav sidebar-menu flex-column">
                    <?php foreach ($clientNav['groups'] as $group): ?>
                    <?php if ($group['label'] !== null): ?><li class="nav-header"><?= e(mb_strtoupper($group['label'])) ?></li><?php endif; ?>
                    <?php foreach ($group['items'] as $it): ?>
                    <li class="nav-item"><a href="<?= e(url($it['url'])) ?>" class="nav-link<?= $it['active'] ? ' active' : '' ?>"<?= $it['active'] ? ' aria-current="page"' : '' ?>>
                        <i class="nav-icon bi <?= e($it['icon']) ?>" aria-hidden="true"></i><p><?= e($it['label']) ?><?php if (($it['badge'] ?? 0) > 0): ?> <span class="badge text-bg-danger ms-1"><?= (int) $it['badge'] ?></span><?php endif; ?></p></a></li>
                    <?php endforeach; ?>
                    <?php endforeach; ?>
                </ul>
            </nav>
            <?php else: ?>
            <nav class="mt-2" aria-label="<?= e(__('Main menu')) ?>">
                <ul class="nav sidebar-menu flex-column">
                    <?= $navItem('/', 'bi-speedometer2', __('Dashboard')) ?>
                    <?= $navItem('/clients', 'bi-building', __('Clients')) ?>
                    <?= $navItem('/findings', 'bi-exclamation-diamond', __('Findings')) ?>
                    <?= $navItem('/reports', 'bi-file-earmark-text', __('Reports')) ?>
                    <li class="nav-header"><?= e(__('SUPPORT')) ?></li>
                    <?= $navItem('/help', 'bi-question-circle', __('Help')) ?>
                </ul>
            </nav>
            <?php endif; ?>
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
        <?= e($product) ?> <?= e(__('version')) ?> <?= e(App::version()) ?><?php $build = App::build(); if ($build !== null && $build['development']): ?> (<?= e($build['branch']) ?> @ <?= e($build['commit']) ?>)<?php endif; ?>
    </footer>
</div>
<script src="<?= e(asset('vendor/bootstrap/bootstrap.bundle.min.js')) ?>"></script>
<script src="<?= e(asset('vendor/adminlte/adminlte.min.js')) ?>"></script>
<script src="<?= e(asset('js/sentinel.js')) ?>"></script>
</body>
</html>
