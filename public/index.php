<?php

declare(strict_types=1);

/**
 * Web front controller: every request that isn't a static file comes here.
 *
 * Security assumptions:
 * - The web server's document root is public/. Everything else (config,
 *   src, migrations) is outside it and can't be fetched directly.
 * - If the app can't boot (missing config or key), a plain message is shown
 *   without any detail. The detail goes to the PHP error log.
 */

// PHP's built-in server (development and tests): let it serve existing static files directly.
if (PHP_SAPI === 'cli-server') {
    $file = __DIR__ . (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
    // Only real, non-PHP files inside assets/ are served as static files.
    $real = (string) realpath($file);
    if (is_file($file) && str_starts_with($real, __DIR__ . '/assets/') && strtolower(pathinfo($real, PATHINFO_EXTENSION)) !== 'php') {
        return false;
    }
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;

try {
    App::boot();
} catch (\Throwable $ex) {
    error_log('[msp-sentinel] boot failed: ' . $ex->getMessage());
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "MSP Sentinel is not configured correctly. The administrator can find details in the PHP error log.\n";
    exit;
}

$router = require SENTINEL_ROOT . '/src/routes.php';
App::handleRequest($router)->send();
