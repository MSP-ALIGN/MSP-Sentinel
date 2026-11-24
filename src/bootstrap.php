<?php

declare(strict_types=1);

/**
 * Application bootstrap: class autoloader and global helper functions.
 *
 * Loaded first by every entry point (web front controller, CLI scripts, tests).
 * It doesn't touch configuration, the database or the session. That happens in
 * {@see \Sentinel\Core\App::boot()}, so CLI tools can load classes without a
 * web context.
 *
 * Security assumptions:
 * - Class names reaching the autoloader may come from code paths influenced by
 *   input (e.g. a mis-built handler name), so the autoloader only accepts
 *   plain class-name characters. It can never be turned into a file inclusion.
 */

// Never show PHP errors to visitors; they go to the error log. Set first, before anything can fail.
ini_set('display_errors', '0');
ini_set('log_errors', '1');

if (PHP_VERSION_ID < 80300) {
    // 8.4 is the target. 8.3 is the oldest version the code is tested against.
    // error_log works in both web and CLI (STDERR only exists in the CLI).
    error_log('MSP Sentinel needs PHP 8.3 or newer (8.4 recommended).');
    exit(1);
}

define('SENTINEL_ROOT', dirname(__DIR__));

spl_autoload_register(static function (string $class): void {
    $prefix = 'Sentinel\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    // Only letters, digits, underscores and namespace separators: no "..", no "/".
    if (!preg_match('/^[A-Za-z0-9_\\\\]+$/', $relative)) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

require __DIR__ . '/helpers.php';
