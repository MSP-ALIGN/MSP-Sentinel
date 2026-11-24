<?php

declare(strict_types=1);

/**
 * CLI: load or remove demo data (made-up clients for trying Sentinel out).
 *
 * Usage:
 *   sudo -u sentinel php bin/demo.php --load   [--user=USERNAME]
 *   sudo -u sentinel php bin/demo.php --remove
 *   sudo -u sentinel php bin/demo.php --status
 *
 * --user: the admin the demo findings are assigned to (default: the first active admin).
 *
 * Demo clients use *.example names and documentation addresses only, are marked as demo, and are never
 * scanned. --remove deletes only demo clients and what belongs to them. See src/Demo/DemoData.php.
 *
 * Security assumptions: CLI only (server administrator). Run as the unprivileged sentinel user, like the
 * worker; it refuses root unless SENTINEL_ALLOW_ROOT=1. The username is looked up with a prepared statement.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;
use Sentinel\Demo\DemoData;

if (function_exists('posix_geteuid') && posix_geteuid() === 0 && getenv('SENTINEL_ALLOW_ROOT') !== '1') {
    fwrite(STDERR, "Refusing to run as root. Run it as the sentinel user: sudo -u sentinel php bin/demo.php --load\n");
    exit(1);
}

$opts = getopt('', ['load', 'remove', 'status', 'user:']);
if (count(array_intersect_key($opts, ['load' => 1, 'remove' => 1, 'status' => 1])) !== 1) {
    fwrite(STDERR, "Usage: php bin/demo.php --load [--user=USERNAME] | --remove | --status\n");
    exit(2);
}

try {
    App::boot();
    $db = App::db();
    $username = is_string($opts['user'] ?? null) ? $opts['user'] : null;
    $stmt = $username === null
        // The built-in Admin role (1.40.1: by role, no longer the old role column).
        ? $db->query("SELECT u.id, u.username FROM users u JOIN roles r ON r.id = u.role_id AND r.role_key = 'admin' WHERE u.is_active = 1 ORDER BY u.id LIMIT 1")
        : $db->prepare("SELECT u.id, u.username FROM users u JOIN roles r ON r.id = u.role_id AND r.role_key = 'admin' WHERE u.username = :u AND u.is_active = 1");
    if ($username !== null) {
        $stmt->execute(['u' => $username]);
    }
    $admin = $stmt->fetch();
    if ($admin === false) {
        fwrite(STDERR, $username === null ? "No active admin found. Create one first (bin/create-admin.php).\n" : "No active admin called {$username}.\n");
        exit(1);
    }
    $demo = new DemoData($db, (int) $admin['id']);

    if (isset($opts['status'])) {
        fwrite(STDOUT, $demo->isLoaded() ? "Demo data is loaded.\n" : "No demo data.\n");
        exit(0);
    }
    if (isset($opts['remove'])) {
        $r = $demo->remove();
        App::audit()->log('demo.removed', null, 'cli', null, null, $r);
        fwrite(STDOUT, $r['clients'] === 0 ? "No demo data to remove.\n" : "Removed {$r['clients']} demo client(s) and everything that belonged to them.\n");
        exit(0);
    }
    if ($demo->isLoaded()) {
        fwrite(STDOUT, "Demo data is already loaded. Remove it first with --remove.\n");
        exit(1);
    }
    $r = $demo->load();
    App::audit()->log('demo.loaded', (int) $admin['id'], 'cli', null, null, $r);
    fwrite(STDOUT, "Loaded {$r['clients']} demo clients with {$r['findings']} findings, {$r['devices']} devices and {$r['reports']} reports.\n"
        . "Findings are assigned to {$admin['username']}. Demo clients are never scanned. Remove them with --remove.\n");
    exit(0);
} catch (Throwable $ex) {
    fwrite(STDERR, 'Demo data failed: ' . $ex->getMessage() . "\n");
    exit(1);
}
