<?php

declare(strict_types=1);

/**
 * CLI: create an admin account (use it for the first admin after installing).
 *
 * Usage: php bin/create-admin.php --username=jdoe --name="Jane Doe" [--email=jdoe@msp.example]
 *        The password is read from standard input (hidden when typed at a
 *        terminal), so it never appears in the process list or shell history.
 *
 * Security assumptions:
 * - CLI only. There is no web "first-run" page for an attacker to race for.
 * - The password must meet the policy. The new admin must set up 2FA at
 *   first sign-in, like every user.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Auth\Passwords;
use Sentinel\Core\App;

$opts = getopt('', ['username:', 'name:', 'email::']);
$username = trim((string) ($opts['username'] ?? ''));
$name = trim((string) ($opts['name'] ?? ''));
$email = trim((string) ($opts['email'] ?? ''));

if (!\Sentinel\Auth\Auth::isValidUsername($username) || $name === '' || mb_strlen($name) > 100) {
    fwrite(STDERR, "Usage: php bin/create-admin.php --username=NAME --name=\"Full Name\" [--email=ADDRESS]\n");
    fwrite(STDERR, "Username: 3 to 50 letters, digits, dots, dashes or underscores.\n");
    exit(2);
}
if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    fwrite(STDERR, "Invalid email address.\n");
    exit(2);
}

$tty = function_exists('posix_isatty') && posix_isatty(STDIN);
if ($tty) {
    fwrite(STDOUT, 'Password (min ' . Passwords::MIN_LENGTH . ' characters): ');
    shell_exec('stty -echo');
    // Turn echo back on even if the script is interrupted (Ctrl+C) or fails.
    register_shutdown_function(static fn () => shell_exec('stty echo'));
    if (function_exists('pcntl_async_signals')) {
        pcntl_async_signals(true);
        pcntl_signal(SIGINT, static function (): void {
            shell_exec('stty echo');
            fwrite(STDOUT, "\n");
            exit(130);
        });
    }
}
$password = rtrim((string) fgets(STDIN), "\r\n");
if ($tty) {
    shell_exec('stty echo');
    fwrite(STDOUT, "\n");
}

try {
    App::boot();
    if (($error = Passwords::policyError($password, $username)) !== null) {
        fwrite(STDERR, $error . "\n");
        exit(2);
    }
    if (App::users()->findByUsername($username) !== null) {
        fwrite(STDERR, "A user with that username already exists.\n");
        exit(1);
    }
    // must_change_password = false: the admin chose this password themselves.
    $id = App::users()->create($username, $name, $email, (int) App::roles()->idForKey('admin'), Passwords::hash($password), false);
    App::audit()->log('user.created', null, 'cli', 'user', $id, ['username' => $username, 'role' => 'Admin', 'via' => 'cli']);
    fwrite(STDOUT, "Admin '{$username}' created. Sign in to set up two-factor authentication.\n");
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Failed: ' . $ex->getMessage() . "\n");
    exit(1);
}
