<?php

declare(strict_types=1);

/**
 * Route table: every URL the web UI answers, with its access rules.
 *
 * Security assumptions:
 * - The default for a route is "signed in with 2FA, any role" (see Router).
 *   Public and pending routes are marked explicitly, and admin routes say so.
 * - Every POST is CSRF-checked by the kernel. Nothing here needs to repeat it.
 */

use Sentinel\Auth\Role;
use Sentinel\Controllers\AdminController;
use Sentinel\Controllers\AuthController;
use Sentinel\Controllers\PageController;
use Sentinel\Controllers\ProfileController;
use Sentinel\Controllers\UserController;
use Sentinel\Core\Router;

$router = new Router();
$public = ['auth' => 'public'];
$pending = ['auth' => 'pending'];
$admin = ['role' => Role::ADMIN];
$duringPasswordChange = ['allow_password_change' => true];

// Sign-in flow
$router->add('GET', '/login', [AuthController::class, 'showLogin'], $public);
$router->add('POST', '/login', [AuthController::class, 'login'], $public);
$router->add('POST', '/logout', [AuthController::class, 'logout'], $public);
$router->add('GET', '/login/2fa', [AuthController::class, 'showSecondFactor'], $pending);
$router->add('POST', '/login/2fa', [AuthController::class, 'verifySecondFactor'], $pending);
$router->add('GET', '/2fa/setup', [AuthController::class, 'showEnrol'], $pending);
$router->add('POST', '/2fa/setup', [AuthController::class, 'enrol'], $pending);
$router->add('GET', '/recovery-codes', [AuthController::class, 'showRecoveryCodes'], $duringPasswordChange);

// Everyone signed in
$router->add('GET', '/', [PageController::class, 'dashboard']);
$router->add('GET', '/help', [PageController::class, 'help'], $duringPasswordChange);
$router->add('GET', '/profile', [ProfileController::class, 'index']);
$router->add('GET', '/profile/password', [ProfileController::class, 'showPassword'], $duringPasswordChange);
$router->add('POST', '/profile/password', [ProfileController::class, 'changePassword'], $duringPasswordChange);
$router->add('POST', '/profile/recovery-codes', [ProfileController::class, 'regenerateRecoveryCodes']);

// Admin only
$router->add('GET', '/users', [UserController::class, 'index'], $admin);
$router->add('GET', '/users/new', [UserController::class, 'create'], $admin);
$router->add('POST', '/users', [UserController::class, 'store'], $admin);
$router->add('GET', '/users/{id}', [UserController::class, 'edit'], $admin);
$router->add('POST', '/users/{id}', [UserController::class, 'update'], $admin);
$router->add('POST', '/users/{id}/password', [UserController::class, 'resetPassword'], $admin);
$router->add('POST', '/users/{id}/2fa-reset', [UserController::class, 'resetTwoFactor'], $admin);
$router->add('GET', '/admin/audit', [AdminController::class, 'auditLog'], $admin);
$router->add('GET', '/admin/settings', [AdminController::class, 'settings'], $admin);
$router->add('POST', '/admin/settings', [AdminController::class, 'saveSettings'], $admin);

return $router;
