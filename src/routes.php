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
use Sentinel\Controllers\AlertController;
use Sentinel\Controllers\AuthController;
use Sentinel\Controllers\AuthorisationController;
use Sentinel\Controllers\ClientController;
use Sentinel\Controllers\DiscoveryController;
use Sentinel\Controllers\FindingController;
use Sentinel\Controllers\ScanController;
use Sentinel\Controllers\ScanningController;
use Sentinel\Controllers\PageController;
use Sentinel\Controllers\ProfileController;
use Sentinel\Controllers\ReportController;
use Sentinel\Controllers\UserController;
use Sentinel\Core\Router;

$router = new Router();
$public = ['auth' => 'public'];
$pending = ['auth' => 'pending'];
$admin = ['role' => Role::ADMIN];
$technician = ['role' => Role::TECHNICIAN];
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
$router->add('POST', '/profile/alerts', [AlertController::class, 'preference']);
$router->add('GET', '/notifications', [AlertController::class, 'notifications']);

// Clients: everyone views; admins manage; technicians may pause (only admins resume)
$router->add('GET', '/clients', [ClientController::class, 'index']);
$router->add('GET', '/clients/new', [ClientController::class, 'create'], $admin);
$router->add('POST', '/clients', [ClientController::class, 'store'], $admin);
$router->add('GET', '/clients/{id}', [ClientController::class, 'show']);
$router->add('GET', '/clients/{id}/edit', [ClientController::class, 'edit'], $admin);
$router->add('POST', '/clients/{id}', [ClientController::class, 'update'], $admin);
$router->add('POST', '/clients/{id}/archive', [ClientController::class, 'archive'], $admin);
$router->add('POST', '/clients/{id}/pause', [ClientController::class, 'pause'], $technician);
$router->add('POST', '/clients/{id}/resume', [ClientController::class, 'resume'], $admin);
$router->add('POST', '/clients/{id}/sites', [ClientController::class, 'addSite'], $admin);
$router->add('POST', '/sites/{id}', [ClientController::class, 'updateSite'], $admin);

// Authorised-to-scan register: admins only (everyone sees it on the client page)
$router->add('GET', '/clients/{id}/authorisations/new', [AuthorisationController::class, 'create'], $admin);
$router->add('POST', '/clients/{id}/authorisations', [AuthorisationController::class, 'store'], $admin);
$router->add('POST', '/authorisations/{id}/revoke', [AuthorisationController::class, 'revoke'], $admin);

// Discovery: technicians and admins run it and triage suggestions; approving into scope is admin-only (authorisation form)
$router->add('POST', '/clients/{id}/discover', [DiscoveryController::class, 'run'], $technician);
$router->add('POST', '/suggestions/{id}/dismiss', [DiscoveryController::class, 'dismiss'], $technician);
$router->add('POST', '/suggestions/{id}/restore', [DiscoveryController::class, 'restore'], $technician);

// Port scans: technicians and admins queue and cancel (the outside-window override is admin-only, checked in the controller)
$router->add('POST', '/clients/{id}/scan', [ScanController::class, 'queue'], $technician);
$router->add('POST', '/scans/{id}/cancel', [ScanController::class, 'cancel'], $technician);

// Findings: everyone views; technicians and admins triage
$router->add('GET', '/findings', [FindingController::class, 'index']);
$router->add('GET', '/findings/{id}', [FindingController::class, 'show']);
$router->add('POST', '/findings/{id}/triage', [FindingController::class, 'triage'], $technician);

// Reports: everyone views and downloads saved reports; technicians and admins create; admins delete and set schedules and branding
$router->add('GET', '/reports', [ReportController::class, 'index']);
$router->add('POST', '/clients/{id}/reports', [ReportController::class, 'store'], $technician);
$router->add('POST', '/clients/{id}/report-schedule', [ReportController::class, 'schedule'], $admin);
$router->add('GET', '/reports/{id}', [ReportController::class, 'show']);
$router->add('GET', '/reports/{id}/view', [ReportController::class, 'view']);
$router->add('GET', '/reports/{id}/download', [ReportController::class, 'download']);
$router->add('GET', '/reports/{id}/csv', [ReportController::class, 'csv']);
$router->add('POST', '/reports/{id}/delete', [ReportController::class, 'delete'], $admin);
$router->add('POST', '/admin/branding', [ReportController::class, 'branding'], $admin);

// Global kill switch
$router->add('POST', '/scanning/pause', [ScanningController::class, 'pause'], $technician);
$router->add('POST', '/scanning/resume', [ScanningController::class, 'resume'], $admin);

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
$router->add('POST', '/admin/alerts', [AlertController::class, 'save'], $admin);
$router->add('POST', '/admin/alerts/test', [AlertController::class, 'test'], $admin);

return $router;
