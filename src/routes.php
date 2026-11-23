<?php

declare(strict_types=1);

/**
 * Route table: every URL the web UI answers, with its access rules.
 *
 * Security assumptions:
 * - The default for a route is "signed in with 2FA, any role" (see Router).
 *   Public and pending routes are marked explicitly, and admin routes say so.
 * - Every POST is CSRF-checked by the kernel. Nothing here needs to repeat it.
 * - /api/... is NOT routed here: App hands it to Sentinel\Api\ApiKernel (bearer tokens, no session).
 */

use Sentinel\Auth\Role;
use Sentinel\Controllers\AdminController;
use Sentinel\Controllers\AgentController;
use Sentinel\Controllers\AlertController;
use Sentinel\Controllers\IntegrationsController;
use Sentinel\Controllers\ApiAdminController;
use Sentinel\Controllers\AuthController;
use Sentinel\Controllers\AuthorisationController;
use Sentinel\Controllers\ClientController;
use Sentinel\Controllers\ComplianceController;
use Sentinel\Controllers\DiscoveryController;
use Sentinel\Controllers\FindingController;
use Sentinel\Controllers\InventoryController;
use Sentinel\Controllers\ScanController;
use Sentinel\Controllers\ScanningController;
use Sentinel\Controllers\SystemController;
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
$router->add('GET', '/dashboard/live', [PageController::class, 'live'], ['passive' => true]);
$router->add('GET', '/help', [PageController::class, 'help'], $duringPasswordChange);
$router->add('GET', '/profile', [ProfileController::class, 'index']);
$router->add('GET', '/profile/password', [ProfileController::class, 'showPassword'], $duringPasswordChange);
$router->add('POST', '/profile/password', [ProfileController::class, 'changePassword'], $duringPasswordChange);
$router->add('POST', '/profile/recovery-codes', [ProfileController::class, 'regenerateRecoveryCodes']);
$router->add('POST', '/profile/alerts', [AlertController::class, 'preference']);
$router->add('POST', '/profile/theme', [AlertController::class, 'theme']);
$router->add('GET', '/notifications', [AlertController::class, 'notifications']);

// Clients: everyone views; admins manage; technicians may pause (only admins resume)
$router->add('GET', '/clients', [ClientController::class, 'index']);
$router->add('GET', '/clients/new', [ClientController::class, 'create'], $admin);
$router->add('POST', '/clients', [ClientController::class, 'store'], $admin);
$router->add('GET', '/clients/{id}', [ClientController::class, 'show']);
// A client's pages, one per section (the overview is /clients/{id}); see ClientController::SECTIONS.
foreach (['findings', 'scans', 'vulnerabilities', 'certificates', 'website', 'agents', 'devices', 'authorisations', 'engagements', 'discovery', 'reports', 'compliance'] as $clientSection) {
    $router->add('GET', '/clients/{id}/' . $clientSection, [ClientController::class, 'show']);
}
$router->add('GET', '/clients/{id}/overview', [ClientController::class, 'overview'], ['passive' => true]);
$router->add('GET', '/clients/{id}/edit', [ClientController::class, 'edit'], $admin);
$router->add('POST', '/clients/{id}', [ClientController::class, 'update'], $admin);
$router->add('POST', '/clients/{id}/archive', [ClientController::class, 'archive'], $admin);
$router->add('POST', '/clients/{id}/pause', [ClientController::class, 'pause'], $technician);
$router->add('POST', '/clients/{id}/resume', [ClientController::class, 'resume'], $admin);
$router->add('POST', '/clients/{id}/sites', [ClientController::class, 'addSite'], $admin);
$router->add('POST', '/sites/{id}', [ClientController::class, 'updateSite'], $admin);

// Authorised-to-scan register: admins only (everyone sees it on the client page)
// Pen-test engagements: technicians and admins create, stop and cancel; a DIFFERENT admin approves (two-person rule).
$router->add('GET', '/clients/{id}/engagements/new', [\Sentinel\Controllers\EngagementController::class, 'create'], $technician);
$router->add('POST', '/clients/{id}/engagements', [\Sentinel\Controllers\EngagementController::class, 'store'], $technician);
$router->add('GET', '/engagements/{id}', [\Sentinel\Controllers\EngagementController::class, 'show']);
$router->add('GET', '/engagements/{id}/document', [\Sentinel\Controllers\EngagementController::class, 'document'], $technician);
$router->add('POST', '/engagements/{id}/approve', [\Sentinel\Controllers\EngagementController::class, 'approve'], $admin);
$router->add('POST', '/engagements/{id}/stop', [\Sentinel\Controllers\EngagementController::class, 'stop'], $technician);
$router->add('POST', '/engagements/{id}/run-external', [\Sentinel\Controllers\EngagementController::class, 'runExternal'], $technician);
$router->add('POST', '/engagements/{id}/run-internal', [\Sentinel\Controllers\EngagementController::class, 'runInternal'], $technician);
$router->add('POST', '/engagements/{id}/report', [\Sentinel\Controllers\EngagementController::class, 'report'], $technician);
$router->add('POST', '/engagements/{id}/cancel', [\Sentinel\Controllers\EngagementController::class, 'cancel'], $technician);
$router->add('GET', '/clients/{id}/authorisations/new', [AuthorisationController::class, 'create'], $admin);
$router->add('POST', '/clients/{id}/authorisations', [AuthorisationController::class, 'store'], $admin);
$router->add('POST', '/authorisations/{id}/revoke', [AuthorisationController::class, 'revoke'], $admin);

// Discovery: technicians and admins run it and triage suggestions; approving into scope is admin-only (authorisation form)
$router->add('POST', '/clients/{id}/discover', [DiscoveryController::class, 'run'], $technician);
$router->add('POST', '/suggestions/{id}/dismiss', [DiscoveryController::class, 'dismiss'], $technician);
$router->add('POST', '/suggestions/{id}/restore', [DiscoveryController::class, 'restore'], $technician);

// Port scans: technicians and admins queue and cancel (the outside-window override is admin-only, checked in the controller)
$router->add('POST', '/clients/{id}/scan', [ScanController::class, 'queue'], $technician);
// On-premises agents: technicians pause a site; admins manage authorisations, enrolment, agents, resume and scan now.
$router->add('GET', '/clients/{id}/sites/{site}/internal-authorisations/new', [AgentController::class, 'authorisationForm'], $admin);
$router->add('POST', '/clients/{id}/sites/{site}/internal-authorisations', [AgentController::class, 'storeAuthorisation'], $admin);
$router->add('POST', '/clients/{id}/internal-authorisations/{auth}/revoke', [AgentController::class, 'revokeAuthorisation'], $admin);
$router->add('POST', '/clients/{id}/sites/{site}/enrol', [AgentController::class, 'enrol'], $admin);
$router->add('POST', '/clients/{id}/agents/{agent}/revoke', [AgentController::class, 'revokeAgent'], $admin);
$router->add('POST', '/clients/{id}/agents/{agent}/approve-key', [AgentController::class, 'approveKey'], $admin);
$router->add('POST', '/clients/{id}/agents/{agent}/restart', [AgentController::class, 'restartAgent'], $admin);
$router->add('POST', '/clients/{id}/agents/{agent}/update', [AgentController::class, 'updateAgent'], $admin);
$router->add('POST', '/clients/{id}/agents-update', [AgentController::class, 'updateClientAgents'], $admin);
$router->add('POST', '/clients/{id}/agents/{agent}/diagnostics', [AgentController::class, 'diagnosticsAgent'], $admin);
$router->add('POST', '/clients/{id}/sites/{site}/agent-settings', [AgentController::class, 'siteSettings'], $admin);
$router->add('POST', '/clients/{id}/sites/{site}/pause', [AgentController::class, 'pause'], $technician);
$router->add('POST', '/clients/{id}/sites/{site}/resume', [AgentController::class, 'resume'], $admin);
$router->add('POST', '/clients/{id}/sites/{site}/scan', [AgentController::class, 'scan'], $admin);
// Active Directory checks of a site (admins): settings and the password sealed in the browser for the agent.
$router->add('POST', '/clients/{id}/sites/{site}/directory', [\Sentinel\Controllers\DirectoryController::class, 'save'], $admin);
$router->add('POST', '/clients/{id}/sites/{site}/directory/trust', [\Sentinel\Controllers\DirectoryController::class, 'trust'], $admin);
$router->add('POST', '/clients/{id}/sites/{site}/directory/remove', [\Sentinel\Controllers\DirectoryController::class, 'remove'], $admin);
// Internal devices (inventory sources): everyone views; technicians ask for a sync; admins link and unlink.
$router->add('GET', '/clients/{id}/devices/{device}', [InventoryController::class, 'device']);
$router->add('GET', '/clients/{id}/inventory/link', [InventoryController::class, 'linkForm'], $admin);
$router->add('POST', '/clients/{id}/inventory/link', [InventoryController::class, 'link'], $admin);
$router->add('POST', '/clients/{id}/inventory/unlink', [InventoryController::class, 'unlink'], $admin);
$router->add('POST', '/clients/{id}/inventory/sync', [InventoryController::class, 'sync'], $technician);
$router->add('POST', '/scans/{id}/cancel', [ScanController::class, 'cancel'], $technician);

// Findings: everyone views; technicians and admins triage
$router->add('GET', '/findings', [FindingController::class, 'index']);
$router->add('GET', '/findings/{id}', [FindingController::class, 'show']);
$router->add('POST', '/findings/{id}/triage', [FindingController::class, 'triage'], $technician);
// Fix workflow: technicians and admins assign and verify; only admins set a finding's own due date.
$router->add('POST', '/findings/{id}/assign', [FindingController::class, 'assign'], $technician);
$router->add('POST', '/findings/{id}/verify', [FindingController::class, 'verify'], $technician);
$router->add('POST', '/findings/{id}/due', [FindingController::class, 'due'], $admin);

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
$router->add('GET', '/admin', [AdminController::class, 'index'], $admin);
$router->add('GET', '/admin/audit', [AdminController::class, 'auditLog'], $admin);
$router->add('GET', '/admin/integrations', [IntegrationsController::class, 'index'], $admin);
$router->add('POST', '/admin/integrations/ninjaone', [IntegrationsController::class, 'saveNinjaOne'], $admin);
$router->add('POST', '/admin/integrations/ninjaone/test', [IntegrationsController::class, 'testNinjaOne'], $admin);
$router->add('POST', '/admin/integrations/itflow', [IntegrationsController::class, 'saveItflow'], $admin);
$router->add('POST', '/admin/integrations/itflow/test', [IntegrationsController::class, 'testItflow'], $admin);
$router->add('POST', '/admin/integrations/itflow/sync', [IntegrationsController::class, 'syncItflow'], $admin);
$router->add('POST', '/admin/integrations/itflow/tickets', [IntegrationsController::class, 'ticketsItflow'], $admin);
$router->add('POST', '/admin/integrations/mspalign', [IntegrationsController::class, 'saveAlign'], $admin);
$router->add('POST', '/admin/integrations/mspalign/test', [IntegrationsController::class, 'testAlign'], $admin);
$router->add('POST', '/clients/{id}/compliance/link', [ComplianceController::class, 'link'], $admin);
$router->add('POST', '/clients/{id}/compliance/unlink', [ComplianceController::class, 'unlink'], $admin);
$router->add('POST', '/clients/{id}/compliance/refresh', [ComplianceController::class, 'refresh'], $technician);
$router->add('GET', '/admin/settings', [AdminController::class, 'settings'], $admin);
$router->add('POST', '/admin/settings', [AdminController::class, 'saveSettings'], $admin);
$router->add('POST', '/admin/settings/due-dates', [AdminController::class, 'saveDuePolicy'], $admin);
$router->add('POST', '/admin/feeds/refresh', [AdminController::class, 'refreshFeeds'], $admin);
$router->add('POST', '/admin/alerts', [AlertController::class, 'save'], $admin);
$router->add('POST', '/admin/alerts/test', [AlertController::class, 'test'], $admin);
$router->add('GET', '/admin/system', [SystemController::class, 'index'], $admin);
$router->add('POST', '/admin/system/retention', [SystemController::class, 'retention'], $admin);
$router->add('POST', '/admin/system/updates', [SystemController::class, 'updates'], $admin);
$router->add('POST', '/admin/system/demo', [SystemController::class, 'demo'], $admin);
$router->add('POST', '/admin/system/update', [SystemController::class, 'update'], $admin);
$router->add('POST', '/admin/system/agents-update', [SystemController::class, 'updateAgents'], $admin);
$router->add('POST', '/admin/system/agents-move', [SystemController::class, 'moveAgents'], $admin);
$router->add('POST', '/admin/system/release-key', [SystemController::class, 'releaseKey'], $admin);
$router->add('POST', '/admin/system/release-sign', [SystemController::class, 'releaseSign'], $admin);
$router->add('GET', '/admin/api', [ApiAdminController::class, 'index'], $admin);
$router->add('POST', '/admin/api/tokens', [ApiAdminController::class, 'create'], $admin);
$router->add('POST', '/admin/api/tokens/{id}/revoke', [ApiAdminController::class, 'revoke'], $admin);
$router->add('POST', '/admin/api/events', [ApiAdminController::class, 'events'], $admin);
$router->add('POST', '/admin/api/events/secret', [ApiAdminController::class, 'secret'], $admin);
$router->add('POST', '/admin/api/events/test', [ApiAdminController::class, 'test'], $admin);

return $router;
