<?php

declare(strict_types=1);

/**
 * Route table: every URL the web UI answers, with its access rules.
 *
 * Security assumptions:
 * - The default for a route is "signed in with 2FA, any role" (see Router).
 *   Public and pending routes are marked explicitly, and every action route names its permission.
 * - Every POST is CSRF-checked by the kernel. Nothing here needs to repeat it.
 * - /api/... is NOT routed here: App hands it to Sentinel\Api\ApiKernel (bearer tokens, no session).
 */

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
// Each action route names the permission it needs (Sentinel\Auth\Permissions, 1.40); the built-in roles hold the
// same rights the old fixed roles had (tests/e2e/roles_test.php checks every route against the 1.39 table).
$anyAdmin = ['perm' => array_values(array_filter(\Sentinel\Auth\Permissions::names(), static fn (string $p): bool => \Sentinel\Auth\Permissions::ALL[$p][0] === 'admin'))];
$duringPasswordChange = ['allow_password_change' => true];

// Sign-in flow
$router->add('GET', '/login', [AuthController::class, 'showLogin'], $public);
$router->add('POST', '/login', [AuthController::class, 'login'], $public);
$router->add('POST', '/logout', [AuthController::class, 'logout'], $public);
// Sign in with Microsoft (1.43): public steps; the user then continues like after a password (or straight in with MFA)
$router->add('GET', '/login/sso', [\Sentinel\Controllers\SsoController::class, 'start'], $public);
$router->add('GET', '/login/sso/callback', [\Sentinel\Controllers\SsoController::class, 'callback'], $public);
$router->add('GET', '/login/2fa', [AuthController::class, 'showSecondFactor'], $pending);
$router->add('POST', '/login/2fa', [AuthController::class, 'verifySecondFactor'], $pending);
$router->add('GET', '/2fa/setup', [AuthController::class, 'showEnrol'], $pending);
$router->add('POST', '/2fa/setup', [AuthController::class, 'enrol'], $pending);
$router->add('GET', '/recovery-codes', [AuthController::class, 'showRecoveryCodes'], $duringPasswordChange);

// Everyone signed in
$router->add('GET', '/', [PageController::class, 'dashboard']);
$router->add('GET', '/dashboard/live', [PageController::class, 'live'], ['passive' => true]);
$router->add('POST', '/dashboard/setup-checklist/hide', [PageController::class, 'hideSetup'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('GET', '/help', [PageController::class, 'help'], $duringPasswordChange);
$router->add('GET', '/search', [PageController::class, 'search']);
$router->add('GET', '/profile', [ProfileController::class, 'index']);
$router->add('GET', '/profile/password', [ProfileController::class, 'showPassword'], $duringPasswordChange);
$router->add('POST', '/profile/password', [ProfileController::class, 'changePassword'], $duringPasswordChange);
$router->add('POST', '/profile/recovery-codes', [ProfileController::class, 'regenerateRecoveryCodes']);
$router->add('POST', '/profile/sso-link', [\Sentinel\Controllers\SsoController::class, 'link']);
$router->add('POST', '/profile/sso-unlink', [\Sentinel\Controllers\SsoController::class, 'unlink']);
$router->add('POST', '/profile/alerts', [AlertController::class, 'preference']);
$router->add('POST', '/profile/theme', [AlertController::class, 'theme']);
$router->add('POST', '/profile/timezone', [AlertController::class, 'timezone']);
$router->add('GET', '/notifications', [AlertController::class, 'notifications']);
$router->add('POST', '/notifications/read', [AlertController::class, 'markRead']);

// Clients: everyone views; admins manage; technicians may pause (only admins resume)
$router->add('GET', '/clients', [ClientController::class, 'index']);
$router->add('GET', '/clients/new', [ClientController::class, 'create'], ['perm' => 'clients.manage']);
$router->add('POST', '/clients', [ClientController::class, 'store'], ['perm' => 'clients.manage']);
$router->add('GET', '/clients/{id}', [ClientController::class, 'show']);
// A client's pages, one per section (the overview is /clients/{id}); see ClientController::SECTIONS.
foreach (['findings', 'scans', 'vulnerabilities', 'certificates', 'website', 'agents', 'devices', 'authorisations', 'engagements', 'discovery', 'reports', 'compliance'] as $clientSection) {
    $router->add('GET', '/clients/{id}/' . $clientSection, [ClientController::class, 'show']);
}
$router->add('GET', '/clients/{id}/overview', [ClientController::class, 'overview'], ['passive' => true]);
$router->add('GET', '/clients/{id}/edit', [ClientController::class, 'edit'], ['perm' => 'clients.manage']);
$router->add('POST', '/clients/{id}', [ClientController::class, 'update'], ['perm' => 'clients.manage']);
$router->add('POST', '/clients/{id}/archive', [ClientController::class, 'archive'], ['perm' => 'clients.manage']);
$router->add('POST', '/clients/{id}/pause', [ClientController::class, 'pause'], ['perm' => 'scanning.pause']);
$router->add('POST', '/clients/{id}/resume', [ClientController::class, 'resume'], ['perm' => 'scanning.resume']);
$router->add('POST', '/clients/{id}/sites', [ClientController::class, 'addSite'], ['perm' => 'clients.manage']);
$router->add('POST', '/sites/{id}', [ClientController::class, 'updateSite'], ['perm' => 'clients.manage', 'client' => 'site']);

// Authorized-to-scan register: admins only (everyone sees it on the client page)
// Pen-test engagements: technicians and admins create, stop and cancel; a DIFFERENT admin approves (two-person rule).
$router->add('GET', '/engagements/new', [\Sentinel\Controllers\EngagementController::class, 'newFor'], ['perm' => 'engagements.run']);
$router->add('GET', '/clients/{id}/engagements/new', [\Sentinel\Controllers\EngagementController::class, 'create'], ['perm' => 'engagements.run']);
$router->add('POST', '/clients/{id}/engagements', [\Sentinel\Controllers\EngagementController::class, 'store'], ['perm' => 'engagements.run']);
$router->add('GET', '/engagements', [\Sentinel\Controllers\EngagementController::class, 'index']);
$router->add('GET', '/engagements/{id}', [\Sentinel\Controllers\EngagementController::class, 'show'], ['client' => 'engagement']);
$router->add('GET', '/engagements/{id}/document', [\Sentinel\Controllers\EngagementController::class, 'document'], ['perm' => ['engagements.run', 'engagements.approve'], 'client' => 'engagement']);
$router->add('POST', '/engagements/{id}/approve', [\Sentinel\Controllers\EngagementController::class, 'approve'], ['perm' => 'engagements.approve', 'client' => 'engagement']);
$router->add('POST', '/engagements/{id}/stop', [\Sentinel\Controllers\EngagementController::class, 'stop'], ['perm' => 'engagements.run', 'client' => 'engagement']);
$router->add('POST', '/engagements/{id}/run-external', [\Sentinel\Controllers\EngagementController::class, 'runExternal'], ['perm' => 'engagements.run', 'client' => 'engagement']);
$router->add('POST', '/engagements/{id}/run-internal', [\Sentinel\Controllers\EngagementController::class, 'runInternal'], ['perm' => 'engagements.run', 'client' => 'engagement']);
$router->add('POST', '/engagements/{id}/report', [\Sentinel\Controllers\EngagementController::class, 'report'], ['perm' => 'engagements.run', 'client' => 'engagement']);
$router->add('POST', '/engagements/{id}/cancel', [\Sentinel\Controllers\EngagementController::class, 'cancel'], ['perm' => 'engagements.run', 'client' => 'engagement']);
$router->add('GET', '/clients/{id}/authorisations/new', [AuthorisationController::class, 'create'], ['perm' => 'authorisations.manage']);
$router->add('POST', '/clients/{id}/authorisations', [AuthorisationController::class, 'store'], ['perm' => 'authorisations.manage']);
$router->add('POST', '/authorisations/{id}/revoke', [AuthorisationController::class, 'revoke'], ['perm' => 'authorisations.manage', 'client' => 'authorisation']);

// Discovery: technicians and admins run it and triage suggestions; approving into scope is admin-only (authorisation form)
$router->add('POST', '/clients/{id}/discover', [DiscoveryController::class, 'run'], ['perm' => 'scans.run']);
$router->add('POST', '/suggestions/{id}/dismiss', [DiscoveryController::class, 'dismiss'], ['perm' => 'scans.run', 'client' => 'suggestion']);
$router->add('POST', '/suggestions/{id}/restore', [DiscoveryController::class, 'restore'], ['perm' => 'scans.run', 'client' => 'suggestion']);

// Port scans: technicians and admins queue and cancel (the outside-window override is admin-only, checked in the controller)
$router->add('POST', '/clients/{id}/scan', [ScanController::class, 'queue'], ['perm' => 'scans.run']);
// On-premises agents: technicians pause a site; admins manage authorisations, enrolment, agents, resume and scan now.
$router->add('GET', '/clients/{id}/sites/{site}/internal-authorisations/new', [AgentController::class, 'authorisationForm'], ['perm' => 'authorisations.manage']);
$router->add('POST', '/clients/{id}/sites/{site}/internal-authorisations', [AgentController::class, 'storeAuthorisation'], ['perm' => 'authorisations.manage']);
$router->add('POST', '/clients/{id}/internal-authorisations/{auth}/revoke', [AgentController::class, 'revokeAuthorisation'], ['perm' => 'authorisations.manage']);
$router->add('POST', '/clients/{id}/sites/{site}/enrol', [AgentController::class, 'enrol'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/agents/{agent}/revoke', [AgentController::class, 'revokeAgent'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/agents/{agent}/approve-key', [AgentController::class, 'approveKey'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/agents/{agent}/restart', [AgentController::class, 'restartAgent'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/agents/{agent}/update', [AgentController::class, 'updateAgent'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/agents-update', [AgentController::class, 'updateClientAgents'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/agents/{agent}/diagnostics', [AgentController::class, 'diagnosticsAgent'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/sites/{site}/agent-settings', [AgentController::class, 'siteSettings'], ['perm' => 'agents.manage']);
$router->add('POST', '/clients/{id}/sites/{site}/pause', [AgentController::class, 'pause'], ['perm' => 'scanning.pause']);
$router->add('POST', '/clients/{id}/sites/{site}/resume', [AgentController::class, 'resume'], ['perm' => 'scanning.resume']);
$router->add('POST', '/clients/{id}/sites/{site}/scan', [AgentController::class, 'scan'], ['perm' => 'agents.manage']);
// Active Directory checks of a site (admins): settings and the password sealed in the browser for the agent.
$router->add('POST', '/clients/{id}/sites/{site}/directory', [\Sentinel\Controllers\DirectoryController::class, 'save'], ['perm' => 'directory.manage']);
$router->add('POST', '/clients/{id}/sites/{site}/directory/trust', [\Sentinel\Controllers\DirectoryController::class, 'trust'], ['perm' => 'directory.manage']);
$router->add('POST', '/clients/{id}/sites/{site}/directory/remove', [\Sentinel\Controllers\DirectoryController::class, 'remove'], ['perm' => 'directory.manage']);
// Internal devices (inventory sources): everyone views; technicians ask for a sync; admins link and unlink.
$router->add('GET', '/clients/{id}/devices/{device}', [InventoryController::class, 'device']);
$router->add('POST', '/clients/{id}/devices/{device}/merge', [InventoryController::class, 'merge'], ['perm' => 'devices.merge']);
$router->add('GET', '/clients/{id}/inventory/link', [InventoryController::class, 'linkForm'], ['perm' => 'integrations.link']);
$router->add('POST', '/clients/{id}/inventory/link', [InventoryController::class, 'link'], ['perm' => 'integrations.link']);
$router->add('POST', '/clients/{id}/inventory/unlink', [InventoryController::class, 'unlink'], ['perm' => 'integrations.link']);
$router->add('POST', '/clients/{id}/inventory/sync', [InventoryController::class, 'sync'], ['perm' => 'scans.run']);
$router->add('POST', '/scans/{id}/cancel', [ScanController::class, 'cancel'], ['perm' => 'scans.run', 'client' => 'scan']);

// Findings: everyone views; technicians and admins triage
$router->add('GET', '/findings', [FindingController::class, 'index']);
$router->add('GET', '/findings/{id}', [FindingController::class, 'show'], ['client' => 'finding']);
$router->add('POST', '/findings/{id}/triage', [FindingController::class, 'triage'], ['perm' => 'findings.triage', 'client' => 'finding']);
// Fix workflow: technicians and admins assign and verify; only admins set a finding's own due date.
$router->add('POST', '/findings/{id}/assign', [FindingController::class, 'assign'], ['perm' => 'findings.assign', 'client' => 'finding']);
$router->add('POST', '/findings/{id}/verify', [FindingController::class, 'verify'], ['perm' => 'findings.verify', 'client' => 'finding']);
$router->add('POST', '/findings/{id}/due', [FindingController::class, 'due'], ['perm' => 'findings.due', 'client' => 'finding']);
$router->add('POST', '/findings/bulk', [FindingController::class, 'bulk'], ['perm' => ['findings.triage', 'findings.assign', 'findings.verify', 'findings.due']]);

// Reports: everyone views and downloads saved reports; technicians and admins create; admins delete and set schedules and branding
$router->add('GET', '/reports', [ReportController::class, 'index']);
$router->add('POST', '/clients/{id}/reports', [ReportController::class, 'store'], ['perm' => 'reports.create']);
$router->add('POST', '/reports', [ReportController::class, 'storeFromList'], ['perm' => 'reports.create']);
$router->add('POST', '/clients/{id}/report-schedule', [ReportController::class, 'schedule'], ['perm' => 'reports.schedule']);
$router->add('GET', '/reports/{id}', [ReportController::class, 'show'], ['client' => 'report']);
$router->add('GET', '/reports/{id}/view', [ReportController::class, 'view'], ['client' => 'report']);
$router->add('GET', '/reports/{id}/download', [ReportController::class, 'download'], ['client' => 'report']);
$router->add('GET', '/reports/{id}/csv', [ReportController::class, 'csv'], ['client' => 'report']);
$router->add('POST', '/reports/{id}/delete', [ReportController::class, 'delete'], ['perm' => 'reports.delete', 'client' => 'report']);
$router->add('POST', '/admin/branding', [ReportController::class, 'branding'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('GET', '/admin/branding/preview', [ReportController::class, 'brandingPreview'], ['perm' => 'settings.manage', 'all_clients' => true]);

// Global kill switch
$router->add('POST', '/scanning/pause', [ScanningController::class, 'pause'], ['perm' => 'scanning.pause', 'all_clients' => true]);
$router->add('POST', '/scanning/resume', [ScanningController::class, 'resume'], ['perm' => 'scanning.resume', 'all_clients' => true]);

// Admin only
$router->add('GET', '/users', [UserController::class, 'index'], ['perm' => 'users.manage']);
$router->add('GET', '/users/new', [UserController::class, 'create'], ['perm' => 'users.manage']);
$router->add('POST', '/users', [UserController::class, 'store'], ['perm' => 'users.manage']);
$router->add('GET', '/users/{id}', [UserController::class, 'edit'], ['perm' => 'users.manage']);
$router->add('POST', '/users/{id}', [UserController::class, 'update'], ['perm' => 'users.manage']);
$router->add('POST', '/users/{id}/password', [UserController::class, 'resetPassword'], ['perm' => 'users.manage']);
$router->add('POST', '/users/{id}/2fa-reset', [UserController::class, 'resetTwoFactor'], ['perm' => 'users.manage']);
$router->add('POST', '/users/{id}/sso-unlink', [UserController::class, 'unlinkSso'], ['perm' => 'users.manage']);
// Roles (1.40): built-in ones read-only, custom ones made from the permission list
$router->add('GET', '/admin/roles', [\Sentinel\Controllers\RoleController::class, 'index'], ['perm' => 'users.manage']);
$router->add('GET', '/admin/roles/new', [\Sentinel\Controllers\RoleController::class, 'create'], ['perm' => 'users.manage']);
$router->add('POST', '/admin/roles', [\Sentinel\Controllers\RoleController::class, 'store'], ['perm' => 'users.manage']);
$router->add('GET', '/admin/roles/{id}', [\Sentinel\Controllers\RoleController::class, 'edit'], ['perm' => 'users.manage']);
$router->add('POST', '/admin/roles/{id}', [\Sentinel\Controllers\RoleController::class, 'update'], ['perm' => 'users.manage']);
$router->add('POST', '/admin/roles/{id}/delete', [\Sentinel\Controllers\RoleController::class, 'delete'], ['perm' => 'users.manage']);
$router->add('GET', '/admin', [AdminController::class, 'index'], $anyAdmin);
$router->add('GET', '/admin/audit', [AdminController::class, 'auditLog'], ['perm' => 'audit.view', 'all_clients' => true]);
$router->add('GET', '/admin/integrations', [IntegrationsController::class, 'index'], ['perm' => 'integrations.manage', 'all_clients' => true]);
// Inventory sources (1.52): one save and test route per registered source, e.g. /admin/integrations/ninjaone.
foreach (array_keys(\Sentinel\Inventory\Sources::types()) as $sourceName) {
    $router->add('POST', '/admin/integrations/' . $sourceName, [IntegrationsController::class, 'saveInventory'], ['perm' => 'integrations.manage', 'all_clients' => true]);
    $router->add('POST', '/admin/integrations/' . $sourceName . '/test', [IntegrationsController::class, 'testInventory'], ['perm' => 'integrations.manage', 'all_clients' => true]);
}
$router->add('POST', '/admin/integrations/itflow', [IntegrationsController::class, 'saveItflow'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/itflow/test', [IntegrationsController::class, 'testItflow'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/itflow/sync', [IntegrationsController::class, 'syncItflow'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/itflow/tickets', [IntegrationsController::class, 'ticketsItflow'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/mspalign', [IntegrationsController::class, 'saveAlign'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/mspalign/test', [IntegrationsController::class, 'testAlign'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/sso', [IntegrationsController::class, 'saveSso'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/sso/connect', [IntegrationsController::class, 'ssoConnect'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/sso/connect/check', [IntegrationsController::class, 'ssoConnectCheck'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/sso/connect/cancel', [IntegrationsController::class, 'ssoConnectCancel'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/breach', [IntegrationsController::class, 'saveBreach'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/admin/integrations/breach/check', [IntegrationsController::class, 'checkBreach'], ['perm' => 'integrations.manage', 'all_clients' => true]);
$router->add('POST', '/clients/{id}/compliance/link', [ComplianceController::class, 'link'], ['perm' => 'integrations.link']);
$router->add('POST', '/clients/{id}/compliance/unlink', [ComplianceController::class, 'unlink'], ['perm' => 'integrations.link']);
$router->add('POST', '/clients/{id}/compliance/refresh', [ComplianceController::class, 'refresh'], ['perm' => 'scans.run']);
$router->add('GET', '/admin/settings', [AdminController::class, 'settings'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('POST', '/admin/settings', [AdminController::class, 'saveSettings'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('POST', '/admin/settings/due-dates', [AdminController::class, 'saveDuePolicy'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('POST', '/admin/settings/clients-timezone', [AdminController::class, 'moveClientsTimezone'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('POST', '/admin/settings/engagements', [AdminController::class, 'saveEngagementPolicy'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('POST', '/admin/feeds/refresh', [AdminController::class, 'refreshFeeds'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('POST', '/admin/alerts', [AlertController::class, 'save'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('POST', '/admin/alerts/test', [AlertController::class, 'test'], ['perm' => 'settings.manage', 'all_clients' => true]);
$router->add('GET', '/admin/system', [SystemController::class, 'index'], ['perm' => ['system.manage', 'release.manage'], 'all_clients' => true]);
$router->add('POST', '/admin/system/retention', [SystemController::class, 'retention'], ['perm' => 'system.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/updates', [SystemController::class, 'updates'], ['perm' => 'system.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/demo', [SystemController::class, 'demo'], ['perm' => 'system.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/update', [SystemController::class, 'update'], ['perm' => 'system.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/agents-update', [SystemController::class, 'updateAgents'], ['perm' => 'system.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/agents-move', [SystemController::class, 'moveAgents'], ['perm' => 'system.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/release-key', [SystemController::class, 'releaseKey'], ['perm' => 'release.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/backups', [SystemController::class, 'backups'], ['perm' => 'system.manage', 'all_clients' => true]);
$router->add('POST', '/admin/system/release-sign', [SystemController::class, 'releaseSign'], ['perm' => 'release.manage', 'all_clients' => true]);
$router->add('GET', '/admin/api', [ApiAdminController::class, 'index'], ['perm' => 'api.manage']);
$router->add('GET', '/admin/api/docs', [ApiAdminController::class, 'docs'], ['perm' => 'api.manage']);
$router->add('POST', '/admin/api/tokens', [ApiAdminController::class, 'create'], ['perm' => 'api.manage']);
$router->add('POST', '/admin/api/tokens/{id}/revoke', [ApiAdminController::class, 'revoke'], ['perm' => 'api.manage']);
$router->add('POST', '/admin/api/events', [ApiAdminController::class, 'events'], ['perm' => 'api.manage']);
$router->add('POST', '/admin/api/events/secret', [ApiAdminController::class, 'secret'], ['perm' => 'api.manage']);
$router->add('POST', '/admin/api/events/test', [ApiAdminController::class, 'test'], ['perm' => 'api.manage']);

return $router;
