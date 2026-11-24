<?php

declare(strict_types=1);

namespace Sentinel\Auth;

/**
 * The fixed list of permissions (1.40) and what the three built-in roles hold.
 *
 * Every action in Sentinel that changes something, or shows something more sensitive than the day-to-day pages,
 * needs one of these permissions. Seeing a client's pages (findings, scans, devices, reports, engagements) needs
 * none: every signed-in user can read them (1.41 limits that to the user's clients).
 *
 * A role is a named set of permissions. The built-in roles (Viewer, Technician, Admin) are defined here, in code, so
 * they behave exactly as the old fixed roles did and a new permission in a later release reaches them without a
 * migration: Admin always holds every permission. Custom roles are stored in the database (role_permissions) and
 * edited on the Roles page.
 *
 * Security assumptions: permission names are fixed strings from this file; anything read from a form or the
 * database is checked with isValid() and unknown names are ignored (never granted). The list is the only place a
 * permission is defined, so a route or check naming an unknown permission is a programming error (Router throws).
 */
final class Permissions
{
    /** Groups, in the order the Roles page shows them. */
    public const GROUPS = ['clients', 'scanning', 'findings', 'reports', 'engagements', 'agents', 'admin'];

    /**
     * Every permission: group, then a short label and what it allows (shown on the Roles page; translated there).
     *
     * @var array<string, array{0:string, 1:string, 2:string}>
     */
    public const ALL = [
        'clients.manage' => ['clients', 'Manage clients', 'Add, edit and archive clients and their sites.'],
        'authorisations.manage' => ['clients', 'Manage authorisations', 'Record and revoke what may be scanned: external scope and internal (site) authorisations.'],
        'scanning.pause' => ['clients', 'Pause scanning', 'Pause all scanning, a client or a site (the kill switch).'],
        'scanning.resume' => ['clients', 'Resume scanning', 'Resume scanning after a pause.'],
        'integrations.link' => ['clients', 'Link clients to integrations', 'Link or unlink a client to its NinjaOne organisation and MSP Align client.'],

        'scans.run' => ['scanning', 'Run scans and discovery', 'Scan now, run discovery, dismiss or restore suggestions, cancel scans, sync inventory and refresh compliance.'],
        'scans.outside_window' => ['scanning', 'Scan outside the scan window', 'Start scans and fix checks at any time, not only in the client\'s scan window.'],

        'findings.triage' => ['findings', 'Triage findings', 'Accept a risk, mark a false positive or reopen (also for a group or picked findings). Can be given findings to fix.'],
        'findings.assign' => ['findings', 'Assign findings', 'Give findings an owner.'],
        'findings.verify' => ['findings', 'Verify fixes', 'Check again whether a finding is fixed.'],
        'findings.due' => ['findings', 'Set due dates', 'Change a finding\'s fix-by date.'],
        'breach.addresses' => ['findings', 'See breached addresses', 'See breached email addresses in full (others see them masked).'],

        'reports.create' => ['reports', 'Create reports', 'Create client and summary reports.'],
        'reports.schedule' => ['reports', 'Schedule reports', 'Set a client\'s monthly report schedule.'],
        'reports.delete' => ['reports', 'Delete reports', 'Delete issued reports.'],

        'engagements.run' => ['engagements', 'Run pen-test engagements', 'Create, run, stop and cancel engagements, download the signed document, and issue the report.'],
        'engagements.approve' => ['engagements', 'Approve pen-test engagements', 'Approve another person\'s engagement (never your own).'],

        'agents.manage' => ['agents', 'Manage agents', 'Enrol, approve, update, restart and revoke agents, change site agent settings, run diagnostics and scan a site now.'],
        'directory.manage' => ['agents', 'Manage directory checks', 'Set, trust and remove the Active Directory account the agents use.'],
        'devices.merge' => ['agents', 'Merge devices', 'Merge or split devices that the agent and an inventory source both report.'],

        'users.manage' => ['admin', 'Manage users and roles', 'Add users, change roles, reset passwords and two-factor authentication, and edit roles. Never more than you hold yourself.'],
        'api.manage' => ['admin', 'Manage the API', 'Create and revoke API tokens and set up webhooks.'],
        'integrations.manage' => ['admin', 'Manage integrations', 'Connect NinjaOne, ITFlow, MSP Align and breach monitoring, and run their syncs.'],
        'settings.manage' => ['admin', 'Manage settings', 'Scanning, due-date and alert settings, vulnerability feeds and report branding.'],
        'system.manage' => ['admin', 'Manage the system', 'Updates, backups, data retention, demo data, and updating or moving all agents. Gets system alerts.'],
        'release.manage' => ['admin', 'Manage agent releases', 'Set the release key and sign agent releases.'],
        'audit.view' => ['admin', 'View the audit log', 'Read the audit log of who did what.'],
    ];

    /** What the built-in Technician role holds (Viewer holds nothing extra; Admin holds everything). */
    private const TECHNICIAN = [
        'scanning.pause', 'scans.run', 'findings.triage', 'findings.assign', 'findings.verify', 'breach.addresses',
        'reports.create', 'engagements.run',
    ];

    /** The built-in role keys, most powerful last. */
    public const BUILTIN = ['viewer', 'technician', 'admin'];

    /** True for a known permission name. $name may be untrusted. */
    public static function isValid(string $name): bool
    {
        return isset(self::ALL[$name]);
    }

    /** @return list<string> every permission name */
    public static function names(): array
    {
        return array_keys(self::ALL);
    }

    /**
     * What a built-in role holds.
     *
     * @return list<string>
     */
    public static function builtin(string $key): array
    {
        return match ($key) {
            'admin' => self::names(),
            'technician' => self::TECHNICIAN,
            default => [],
        };
    }

    /**
     * Only the known names of a list, once each, in catalogue order (anything else is dropped, never granted).
     *
     * @param array<mixed> $names untrusted
     * @return list<string>
     */
    public static function clean(array $names): array
    {
        $set = array_flip(array_filter($names, 'is_string'));
        return array_values(array_filter(self::names(), static fn (string $n): bool => isset($set[$n])));
    }

    /** True when $held covers every permission. @param list<string> $held */
    public static function isComplete(array $held): bool
    {
        return array_diff(self::names(), $held) === [];
    }

    /** The translated name of a group. */
    public static function groupLabel(string $group): string
    {
        return match ($group) {
            'clients' => __('Clients and scope'),
            'scanning' => __('Scanning'),
            'findings' => __('Findings'),
            'reports' => __('Reports'),
            'engagements' => __('Pen-test engagements'),
            'agents' => __('Agents and devices'),
            default => __('Administration'),
        };
    }

    /**
     * The catalogue grouped for display, translated.
     *
     * @return array<string, list<array{name:string, label:string, help:string}>>
     */
    public static function grouped(): array
    {
        $out = array_fill_keys(self::GROUPS, []);
        foreach (self::ALL as $name => [$group, $label, $help]) {
            $out[$group][] = ['name' => $name, 'label' => __($label), 'help' => __($help)];
        }
        return $out;
    }

    /** True when any of the Administration permissions is held (the Administration menu shows). @param list<string> $held */
    public static function anyAdmin(array $held): bool
    {
        foreach ($held as $p) {
            if ((self::ALL[$p][0] ?? '') === 'admin') {
                return true;
            }
        }
        return false;
    }
}
