<?php

declare(strict_types=1);

namespace Sentinel\Dashboard;

use PDO;
use Sentinel\Core\Settings;

/**
 * The first-run checklist on the dashboard (1.51): the steps of "Your first day", each ticked off by what Sentinel
 * already holds, so it needs no upkeep and can't drift from the truth.
 *
 * Shown to users who can manage settings, until every step is done or someone hides it (an organization-wide
 * setting, 'setup_checklist_hidden'). Read-only queries on Sentinel's own tables; no input is involved. Demo clients
 * and demo data never count as a first client, an authorization or a scan.
 */
final class SetupChecklist
{
    public function __construct(private readonly PDO $db, private readonly Settings $settings)
    {
    }

    /**
     * The steps in order, each with its label, a link to where it is done, and whether it is done.
     *
     * @return list<array{key:string,label:string,hint:string,url:string,done:bool}>
     */
    public function steps(): array
    {
        $count = fn (string $sql): int => (int) $this->db->query($sql)->fetchColumn();
        $realClient = 'c.is_demo = 0 AND c.is_archived = 0';
        return [
            ['key' => 'timezone', 'label' => __('Set your time zone'), 'hint' => __('Times are shown in it; new clients start in it.'),
             'url' => '/admin/settings', 'done' => $this->settings->get('display_timezone') !== 'UTC'],
            ['key' => 'admin', 'label' => __('Add a second admin'), 'hint' => __('A backup if you can\'t sign in, and a second approver for pen-test engagements.'),
             'url' => '/users', 'done' => $count("SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE r.role_key = 'admin' AND u.is_active = 1") >= 2],
            ['key' => 'alerts', 'label' => __('Turn on alerts'), 'hint' => __('Email or Teams/Slack, so new Fail findings reach the team.'),
             'url' => '/admin/settings#alerts', 'done' => $this->settings->get('email_enabled') === '1' || $this->settings->get('webhook_enabled') === '1'],
            ['key' => 'client', 'label' => __('Add your first client'), 'hint' => __('Or connect ITFlow to bring your clients in.'),
             'url' => '/clients/new', 'done' => $count("SELECT COUNT(*) FROM clients c WHERE {$realClient}") > 0],
            ['key' => 'authorization', 'label' => __('Record the client\'s authorization'), 'hint' => __('Nothing is scanned without the client\'s written approval.'),
             'url' => '/clients', 'done' => $count("SELECT COUNT(*) FROM scan_authorisations a JOIN clients c ON c.id = a.client_id AND {$realClient} WHERE a.revoked_at IS NULL") > 0],
            ['key' => 'scan', 'label' => __('Run the first scan'), 'hint' => __('Scan now on the client\'s overview, or wait for its weekly scan.'),
             'url' => '/clients', 'done' => $count("SELECT COUNT(*) FROM scan_jobs j JOIN clients c ON c.id = j.client_id AND c.is_demo = 0 WHERE j.status IN ('done', 'partial')") > 0],
        ];
    }

    /**
     * The steps when the checklist should be shown (not hidden, at least one step still open), else [] (1.51.1: one
     * set of queries per page).
     *
     * @return list<array{key:string,label:string,hint:string,url:string,done:bool}>
     */
    public function shown(): array
    {
        if ($this->settings->get('setup_checklist_hidden') === '1') {
            return [];
        }
        $steps = $this->steps();
        return array_filter($steps, static fn (array $s): bool => !$s['done']) !== [] ? $steps : [];
    }
}
