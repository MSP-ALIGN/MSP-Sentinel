<?php

declare(strict_types=1);

namespace Sentinel\Core;

use PDO;

/**
 * Settings an admin can change in the UI, stored in the `settings` table.
 *
 * Only names listed in DEFAULTS can be read or written, so a form can't
 * create arbitrary settings.
 *
 * Security assumptions:
 * - Values are untrusted text (an admin typed them). They are validated by
 *   the controller before saving and escaped on output.
 * - Secret settings (added in later releases) are stored with Crypto,
 *   never as plain text.
 */
final class Settings
{
    /** Known settings and their defaults. */
    public const DEFAULTS = [
        // White-label: the name shown in the web UI.
        'product_name' => 'MSP Sentinel',
        // AGPL-3.0 section 13: users interacting over a network must be offered the source.
        'source_url' => 'https://github.com/msp-align/msp-sentinel',
        // Global kill switch: '1' stops all scanning straight away. Technicians and admins can pause; only admins resume.
        'scanning_paused' => '0',
        // The dashboard's first-run checklist (1.51): '1' once someone who manages settings hides it.
        'setup_checklist_hidden' => '0',
        // Alerts (step 8). Secrets (smtp_password, webhook_url) are stored encrypted: see setSecret().
        'email_enabled' => '0',
        'smtp_host' => '',
        'smtp_port' => '587',
        'smtp_security' => 'starttls',
        'smtp_username' => '',
        'smtp_password' => '',
        'smtp_from' => '',
        'team_addresses' => '',
        'webhook_enabled' => '0',
        'webhook_url' => '',
        'webhook_format' => 'teams',
        // Report branding (step 9). The logo is a SHA-256 naming a re-encoded PNG in storage/branding.
        'brand_name' => '',
        'brand_color' => '#1f4e79',
        'brand_footer' => '',
        'brand_logo' => '',
        'report_paper' => 'A4',
        'report_powered_by' => '1',
        // Branding suite (1.59): second color, cover style, contact block, sign-off and the confidential label
        // ({client} becomes the client's name). All plain text, validated by ReportController::branding().
        'brand_accent' => '#5aa9e6',
        'report_cover' => 'color',
        'brand_address' => '',
        'brand_phone' => '',
        'brand_email' => '',
        'brand_website' => '',
        'report_prepared_by' => '',
        'report_prepared_title' => '',
        'report_signoff' => '',
        'report_confidential' => 'Confidential: prepared for {client}',
        // '1' when the logo already shows the company name (1.60): the cover and emails then show the logo alone.
        'brand_logo_has_name' => '0',
        // Outbound events for other systems (step 10). URL and signing secret are stored encrypted.
        'event_webhook_enabled' => '0',
        'event_webhook_url' => '',
        'event_webhook_secret' => '',
        // Operations (step 11). Retention: months to keep (0 = keep forever). The audit log is never pruned.
        'retention_scans_months' => '0',
        'retention_findings_months' => '0',
        'retention_reports_months' => '0',
        'update_check_enabled' => '1',
        // Written by the worker (not shown in forms).
        'worker_last_tick' => '',
        'update_latest_version' => '',
        'update_checked_at' => '',
        // Why the last release check found no version (1.55.2): '' (it did), 'no_release' or 'unreachable'.
        'update_last_error' => '',
        // Vulnerability data refresh (FeedSchedule): last run start and end, and the last "Refresh now" (UTC).
        'feeds_run_started' => '',
        'feeds_run_finished' => '',
        'feeds_requested_at' => '',
        'feeds_run_ok' => '',
        // NinjaOne (Administration > Integrations): instance host, API client ID, and on/off. The client secret
        // is in ninjaone_client_secret (encrypted, see SECRETS).
        'ninjaone_enabled' => '0',
        'ninjaone_host' => '',
        'ninjaone_client_id' => '',
        'ninjaone_client_secret' => '',
        'ninjaone_tested_at' => '',
        'ninjaone_test_result' => '',
        // MSP Align compliance (read-only): address, on/off, last test. The API key is in mspalign_api_key (SECRETS).
        'mspalign_enabled' => '0',
        'mspalign_url' => '',
        'mspalign_api_key' => '',
        'mspalign_tested_at' => '',
        'mspalign_test_result' => '',
        'mspalign_clients_cache' => '',
        // ITFlow client sync (ItflowSync): address, on/off, last test and last sync. The key is in itflow_api_key (SECRETS).
        'itflow_enabled' => '0',
        'itflow_url' => '',
        'itflow_api_key' => '',
        'itflow_tested_at' => '',
        'itflow_test_result' => '',
        'itflow_last_sync' => '',
        'itflow_last_result' => '',
        'itflow_last_ok' => '',
        // ITFlow tickets from findings (ItflowTickets): on/off, from when, and the last run.
        'tickets_enabled' => '0',
        // 1.56: one priority for every Sentinel ticket ('' = automatic: High, Urgent when exploited, Medium weekly), and an
        // optional ITFlow ticket template whose category (tags, tasks, due time) new tickets get.
        'tickets_priority' => '',
        'itflow_ticket_template' => '',
        'tickets_since' => '', 'tickets_weekly_since' => '',
        // Moving agents to a new Sentinel address: ONE value in SECRETS (agent_move, JSON url/ca/requested_at), encrypted
        // and authenticated with the app key from the config file, so a database write alone can't set a move.
        'agent_move' => '',
        // Agent release key made on the System page: ONE value in SECRETS (release_key, JSON: the PUBLIC key, when it was
        // made, and the chain of rotation statements each signed by the key before), encrypted and authenticated with the
        // app key, so a database write alone can't plant a release key agents would trust. The private key stays in the
        // admin's file.
        'release_key' => '',
        'tickets_last_run' => '',
        'tickets_last_result' => '',
        'tickets_last_ok' => '',
        // Breach monitoring (1.33, XposedOrNot): on/off, the last weekly check and its result, verified domains in no
        // client's register. The API key is in xon_api_key (SECRETS).
        'breach_enabled' => '0',
        'xon_api_key' => '',
        // ITFlow service board for new tickets (1.44, ITFlow builds with boards): '' = the board named "Alerts",
        // '0' = ITFlow's default board, else a board ID.
        'itflow_board' => '',
        // Sync only ITFlow clients with this tag (1.45): on/off and the tag's name (matched ignoring case).
        'itflow_tag_filter' => '0',
        'itflow_tag_name' => 'Sentinel',
        // The boards ITFlow listed last (1.44.1, JSON; 'null' = this ITFlow has none, '' = not checked yet): refreshed by
        // the sync, Test connection and ticket runs, so the Integrations page never waits on ITFlow.
        'itflow_boards_cache' => '',
        // Sign in with Microsoft (1.43): on/off, the Entra tenant and app (client) IDs; the client secret is a secret.
        // The organisation's time zone (1.48): how times are shown (unless a user picks their own) and where new
        // clients start. Times are stored and compared in UTC whatever this is.
        'display_timezone' => 'UTC',
        // Pen-test engagements need a second person to approve them (1.47: '0' lets the creator approve their own).
        'engagement_two_person' => '1',
        'sso_entra_enabled' => '0',
        'sso_entra_tenant' => '',
        'sso_entra_client' => '',
        'sso_entra_secret' => '',
        // Automatic setup (1.46): when the script-made secret expires, the one-time setup code (HMAC), and warnings.
        'sso_entra_secret_expires' => '',
        'sso_setup_code' => '',
        'sso_setup_expires' => '',
        'sso_setup_by' => '',
        'sso_setup_new_tenant' => '0',
        'sso_secret_warned' => '',
        'breach_last_run' => '',
        'breach_last_ok_run' => '',
        'breach_last_result' => '',
        'breach_last_ok' => '',
        'breach_unmatched' => '',
        // Backup runs (1.37): JSON list written by bin/backup.php (BackupStatus), newest first.
        'backup_history' => '',
        // '1' when backups are made another way (VM snapshots...): no backup warning or alert (1.37.1).
        'backup_external' => '0',
        // Git-based installs: commits the followed branch is ahead of the installed commit, its newest commit, and
        // the installed commit the answer is for (so an answer for an older commit is never shown after updating).
        'update_branch_behind' => '',
        'update_branch_head' => '',
        'update_branch_base' => '',
        'retention_last_run' => '',
        // Fix workflow: days to fix by severity (known-exploited first), and the last daily reminder run (Y-m-d, UTC).
        'due_days_kev' => '7',
        'due_days_fail' => '14',
        'due_days_warn' => '30',
        'fix_reminders_last_run' => '',
    ];

    /** Settings that hold secrets: stored encrypted with the app key, never shown again. */
    public const SECRETS = ['smtp_password', 'webhook_url', 'event_webhook_url', 'event_webhook_secret', 'ninjaone_client_secret', 'mspalign_api_key', 'itflow_api_key', 'agent_move', 'release_key', 'xon_api_key', 'sso_entra_secret'];

    /** @var array<string,string>|null */
    private ?array $cache = null;

    /** Reads and writes the settings table on the given connection. Crypto is needed for secret settings. */
    public function __construct(private readonly PDO $db, private readonly ?Crypto $crypto = null)
    {
    }

    /** Store a secret setting encrypted ('' clears it). */
    public function setSecret(string $name, string $value): void
    {
        if (!in_array($name, self::SECRETS, true) || $this->crypto === null) {
            throw new \InvalidArgumentException('Not a secret setting: ' . $name);
        }
        $this->set($name, $value === '' ? '' : $this->crypto->encryptFor('setting:' . $name, $value));
    }

    /** Read a secret setting (decrypted, straight from the database), or '' if unset or unreadable (e.g. the app key changed). */
    public function getSecret(string $name): string
    {
        if (!in_array($name, self::SECRETS, true) || $this->crypto === null) {
            throw new \InvalidArgumentException('Not a secret setting: ' . $name);
        }
        $stored = $this->fresh($name); // never stale: a changed password applies at once, also in long-running processes
        if ($stored === '') {
            return '';
        }
        try {
            return $this->crypto->decryptFor('setting:' . $name, $stored); // bound to this setting's name (1.34)
        } catch (\RuntimeException) {
            return '';
        }
    }

    /** A known setting, or its default. Unknown names throw. */
    public function get(string $name): string
    {
        if (!array_key_exists($name, self::DEFAULTS)) {
            throw new \InvalidArgumentException('Unknown setting: ' . $name);
        }
        if ($this->cache === null) {
            $this->cache = [];
            foreach ($this->db->query('SELECT name, value FROM settings') as $row) {
                $this->cache[(string) $row['name']] = (string) $row['value'];
            }
        }
        return $this->cache[$name] ?? self::DEFAULTS[$name];
    }

    /**
     * Read a setting straight from the database, skipping the cache. Use it for
     * values that must never be stale, such as the scanning kill switch, which
     * long-running workers check again and again.
     */
    public function fresh(string $name): string
    {
        if (!array_key_exists($name, self::DEFAULTS)) {
            throw new \InvalidArgumentException('Unknown setting: ' . $name);
        }
        $stmt = $this->db->prepare('SELECT value FROM settings WHERE name = :n');
        $stmt->execute(['n' => $name]);
        $value = $stmt->fetchColumn();
        return $value === false ? self::DEFAULTS[$name] : (string) $value;
    }

    /** Save a setting. The caller has already validated the value. */
    public function set(string $name, string $value): void
    {
        if (!array_key_exists($name, self::DEFAULTS)) {
            throw new \InvalidArgumentException('Unknown setting: ' . $name);
        }
        $stmt = $this->db->prepare('INSERT INTO settings (name, value) VALUES (:n, :v) ON DUPLICATE KEY UPDATE value = VALUES(value)');
        $stmt->execute(['n' => $name, 'v' => $value]);
        $this->cache = null;
    }
}
