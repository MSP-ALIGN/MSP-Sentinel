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
        'retention_last_run' => '',
    ];

    /** Settings that hold secrets: stored encrypted with the app key, never shown again. */
    public const SECRETS = ['smtp_password', 'webhook_url', 'event_webhook_url', 'event_webhook_secret'];

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
        $this->set($name, $value === '' ? '' : $this->crypto->encrypt($value));
    }

    /** Read a secret setting (decrypted), or '' if unset or unreadable (e.g. the app key changed). */
    public function getSecret(string $name): string
    {
        if (!in_array($name, self::SECRETS, true) || $this->crypto === null) {
            throw new \InvalidArgumentException('Not a secret setting: ' . $name);
        }
        $stored = $this->get($name);
        if ($stored === '') {
            return '';
        }
        try {
            return $this->crypto->decrypt($stored);
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
