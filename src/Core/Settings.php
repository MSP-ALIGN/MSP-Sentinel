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
    ];

    /** @var array<string,string>|null */
    private ?array $cache = null;

    /** Reads and writes the settings table on the given connection. */
    public function __construct(private readonly PDO $db)
    {
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
