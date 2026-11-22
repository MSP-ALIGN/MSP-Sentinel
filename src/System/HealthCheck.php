<?php

declare(strict_types=1);

namespace Sentinel\System;

use PDO;
use Sentinel\Core\Config;
use Sentinel\Core\Settings;
use Sentinel\Migrations\Migrator;
use Sentinel\Scanning\NmapRunner;

/**
 * Checks that an install is healthy: PHP, database, migrations, nmap, the
 * cron jobs, storage, HTTPS, mail and updates. Used by bin/doctor.php and
 * the admin System page.
 *
 * Security assumptions: read-only (except a test write in storage/ that is
 * removed at once). Results never contain secrets: only states and short
 * explanations. The System page is admin-only.
 */
final class HealthCheck
{
    public const REQUIRED_EXTENSIONS = ['pdo_mysql', 'sodium', 'mbstring', 'openssl', 'curl', 'simplexml', 'json'];

    /** Needs the database, config, settings, the migrations folder and the update checker. */
    public function __construct(
        private readonly PDO $db,
        private readonly Config $config,
        private readonly Settings $settings,
        private readonly string $root,
        private readonly UpdateChecker $updates,
    ) {
    }

    /**
     * Run every check.
     *
     * @return list<array{key:string, label:string, status:string, detail:string}> status: ok|warn|fail
     */
    public function run(): array
    {
        $out = [];
        $add = static function (string $key, string $label, string $status, string $detail) use (&$out): void {
            $out[] = ['key' => $key, 'label' => $label, 'status' => $status, 'detail' => $detail];
        };
        // One broken check (for example a table missing before migrations ran) must not hide the others.
        $safe = static function (string $key, string $label, callable $check) use ($add): void {
            try {
                $check();
            } catch (\Throwable $ex) {
                $add($key, $label, 'fail', __('Could not check: {e}', ['e' => mb_substr($ex->getMessage(), 0, 150)]));
            }
        };

        // PHP
        $add('php', __('PHP version'), PHP_VERSION_ID >= 80400 ? 'ok' : 'warn',
            PHP_VERSION_ID >= 80400 ? PHP_VERSION : __('{v}: works, but 8.4 is recommended.', ['v' => PHP_VERSION]));
        $missing = array_values(array_filter(self::REQUIRED_EXTENSIONS, static fn (string $e): bool => !extension_loaded($e)));
        $add('extensions', __('PHP extensions'), $missing === [] ? 'ok' : 'fail', $missing === [] ? __('All required extensions are loaded.') : __('Missing: {list}', ['list' => implode(', ', $missing)]));
        $add('gd', __('Image support (GD)'), extension_loaded('gd') ? 'ok' : 'warn', extension_loaded('gd') ? __('Loaded.') : __('Missing: report logos cannot be uploaded (install php-gd).'));

        // Database
        $version = (string) $this->db->query('SELECT VERSION()')->fetchColumn();
        $isMaria = stripos($version, 'mariadb') !== false;
        $add('database', __('Database'), $isMaria && version_compare($version, '10.6', '>=') ? 'ok' : 'warn',
            $isMaria ? $version : __('{v}: MariaDB 10.6 or newer is the tested database.', ['v' => $version]));
        $pending = (new Migrator($this->db, $this->root . '/migrations'))->pending();
        $add('migrations', __('Database migrations'), $pending === [] ? 'ok' : 'fail',
            $pending === [] ? __('Up to date.') : __('{n} not applied: run php bin/migrate.php', ['n' => count($pending)]));
        $drift = abs((int) $this->db->query('SELECT UNIX_TIMESTAMP()')->fetchColumn() - time());
        $add('clock', __('Clock'), $drift <= 60 ? 'ok' : 'warn', $drift <= 60 ? __('Web server and database agree.') : __('Web server and database clocks differ by {n} seconds. Check time sync (NTP).', ['n' => $drift]));

        // Config file permissions
        $configPath = getenv('SENTINEL_CONFIG') ?: $this->root . '/config/config.php';
        $perms = @fileperms($configPath);
        $add('config', __('Config file'), $perms !== false && ($perms & 0o007) === 0 ? 'ok' : 'warn',
            $perms === false ? __('Could not read the file permissions.') : (($perms & 0o007) === 0 ? __('Not readable by other users.') : __('Readable by every user on the server: chmod 640 it (it holds the app key and database password).')));

        // nmap
        $nmap = NmapRunner::fromConfig($this->config);
        $add('nmap', __('nmap'), $nmap->available() ? 'ok' : 'fail', $nmap->available() ? __('Installed.') : __('Not found: install nmap or set scanner.nmap_path. Scans cannot run.'));

        // Worker (cron)
        $safe('worker', __('Scan worker (cron)'), function () use ($add): void {
        $tick = $this->settings->fresh('worker_last_tick');
        $age = $tick === '' ? null : time() - (int) strtotime($tick . ' UTC');
        $add('worker', __('Scan worker (cron)'), $age === null ? 'fail' : ($age <= 300 ? 'ok' : ($age <= 3600 ? 'warn' : 'fail')),
            $age === null ? __('Has never run. Add the worker cron job (every minute).') : __('Last run {n} minute(s) ago.', ['n' => intdiv($age, 60)]));
        });

        // Feeds
        $safe('feeds', __('Threat feeds'), function () use ($add): void {
        $feeds = $this->db->query('SELECT name, last_success FROM feed_status')->fetchAll(PDO::FETCH_KEY_PAIR);
        foreach (['kev' => 'CISA KEV', 'epss' => 'EPSS'] as $feed => $name) {
            $last = $feeds[$feed] ?? null;
            $old = $last === null ? null : time() - (int) strtotime($last . ' UTC');
            $add('feed_' . $feed, __('{feed} feed', ['feed' => $name]), $old !== null && $old <= 2 * 86400 ? 'ok' : 'warn',
                $old === null ? __('Never refreshed. Add the daily feeds cron job (bin/feeds.php).') : __('Last refreshed {n} hour(s) ago.', ['n' => intdiv($old, 3600)]));
        }
        });

        // Storage
        $storage = $this->root . '/storage';
        $probe = $storage . '/.health-' . bin2hex(random_bytes(4));
        $writable = (is_dir($storage) || @mkdir($storage, 0750, true)) && @file_put_contents($probe, 'x') !== false;
        @unlink($probe);
        $add('storage', __('Storage folder'), $writable ? 'ok' : 'fail', $writable ? __('Writable.') : __('{dir} is not writable by this user.', ['dir' => 'storage/']));
        $free = @disk_free_space($this->root);
        $add('disk', __('Disk space'), $free === false || $free > 1_000_000_000 ? 'ok' : 'warn',
            $free === false ? __('Unknown.') : __('{n} GB free.', ['n' => round($free / 1_000_000_000, 1)]));

        // HTTPS and links
        $url = (string) $this->config->get('app.public_url', '');
        $add('https', __('HTTPS and public address'), str_starts_with($url, 'https://') && $this->config->get('app.force_secure_cookies', false) === true ? 'ok' : 'warn',
            $url === '' ? __('app.public_url is not set: alert emails have no links.') : (str_starts_with($url, 'https://') ? ($this->config->get('app.force_secure_cookies', false) === true ? $url : __('Set app.force_secure_cookies to true.')) : __('app.public_url should start with https://.')));

        // Mail
        $safe('mail', __('Email'), function () use ($add): void {
        if ($this->settings->get('email_enabled') === '1') {
            $failed = (int) $this->db->query("SELECT COUNT(*) FROM deliveries WHERE channel = 'email' AND status = 'failed' AND created_at > UTC_TIMESTAMP() - INTERVAL 1 DAY")->fetchColumn();
            $add('mail', __('Email'), $failed === 0 ? 'ok' : 'warn', $failed === 0 ? __('No failed emails in the last day.') : __('{n} email(s) failed in the last day. See Settings, Alerts.', ['n' => $failed]));
        } else {
            $add('mail', __('Email'), 'warn', __('Email alerts are off.'));
        }
        });

        // Updates
        if ($this->settings->get('update_check_enabled') !== '1') {
            $add('updates', __('Updates'), 'ok', __('Update check is off.'));
        } else {
            $newer = $this->updates->newer();
            $add('updates', __('Updates'), $newer === null ? 'ok' : 'warn', $newer === null ? __('Up to date (as of the last daily check).') : __('Version {v} is available.', ['v' => $newer]));
        }
        return $out;
    }
}
