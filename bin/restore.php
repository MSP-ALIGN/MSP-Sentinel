<?php

declare(strict_types=1);

/**
 * CLI: restore a backup made by bin/backup.php.
 *
 * Usage: php bin/restore.php --file=PATH [--yes] [--with-config] [--with-storage]
 *   Without --yes it only checks the backup and says what it would do.
 *   --with-config   also restore config/config.php (the old one is kept as .before-restore-*).
 *   --with-storage  also restore the storage folder (report logo).
 * Encrypted backups (.enc) need SENTINEL_BACKUP_PASSPHRASE or the passphrase on the terminal.
 * After restoring, pending migrations are applied.
 *
 * Security assumptions: run by the server administrator only (refuses to run
 * from the web). Every file is checked against the backup's manifest before
 * anything is changed. It REPLACES the tables in the configured database.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;
use Sentinel\Migrations\Migrator;
use Sentinel\System\Backup;

$opts = getopt('', ['file:', 'yes', 'with-config', 'with-storage']);
$file = is_string($opts['file'] ?? null) ? $opts['file'] : '';
if ($file === '') {
    fwrite(STDERR, "Usage: php bin/restore.php --file=PATH [--yes] [--with-config] [--with-storage]\n");
    exit(2);
}
$passphrase = null;
if (str_ends_with($file, '.enc')) {
    $passphrase = getenv('SENTINEL_BACKUP_PASSPHRASE') ?: null;
    if ($passphrase === null) {
        fwrite(STDOUT, 'Backup passphrase: ');
        $tty = function_exists('posix_isatty') && posix_isatty(STDIN);
        if ($tty) {
            shell_exec('stty -echo');
            register_shutdown_function(static fn () => shell_exec('stty echo'));
        }
        $passphrase = rtrim((string) fgets(STDIN), "\r\n");
        if ($tty) {
            shell_exec('stty echo');
            fwrite(STDOUT, "\n");
        }
    }
}

try {
    App::boot();
    $backup = new Backup(App::config(), SENTINEL_ROOT, App::version());
    [$work, $manifest] = $backup->open($file, $passphrase);
    fwrite(STDOUT, 'Backup OK: version ' . ($manifest['version'] ?? '?') . ', made ' . ($manifest['created_at'] ?? '?') . ', ' . count($manifest['files']) . " file(s) verified.\n");
    if (version_compare((string) ($manifest['version'] ?? '0'), App::version(), '>')) {
        $backup->discard($work);
        fwrite(STDERR, "This backup is from a newer version than this install. Upgrade first, then restore.\n");
        exit(1);
    }
    $keyDiffers = $backup->appKeyDiffers($work);
    if ($keyDiffers && !isset($opts['with-config'])) {
        fwrite(STDOUT, "Warning: the backup's app key differs from this install's. Without --with-config, 2FA and saved secrets will not work.\n");
    }
    if (!isset($opts['yes'])) {
        $backup->discard($work);
        fwrite(STDOUT, 'Would replace the database "' . App::config()->get('db.name') . '"' . (isset($opts['with-config']) ? ', the config file' : '') . (isset($opts['with-storage']) ? ', the storage folder' : '') . ". Add --yes to restore.\n");
        exit(0);
    }
    $backup->restore($work, isset($opts['with-config']), isset($opts['with-storage']));
    App::boot(); // reload, in case the config was restored
    $applied = (new Migrator(App::db(), SENTINEL_ROOT . '/migrations'))->migrate();
    fwrite(STDOUT, 'Restored.' . ($applied !== [] ? ' Applied ' . count($applied) . ' migration(s).' : '') . "\n");
    exit(0);
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Restore failed: ' . $ex->getMessage() . "\n");
    exit(1);
}
