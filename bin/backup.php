<?php

declare(strict_types=1);

/**
 * CLI: back up the database, the config file and the storage folder.
 *
 * Usage: php bin/backup.php [--dir=/var/backups/msp-sentinel] [--keep=14] [--encrypt]
 *   --encrypt  encrypt with a passphrase from SENTINEL_BACKUP_PASSPHRASE (cron)
 *              or asked on the terminal (at least 12 characters).
 *   --keep=N   keep only the newest N backups in the folder (default 14).
 *
 * Security assumptions: run by the server administrator only (refuses to run
 * from the web). The backup holds the app key, the database password and all
 * client data: it is written 0600 in a 0700 folder; encrypt copies kept
 * elsewhere. The passphrase is never printed or logged.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/src/bootstrap.php';

use Sentinel\Core\App;
use Sentinel\System\Backup;

$opts = getopt('', ['dir:', 'keep:', 'encrypt']);
$dir = is_string($opts['dir'] ?? null) ? rtrim($opts['dir'], '/') : SENTINEL_ROOT . '/storage/backups';
$keep = isset($opts['keep']) && ctype_digit((string) $opts['keep']) ? max(1, (int) $opts['keep']) : 14;
$passphrase = null;
/** Record a run that stopped before the backup started (1.37.1: cron with a missing passphrase was never recorded). */
$recordEarlyFailure = static function (string $why): void {
    try {
        App::boot();
        (new \Sentinel\System\BackupStatus(App::settings(), App::db()))->record(false, '', 0, true, $why);
    } catch (\Throwable) {
    }
};
if (isset($opts['encrypt'])) {
    $passphrase = getenv('SENTINEL_BACKUP_PASSPHRASE') ?: null;
    if ($passphrase === null) {
        $passphrase = sentinel_ask_secret('Backup passphrase (min 12 characters): ');
        if ($passphrase !== sentinel_ask_secret('Repeat the passphrase: ')) {
            fwrite(STDERR, "The passphrases do not match.\n");
            $recordEarlyFailure('The encryption passphrases did not match.');
            exit(2);
        }
    }
    if (mb_strlen($passphrase) < 12) {
        fwrite(STDERR, "The passphrase must be at least 12 characters.\n");
        $recordEarlyFailure('Encryption was asked for, but the passphrase is missing or shorter than 12 characters (check /etc/msp-sentinel/backup.env).');
        exit(2);
    }
}

try {
    App::boot();
    $file = (new Backup(App::config(), SENTINEL_ROOT, App::version()))->create($dir, $passphrase);
    $removed = Backup::prune($dir, $keep);
    // Recorded for the System page, the health check and the stale-backup alert (1.37). A failure to record never
    // turns a good backup into a failed run.
    try {
        (new \Sentinel\System\BackupStatus(App::settings(), App::db()))->record(true, $file, (int) filesize($file), $passphrase !== null);
    } catch (\Throwable) {
    }
    fwrite(STDOUT, 'Backup written: ' . $file . ' (' . round(filesize($file) / 1_000_000, 1) . " MB)\n");
    if ($removed > 0) {
        fwrite(STDOUT, "Removed {$removed} older backup(s) (keeping {$keep}).\n");
    }
    if ($passphrase === null) {
        fwrite(STDOUT, "Note: not encrypted. It contains the app key and database password: keep it private, or use --encrypt.\n");
    }
    exit(0);
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Backup failed: ' . $ex->getMessage() . "\n");
    try {
        (new \Sentinel\System\BackupStatus(App::settings(), App::db()))->record(false, '', 0, $passphrase !== null, $ex->getMessage());
    } catch (\Throwable) {
        // the database may be what failed
    }
    exit(1);
}

/** Read a secret from the terminal without echoing it. */
function sentinel_ask_secret(string $prompt): string
{
    $tty = function_exists('posix_isatty') && posix_isatty(STDIN);
    fwrite(STDOUT, $prompt);
    if ($tty) {
        shell_exec('stty -echo');
        register_shutdown_function(static fn () => shell_exec('stty echo'));
    }
    $value = rtrim((string) fgets(STDIN), "\r\n");
    if ($tty) {
        shell_exec('stty echo');
        fwrite(STDOUT, "\n");
    }
    return $value;
}
