<?php

declare(strict_types=1);

namespace Sentinel\System;

use Sentinel\Core\Config;

/**
 * Backups and restores: the database (mysqldump), the config file and the
 * storage folder, in one .tar.gz, optionally encrypted.
 *
 * Archive layout: manifest.json (version, time, SHA-256 of each file),
 * database.sql, config.php, storage/...
 *
 * Encryption (".enc"): a passphrase is stretched with Argon2id
 * (sodium_crypto_pwhash, random salt), then the archive is encrypted with
 * libsodium secretstream (XChaCha20-Poly1305) in 64 KB chunks. Any change to
 * the file makes decryption fail. File: "MSPSBK1\n" + salt + stream header + chunks.
 *
 * Security assumptions:
 * - A backup holds the app key and the database password (in config.php)
 *   and all client data. Files and folders are created 0600/0700; encrypting
 *   is strongly recommended for copies kept off the server.
 * - Database credentials are passed to mysqldump/mysql in a temporary 0600
 *   options file, never on the command line (visible to other users in ps).
 * - Restoring checks every file against the manifest before touching anything,
 *   and only writes into the configured database, config/ and storage/.
 * - The passphrase comes from the SENTINEL_BACKUP_PASSPHRASE environment
 *   variable or the terminal; it is never logged.
 */
final class Backup
{
    private const MAGIC = "MSPSBK1\n";
    private const CHUNK = 65536;

    /** @param string $root Install folder. */
    public function __construct(private readonly Config $config, private readonly string $root, private readonly string $version)
    {
    }

    /**
     * Create a backup in $dir. Returns the file path.
     *
     * @throws \RuntimeException with a safe message.
     */
    public function create(string $dir, ?string $passphrase): string
    {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            throw new \RuntimeException('Cannot create the backup folder ' . $dir);
        }
        @chmod($dir, 0700);
        $work = $this->tempDir();
        try {
            $this->dump($work . '/database.sql');
            $configPath = getenv('SENTINEL_CONFIG') ?: $this->root . '/config/config.php';
            copy($configPath, $work . '/config.php');
            if (is_dir($this->root . '/storage')) {
                // Not earlier backups (they'd nest) and not the CA bundle cache (rebuilt automatically).
                $this->copyTree($this->root . '/storage', $work . '/storage', ['backups/', 'ca/']);
            }
            $files = [];
            foreach ($this->listFiles($work) as $rel) {
                $files[$rel] = hash_file('sha256', $work . '/' . $rel);
            }
            file_put_contents($work . '/manifest.json', json_encode(['product' => 'msp-sentinel', 'version' => $this->version, 'created_at' => gmdate('Y-m-d\TH:i:s\Z'), 'files' => $files], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            $name = 'msp-sentinel-backup-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3));
            $tar = $work . '/../' . $name . '.tar';
            $old = umask(0077);
            try {
                $phar = new \PharData($tar);
                $phar->buildFromDirectory($work);
                $phar->compress(\Phar::GZ);
                unset($phar);
                @unlink($tar);
                $gz = $tar . '.gz';
                if ($passphrase !== null) {
                    $target = $dir . '/' . $name . '.tar.gz.enc';
                    self::encryptFile($gz, $target, $passphrase);
                    @unlink($gz);
                } else {
                    $target = $dir . '/' . $name . '.tar.gz';
                    if (!@rename($gz, $target)) {
                        copy($gz, $target);
                        @unlink($gz);
                    }
                }
                @chmod($target, 0600);
            } finally {
                umask($old);
            }
            return $target;
        } finally {
            $this->removeTree($work);
        }
    }

    /**
     * Keep only the newest $keep backups in $dir. Returns how many were removed.
     */
    public static function prune(string $dir, int $keep): int
    {
        $files = glob($dir . '/msp-sentinel-backup-*.tar.gz*') ?: [];
        rsort($files); // names sort by time
        $removed = 0;
        foreach (array_slice($files, max(1, $keep)) as $f) {
            if (@unlink($f)) {
                $removed++;
            }
        }
        return $removed;
    }

    /**
     * Check and unpack a backup into a temporary folder. Returns [folder, manifest].
     *
     * @return array{0:string, 1:array<string,mixed>}
     * @throws \RuntimeException if it is damaged, the passphrase is wrong, or a file doesn't match the manifest.
     */
    public function open(string $file, ?string $passphrase): array
    {
        if (!is_file($file)) {
            throw new \RuntimeException('Backup file not found.');
        }
        $work = $this->tempDir();
        try {
            $gz = $work . '/backup.tar.gz';
            if (str_ends_with($file, '.enc')) {
                if ($passphrase === null) {
                    throw new \RuntimeException('This backup is encrypted: set SENTINEL_BACKUP_PASSPHRASE or enter the passphrase.');
                }
                self::decryptFile($file, $gz, $passphrase);
            } else {
                copy($file, $gz);
            }
            $out = $work . '/files';
            mkdir($out, 0700);
            $phar = new \PharData($gz);
            // Refuse paths that would escape the folder (PharData also normalises them).
            foreach (new \RecursiveIteratorIterator($phar) as $entry) {
                $rel = substr((string) $entry->getPathname(), strlen('phar://' . $gz . '/'));
                if (str_contains($rel, '..') || str_starts_with($rel, '/')) {
                    throw new \RuntimeException('The backup contains an unsafe path.');
                }
            }
            $phar->extractTo($out);
            $manifest = json_decode((string) @file_get_contents($out . '/manifest.json'), true);
            if (!is_array($manifest) || ($manifest['product'] ?? '') !== 'msp-sentinel' || !is_array($manifest['files'] ?? null)) {
                throw new \RuntimeException('This is not an MSP Sentinel backup (no valid manifest).');
            }
            foreach ($manifest['files'] as $rel => $sha) {
                if (!is_string($rel) || str_contains($rel, '..') || !is_file($out . '/' . $rel) || !hash_equals((string) $sha, (string) hash_file('sha256', $out . '/' . $rel))) {
                    throw new \RuntimeException('The backup is damaged: ' . (is_string($rel) ? $rel : '?') . ' does not match its checksum.');
                }
            }
            if (!isset($manifest['files']['database.sql'])) {
                throw new \RuntimeException('The backup has no database dump.');
            }
            return [$work, $manifest];
        } catch (\Throwable $ex) {
            $this->removeTree($work);
            throw $ex instanceof \RuntimeException ? $ex : new \RuntimeException('The backup could not be read: ' . $ex->getMessage());
        }
    }

    /**
     * Restore an opened backup into the configured database (and optionally config and storage).
     *
     * @param string $work Folder returned by open().
     */
    public function restore(string $work, bool $withConfig, bool $withStorage): void
    {
        $files = $work . '/files';
        try {
            $this->import($files . '/database.sql');
            if ($withStorage && is_dir($files . '/storage')) {
                $this->copyTree($files . '/storage', $this->root . '/storage');
            }
            if ($withConfig && is_file($files . '/config.php')) {
                $configPath = getenv('SENTINEL_CONFIG') ?: $this->root . '/config/config.php';
                $restored = include $files . '/config.php';
                $current = is_file($configPath) ? include $configPath : [];
                if (!is_array($restored)) {
                    throw new \RuntimeException('The config file in the backup is not valid.');
                }
                // Keep THIS server's database connection (a new server has its own database password);
                // everything else, above all the app key, comes from the backup.
                if (is_array($current) && isset($current['db'])) {
                    $restored['db'] = $current['db'];
                }
                if (is_file($configPath)) {
                    copy($configPath, $configPath . '.before-restore-' . gmdate('Ymd-His'));
                }
                // Writing into the existing file keeps its owner and group.
                file_put_contents($configPath, "<?php\n\n// Restored from a backup on " . gmdate('Y-m-d') . " (database settings kept from this server).\n\nreturn "
                    . var_export($restored, true) . ";\n", LOCK_EX);
                @chmod($configPath, 0640);
            }
        } finally {
            $this->removeTree($work);
        }
    }

    /** True if the backup's app key differs from the current one (2FA and secrets would not decrypt). */
    public function appKeyDiffers(string $work): bool
    {
        $cfg = @include $work . '/files/config.php';
        return !is_array($cfg) || ($cfg['app_key'] ?? null) !== $this->config->get('app_key');
    }

    /** Remove an opened backup's temporary folder (when not restoring). */
    public function discard(string $work): void
    {
        $this->removeTree($work);
    }

    /** Encrypt a file with a passphrase (see class notes). */
    public static function encryptFile(string $in, string $out, string $passphrase): void
    {
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $key = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, $passphrase, $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $src = fopen($in, 'rb');
        $dst = fopen($out, 'wb');
        if ($src === false || $dst === false) {
            throw new \RuntimeException('Cannot open files for encryption.');
        }
        fwrite($dst, self::MAGIC . $salt . $header);
        $chunk = fread($src, self::CHUNK);
        while (true) {
            $next = feof($src) ? '' : fread($src, self::CHUNK);
            $last = $next === '' || $next === false;
            fwrite($dst, sodium_crypto_secretstream_xchacha20poly1305_push($state, (string) $chunk, '',
                $last ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE));
            if ($last) {
                break;
            }
            $chunk = $next;
        }
        fclose($src);
        fclose($dst);
        sodium_memzero($key);
    }

    /** Decrypt a file made by encryptFile(). Throws on a wrong passphrase or any tampering. */
    public static function decryptFile(string $in, string $out, string $passphrase): void
    {
        $src = fopen($in, 'rb');
        if ($src === false) {
            throw new \RuntimeException('Cannot open the backup.');
        }
        $head = fread($src, strlen(self::MAGIC) + SODIUM_CRYPTO_PWHASH_SALTBYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if (!is_string($head) || !str_starts_with($head, self::MAGIC) || strlen($head) !== strlen(self::MAGIC) + SODIUM_CRYPTO_PWHASH_SALTBYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new \RuntimeException('Not an encrypted MSP Sentinel backup.');
        }
        $salt = substr($head, strlen(self::MAGIC), SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $header = substr($head, strlen(self::MAGIC) + SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $key = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, $passphrase, $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        sodium_memzero($key);
        $dst = fopen($out, 'wb');
        $final = false;
        while (!feof($src)) {
            $c = fread($src, self::CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            if ($c === '' || $c === false) {
                break;
            }
            $r = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $c);
            if ($r === false || $final) {
                fclose($dst);
                @unlink($out);
                throw new \RuntimeException('Wrong passphrase, or the backup file is damaged.');
            }
            fwrite($dst, $r[0]);
            $final = $r[1] === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
        }
        fclose($src);
        fclose($dst);
        if (!$final) {
            @unlink($out);
            throw new \RuntimeException('The backup file is incomplete (truncated).');
        }
    }

    /** Run mysqldump (or mariadb-dump) into $file. */
    private function dump(string $file): void
    {
        $bin = $this->findBinary(['mariadb-dump', 'mysqldump']);
        $opts = $this->optionsFile();
        try {
            $cmd = [$bin, '--defaults-extra-file=' . $opts, '--single-transaction', '--quick', '--hex-blob', '--no-tablespaces',
                    '--default-character-set=utf8mb4', '--skip-comments', '--result-file=' . $file, (string) $this->config->get('db.name')];
            $this->run($cmd, null, 'Database dump failed');
        } finally {
            @unlink($opts);
        }
        if (!is_file($file) || filesize($file) === 0) {
            throw new \RuntimeException('Database dump is empty.');
        }
    }

    /** Import an SQL file with the mysql/mariadb client. */
    private function import(string $file): void
    {
        $bin = $this->findBinary(['mariadb', 'mysql']);
        $opts = $this->optionsFile();
        try {
            $this->run([$bin, '--defaults-extra-file=' . $opts, '--default-character-set=utf8mb4', (string) $this->config->get('db.name')], $file, 'Database restore failed');
        } finally {
            @unlink($opts);
        }
    }

    /**
     * Run a command without a shell. $stdinFile is fed to stdin.
     *
     * @param list<string> $cmd
     */
    private function run(array $cmd, ?string $stdinFile, string $what): void
    {
        $proc = proc_open($cmd, [0 => $stdinFile !== null ? ['file', $stdinFile, 'r'] : ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            throw new \RuntimeException($what . ': could not start ' . basename($cmd[0]) . '.');
        }
        stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        $code = proc_close($proc);
        if ($code !== 0) {
            throw new \RuntimeException($what . ': ' . mb_substr(trim($err), 0, 300));
        }
    }

    /** A temporary 0600 client options file with the database credentials. */
    private function optionsFile(): string
    {
        $path = sys_get_temp_dir() . '/msp-sentinel-db-' . bin2hex(random_bytes(8)) . '.cnf';
        $old = umask(0077);
        $q = static fn (string $v): string => '"' . addcslashes($v, "\\\"") . '"';
        file_put_contents($path, "[client]\nhost=" . $q((string) $this->config->get('db.host')) . "\nport=" . (int) $this->config->get('db.port', 3306)
            . "\nuser=" . $q((string) $this->config->get('db.user')) . "\npassword=" . $q((string) $this->config->get('db.pass', '')) . "\n");
        umask($old);
        return $path;
    }

    /** First binary found on PATH (or in /usr/bin). */
    private function findBinary(array $names): string
    {
        foreach ($names as $n) {
            foreach (array_merge(explode(':', (string) getenv('PATH')), ['/usr/bin', '/usr/local/bin']) as $d) {
                if ($d !== '' && is_executable($d . '/' . $n)) {
                    return $d . '/' . $n;
                }
            }
        }
        throw new \RuntimeException('Not found: ' . implode(' or ', $names) . ' (install the MariaDB client).');
    }

    /** A new private temporary folder. */
    private function tempDir(): string
    {
        $dir = sys_get_temp_dir() . '/msp-sentinel-backup-' . bin2hex(random_bytes(8));
        mkdir($dir, 0700);
        return $dir;
    }

    /** @return list<string> Files below $dir, relative, sorted. */
    private function listFiles(string $dir): array
    {
        $out = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile() && !$f->isLink()) {
                $out[] = substr($f->getPathname(), strlen($dir) + 1);
            }
        }
        sort($out);
        return $out;
    }

    /**
     * Copy a folder tree (regular files only; links are skipped).
     *
     * @param list<string> $skip Relative path prefixes to leave out.
     */
    private function copyTree(string $from, string $to, array $skip = []): void
    {
        if (!is_dir($to)) {
            mkdir($to, 0750, true);
        }
        foreach ($this->listFiles($from) as $rel) {
            foreach ($skip as $prefix) {
                if (str_starts_with($rel, $prefix) || str_starts_with(basename($rel), '.')) {
                    continue 2;
                }
            }
            $dest = $to . '/' . $rel;
            if (!is_dir(dirname($dest))) {
                mkdir(dirname($dest), 0750, true);
            }
            copy($from . '/' . $rel, $dest);
            @chmod($dest, 0640);
        }
    }

    /** Delete a folder tree. */
    private function removeTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($dir);
    }
}
