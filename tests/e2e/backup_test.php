<?php

declare(strict_types=1);

/**
 * End-to-end tests for bin/backup.php and bin/restore.php: archive contents
 * and permissions, encryption (wrong passphrase and tampering refused),
 * dry run by default, and a real restore into the test database.
 */

use Sentinel\System\Backup;
use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$dir = static fn (): string => sys_get_temp_dir() . '/sentinel-backup-test';

return [
    'plain backup: database, config and manifest; private file' => function (TestContext $ctx) use ($dir): void {
        $d = $dir();
        array_map('unlink', glob($d . '/*') ?: []);
        [$code, $out] = $ctx->cli('bin/backup.php', ['--dir=' . $d, '--keep=2']);
        Assert::same(0, $code, $out);
        Assert::contains('not encrypted', $out);
        $files = glob($d . '/msp-sentinel-backup-*.tar.gz') ?: [];
        Assert::same(1, count($files));
        Assert::same('0600', substr(sprintf('%o', fileperms($files[0])), -4));
        Assert::same('0700', substr(sprintf('%o', fileperms($d)), -4));
        $phar = new PharData($files[0]);
        Assert::true(isset($phar['database.sql'], $phar['config.json'], $phar['manifest.json']) && !isset($phar['config.php']), 'contents (config as data, not code)');
        Assert::contains('CREATE TABLE `findings`', (string) file_get_contents('phar://' . $files[0] . '/database.sql'));
        // --keep prunes older backups.
        $ctx->cli('bin/backup.php', ['--dir=' . $d, '--keep=2']);
        $ctx->cli('bin/backup.php', ['--dir=' . $d, '--keep=2']);
        Assert::same(2, count(glob($d . '/msp-sentinel-backup-*') ?: []), 'kept the newest 2');
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . (glob($d . '/*.tar.gz') ?: [''])[0]]);
        Assert::same(0, $code, $out);
        Assert::contains('Add --yes to restore', $out, 'dry run unless --yes');
    },
    'encrypted backup: unreadable without the passphrase; tampering detected' => function (TestContext $ctx) use ($dir): void {
        $d = $dir() . '-enc';
        array_map('unlink', glob($d . '/*') ?: []);
        [$code, $out] = $ctx->cli('bin/backup.php', ['--dir=' . $d, '--encrypt'], ['SENTINEL_BACKUP_PASSPHRASE' => 'short']);
        Assert::same(2, $code, 'passphrase too short');
        [$code, $out] = $ctx->cli('bin/backup.php', ['--dir=' . $d, '--encrypt'], ['SENTINEL_BACKUP_PASSPHRASE' => 'correct horse battery staple']);
        Assert::same(0, $code, $out);
        $file = (glob($d . '/*.tar.gz.enc') ?: [''])[0];
        $raw = (string) file_get_contents($file);
        Assert::true(str_starts_with($raw, "MSPSBK1\n"), 'format marker');
        $cfg = require $ctx->configPath;
        Assert::notContains($cfg['app_key'], $raw, 'app key not readable');
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . $file], ['SENTINEL_BACKUP_PASSPHRASE' => 'wrong passphrase here']);
        Assert::same(1, $code);
        Assert::contains('Wrong passphrase', $out);
        $bad = $d . '/tampered.tar.gz.enc';
        $raw[(int) (strlen($raw) / 2)] = chr(ord($raw[(int) (strlen($raw) / 2)]) ^ 1);
        file_put_contents($bad, $raw);
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . $bad], ['SENTINEL_BACKUP_PASSPHRASE' => 'correct horse battery staple']);
        Assert::same(1, $code, 'tampered file refused');
        $cut = $d . '/cut.tar.gz.enc';
        file_put_contents($cut, substr((string) file_get_contents($file), 0, -100));
        [$code] = $ctx->cli('bin/restore.php', ['--file=' . $cut], ['SENTINEL_BACKUP_PASSPHRASE' => 'correct horse battery staple']);
        Assert::same(1, $code, 'truncated file refused');
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . $file], ['SENTINEL_BACKUP_PASSPHRASE' => 'correct horse battery staple']);
        Assert::same(0, $code, $out);
        Assert::contains('file(s) verified', $out);
    },
    'a tampered database dump cannot run client commands (shell, source)' => function (TestContext $ctx): void {
        $root = dirname(__DIR__, 2);
        $b = new \Sentinel\System\Backup(\Sentinel\Core\App::config(), $root, \Sentinel\Core\App::version());
        $refuse = new ReflectionMethod($b, 'refuseClientCommands');
        $marker = sys_get_temp_dir() . '/sentinel-shell-' . bin2hex(random_bytes(4));
        foreach (["SELECT 1;\n\\! touch {$marker}\n", "SELECT 1;\nsystem touch {$marker}\n", "  \\. /etc/passwd\n"] as $sql) {
            $f = tempnam(sys_get_temp_dir(), 'dump');
            file_put_contents($f, $sql);
            $refused = false;
            try {
                $refuse->invoke($b, $f);
            } catch (\RuntimeException $e) {
                $refused = str_contains($e->getMessage(), 'client commands');
            }
            unlink($f);
            Assert::true($refused, 'refused: ' . trim($sql));
        }
        // An ordinary dump (comments, SET, INSERT with backslashes in strings) is fine.
        $f = tempnam(sys_get_temp_dir(), 'dump');
        file_put_contents($f, "/*M!999999\\- enable the sandbox mode */\n/*!40101 SET NAMES utf8mb4 */;\nINSERT INTO t VALUES ('a\\\\b','\\! not a command');\n");
        $refuse->invoke($b, $f);
        // A long row (a report's HTML over the 1 MB read size) is never mistaken for a command, wherever chunks split.
        $row = str_repeat('<p class=\\"x\\">use source system \\n\\! more</p>', 60000);
        file_put_contents($f, "INSERT INTO reports VALUES ('" . $row . "');\nINSERT INTO t VALUES (1);\n");
        $refuse->invoke($b, $f);
        // Even past the check, the client runs with --binary-mode (client commands off).
        $import = new ReflectionMethod($b, 'import');
        file_put_contents($f, "SELECT 1; \\! touch {$marker}\n");
        try {
            $import->invoke($b, $f);
        } catch (\RuntimeException) {
            // a syntax error is fine; running the shell is not
        }
        unlink($f);
        Assert::true(!file_exists($marker), 'no shell command ran');
        $local = (new ReflectionClassConstant($b, 'LOCAL_ONLY_CONFIG'))->getValue();
        Assert::true(in_array(['scanner', 'nmap_path'], $local, true) && in_array(['web_update', 'state_dir'], $local, true), 'programs and folders stay local');
    },
    'a backup can never run code or write through links' => function (TestContext $ctx) use ($dir): void {
        $d = $dir() . '-evil';
        array_map('unlink', glob($d . '/*') ?: []);
        @mkdir($d, 0700, true);
        $marker = sys_get_temp_dir() . '/sentinel-pwned-' . bin2hex(random_bytes(4));
        $root = dirname(__DIR__, 2);
        // A hand-made "backup" with PHP in the config and a storage file outside the manifest.
        $work = sys_get_temp_dir() . '/sentinel-evil-' . bin2hex(random_bytes(4));
        mkdir($work . '/storage', 0700, true);
        file_put_contents($work . '/database.sql', 'SELECT 1;');
        file_put_contents($work . '/config.json', '{"app_key":"x"}');
        file_put_contents($work . '/config.php', '<?php file_put_contents(' . var_export($marker, true) . ', "ran"); return [];');
        file_put_contents($work . '/storage/unlisted.txt', 'not in the manifest');
        $files = [];
        foreach (['database.sql', 'config.json', 'config.php'] as $f) {
            $files[$f] = hash_file('sha256', $work . '/' . $f);
        }
        file_put_contents($work . '/manifest.json', json_encode(['product' => 'msp-sentinel', 'version' => '1.0.0', 'files' => $files]));
        $phar = new PharData($d . '/msp-sentinel-backup-evil.tar');
        $phar->buildFromDirectory($work);
        $phar->compress(Phar::GZ);
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . $d . '/msp-sentinel-backup-evil.tar.gz']);
        Assert::true(!file_exists($marker), 'PHP inside a backup is never executed (dry run): ' . $out);
        Assert::contains("app key differs", $out);
        // Restoring storage writes only manifest-listed files, and never through a symlink already in storage/.
        $target = sys_get_temp_dir() . '/sentinel-link-target-' . bin2hex(random_bytes(4));
        @mkdir($root . '/storage', 02770, true);
        $link = $root . '/storage/evil-link-' . bin2hex(random_bytes(3));
        symlink($target, $link);
        $b = new \Sentinel\System\Backup(\Sentinel\Core\App::config(), $root, \Sentinel\Core\App::version());
        $refl = new ReflectionMethod($b, 'listFiles');
        Assert::true(!in_array(basename($link), $refl->invoke($b, $root . '/storage'), true), 'links never enter a backup');
        unlink($link);
        // A real restore with --with-storage: the listed file is written fresh; a symlink planted at its place is not followed.
        file_put_contents($work . '/storage/listed.txt', 'restored content');
        $files['storage/listed.txt'] = hash_file('sha256', $work . '/storage/listed.txt');
        file_put_contents($work . '/manifest.json', json_encode(['product' => 'msp-sentinel', 'version' => '1.0.0', 'files' => $files]));
        @unlink($d . '/msp-sentinel-backup-evil.tar.gz');
        $phar2 = new PharData($d . '/msp-sentinel-backup-evil2.tar');
        $phar2->buildFromDirectory($work);
        $phar2->compress(Phar::GZ);
        @unlink($root . '/storage/listed.txt');
        symlink($target, $root . '/storage/listed.txt');
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . $d . '/msp-sentinel-backup-evil2.tar.gz', '--yes', '--with-storage']);
        Assert::same(0, $code, $out);
        Assert::true(!file_exists($target), 'nothing written through the planted link');
        Assert::true(!is_link($root . '/storage/listed.txt') && file_get_contents($root . '/storage/listed.txt') === 'restored content', 'file written fresh');
        unlink($root . '/storage/listed.txt');
        Assert::true(!file_exists($marker), 'PHP inside a backup is never executed (restore)');
        Assert::true(!file_exists($root . '/storage/unlisted.txt'), 'unlisted file not restored');
        array_map('unlink', array_merge(glob($work . '/storage/*') ?: [], glob($work . '/*.*') ?: [], glob($d . '/*') ?: []));
        @rmdir($work . '/storage');
        @rmdir($work);
    },
    'restore brings the database back to the backup' => function (TestContext $ctx) use ($dir): void {
        $d = $dir() . '-restore';
        array_map('unlink', glob($d . '/*') ?: []);
        $ctx->cli('bin/backup.php', ['--dir=' . $d]);
        $before = (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn();
        $ctx->createUser('after-backup-' . bin2hex(random_bytes(2)), 'viewer', 'After-Backup-01!');
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . (glob($d . '/*.tar.gz') ?: [''])[0], '--yes']);
        Assert::same(0, $code, $out);
        Assert::contains('Restored.', $out);
        Assert::same($before, (int) $ctx->db->query('SELECT COUNT(*) FROM users')->fetchColumn(), 'user added after the backup is gone');
        Assert::same(200, $ctx->login('admin', 'Admin-Pass-0001!')->get('/')->status, 'the app works after restoring');
        // --with-config keeps this server's database settings and restores the rest.
        $before = require $ctx->configPath;
        $orig = (string) file_get_contents($ctx->configPath);
        [$code, $out] = $ctx->cli('bin/restore.php', ['--file=' . (glob($d . '/*.tar.gz') ?: [''])[0], '--yes', '--with-config']);
        Assert::same(0, $code, $out);
        clearstatcache();
        $after = (static fn (string $p): array => require $p)($ctx->configPath);
        Assert::same([$before['db'], $before['app_key']], [$after['db'], $after['app_key']]);
        Assert::same(1, count(glob($ctx->configPath . '.before-restore-*') ?: []), 'previous config kept');
        array_map('unlink', glob($ctx->configPath . '.before-restore-*') ?: []);
        file_put_contents($ctx->configPath, $orig);
        Assert::same(200, $ctx->login('admin', 'Admin-Pass-0001!')->get('/')->status, 'still works with the restored config');
        array_map('unlink', glob($d . '/*') ?: []);
    },
    'backup status: each run is recorded, shown on the System page and in the health check; failed or stale ones alert admins once a day' => function (TestContext $ctx) use ($dir): void {
        App::settings()->set('backup_history', '');
        $ctx->db->exec("DELETE FROM notifications WHERE kind = 'backup'");
        $health = static fn (): array => array_values(array_filter(App::health()->run(), static fn (array $c): bool => $c['key'] === 'backups'))[0];
        Assert::same('warn', $health()['status'], 'nothing recorded yet');
        $d = $dir();
        [$code, $out] = $ctx->cli('bin/backup.php', ['--dir=' . $d, '--keep=2']);
        Assert::same(0, $code, $out);
        $h = (new \Sentinel\System\BackupStatus(App::settings()))->history();
        Assert::true($h[0]['ok'] && $h[0]['bytes'] > 0 && !$h[0]['encrypted'] && str_starts_with($h[0]['file'], 'msp-sentinel-backup-'), 'recorded: ' . json_encode($h[0]));
        Assert::same('ok', $health()['status']);
        $page = $ctx->login('admin', 'Admin-Pass-0001!')->get('/admin/system')->body;
        Assert::contains('id="backups"', $page);
        Assert::contains(htmlspecialchars($h[0]['file']), $page);
        // A failed run (an unwritable folder): recorded with its error, the health check fails, admins are alerted once.
        [$code] = $ctx->cli('bin/backup.php', ['--dir=/proc/no-such-folder']);
        Assert::true($code !== 0, 'failed run');
        $status = new \Sentinel\System\BackupStatus(App::settings());
        Assert::same(false, $status->history()[0]['ok']);
        Assert::same('fail', $health()['status']);
        Assert::contains('failed', (string) $status->problem());
        $ctx->cli('bin/worker.php', ['--no-schedule']);
        $ctx->cli('bin/worker.php', ['--no-schedule']);
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM notifications n JOIN users u ON u.id = n.user_id WHERE n.kind = 'backup' AND u.username = 'admin'")->fetchColumn(), 'alerted once');
        // Stale: the last good backup is over 2 days old.
        $old = [['at' => gmdate('Y-m-d H:i:s', time() - 3 * 86400), 'ok' => true, 'file' => 'x.tar.gz', 'bytes' => 1, 'encrypted' => true, 'error' => '']];
        App::settings()->set('backup_history', json_encode($old));
        Assert::contains('No good backup in the last 48 hours', (string) (new \Sentinel\System\BackupStatus(App::settings()))->problem());
        App::settings()->set('backup_history', '');
    },
];
