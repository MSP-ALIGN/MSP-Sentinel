<?php

declare(strict_types=1);

/**
 * End-to-end tests for bin/backup.php and bin/restore.php: archive contents
 * and permissions, encryption (wrong passphrase and tampering refused),
 * dry run by default, and a real restore into the test database.
 */

use Sentinel\System\Backup;
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
        Assert::true(isset($phar['database.sql'], $phar['config.php'], $phar['manifest.json']), 'contents');
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
];
