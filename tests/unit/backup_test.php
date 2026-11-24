<?php

declare(strict_types=1);

/**
 * Unit tests for backup encryption: round trip, wrong passphrase, tampering, truncation.
 */

use Sentinel\System\Backup;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'backup encryption round-trips and detects any change' => function (TestContext $ctx): void {
        $dir = sys_get_temp_dir() . '/sentinel-enc-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $plain = random_bytes(200000) . 'END';
        file_put_contents($dir . '/in', $plain);
        Backup::encryptFile($dir . '/in', $dir . '/enc', 'a long test passphrase');
        Backup::decryptFile($dir . '/enc', $dir . '/out', 'a long test passphrase');
        Assert::same(hash('sha256', $plain), hash_file('sha256', $dir . '/out'));
        foreach (['wrong' => static fn (string $s): string => $s, 'flip' => static function (string $s): string { $s[100] = chr(ord($s[100]) ^ 1); return $s; },
                  'cut' => static fn (string $s): string => substr($s, 0, 70000)] as $case => $mutate) {
            file_put_contents($dir . '/bad', $mutate((string) file_get_contents($dir . '/enc')));
            try {
                Backup::decryptFile($dir . '/bad', $dir . '/out2', $case === 'wrong' ? 'not the passphrase' : 'a long test passphrase');
                Assert::true(false, 'should fail: ' . $case);
            } catch (RuntimeException) {
                Assert::true(!is_file($dir . '/out2') || $case === 'cut' && filesize($dir . '/out2') === 0 || !is_file($dir . '/out2'), 'no partial output kept: ' . $case);
            }
        }
        array_map('unlink', glob($dir . '/*') ?: []);
        rmdir($dir);
    },
];
