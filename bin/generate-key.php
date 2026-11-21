<?php

declare(strict_types=1);

/**
 * CLI: print a new random app key for config/config.php ('app_key').
 *
 * Usage: php bin/generate-key.php
 *
 * Security assumptions: the key encrypts secrets at rest. Generate it once
 * per install, keep it only in the config file (and in your backups), and
 * never share it. If you lose it, encrypted secrets (such as 2FA seeds)
 * can't be read and users have to enrol 2FA again.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

fwrite(STDOUT, base64_encode(random_bytes(32)) . "\n");
