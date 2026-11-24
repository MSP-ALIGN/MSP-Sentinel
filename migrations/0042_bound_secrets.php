<?php

declare(strict_types=1);

/**
 * Migration 0042 (1.34): stored secrets are bound to their place.
 *
 * Every encrypted setting (Settings::SECRETS) and every user's TOTP seed is rewritten from the old "v1:" format to
 * "v2:" (Crypto::encryptFor), whose associated data names the setting or the user ("setting:smtp_password",
 * "totp:7"). After this, a value copied into another setting or another user's row, or an old value of a different
 * setting put back by someone with database access, no longer decrypts.
 *
 * Untrusted: nothing new (values come from Sentinel's own database). Security assumptions: needs the app key (config);
 * a value that can't be decrypted (another key) is left untouched, as it was already unreadable.
 *
 * Idempotent: only values still starting with "v1:" are rewritten; v2 values are skipped. Safe to run twice.
 */

use Sentinel\Core\App;
use Sentinel\Core\Settings;
use Sentinel\Migrations\Migrator;

return [
    'description' => 'Bind encrypted secrets to their setting or user',
    'up' => static function (PDO $db, Migrator $m): void {
        try {
            $crypto = App::crypto();
        } catch (\Throwable) {
            return; // no app key in this context: nothing can be decrypted, so nothing to upgrade
        }
        $names = implode(',', array_map(static fn (string $n): string => $db->quote($n), Settings::SECRETS));
        $upd = $db->prepare('UPDATE settings SET value = :v WHERE name = :n AND value = :old');
        foreach ($db->query("SELECT name, value FROM settings WHERE name IN ({$names}) AND value LIKE 'v1:%'")->fetchAll() as $row) {
            try {
                $plain = $crypto->decrypt((string) $row['value']);
            } catch (\RuntimeException) {
                continue;
            }
            $upd->execute(['v' => $crypto->encryptFor('setting:' . $row['name'], $plain), 'n' => $row['name'], 'old' => $row['value']]);
        }
        $updUser = $db->prepare('UPDATE users SET totp_secret_enc = :v WHERE id = :id AND totp_secret_enc = :old');
        foreach ($db->query("SELECT id, totp_secret_enc FROM users WHERE totp_secret_enc LIKE 'v1:%'")->fetchAll() as $row) {
            try {
                $plain = $crypto->decrypt((string) $row['totp_secret_enc']);
            } catch (\RuntimeException) {
                continue;
            }
            $updUser->execute(['v' => $crypto->encryptFor('totp:' . (int) $row['id'], $plain), 'id' => $row['id'], 'old' => $row['totp_secret_enc']]);
        }
    },
];
