<?php

declare(strict_types=1);

/**
 * End-to-end tests for bound secrets (1.34 audit): migration 0042 rewrites old v1 secrets as v2 values bound to their
 * setting or user; a value moved to another setting no longer decrypts; running the migration twice changes nothing.
 * Made-up values only.
 */

use Sentinel\Core\App;
use Sentinel\Migrations\Migrator;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'old secrets are upgraded to bound values, and a moved value is refused' => function (TestContext $ctx): void {
        $crypto = App::crypto();
        $old = ['smtp_password' => 'Relay-Example-1', 'itflow_api_key' => 'itflow-example-key-0001'];
        foreach ($old as $name => $plain) {
            App::settings()->set($name, $crypto->encrypt($plain)); // as stored before 1.34
        }
        $ctx->createUser('secretsuser', 'viewer', 'Secrets-Pass-0001!');
        $uid = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'secretsuser'")->fetchColumn();
        $ctx->db->exec("UPDATE users SET totp_secret_enc = " . $ctx->db->quote($crypto->encrypt('JBSWY3DPEHPK3PXP')) . " WHERE id = {$uid}");
        Assert::same('', App::settings()->getSecret('smtp_password'), 'an unbound v1 value is no longer read as a setting');

        $migration = require dirname(__DIR__, 2) . '/migrations/0042_bound_secrets.php';
        $m = new Migrator($ctx->db, dirname(__DIR__, 2) . '/migrations');
        $migration['up']($ctx->db, $m);
        foreach ($old as $name => $plain) {
            Assert::same($plain, App::settings()->getSecret($name), $name . ' readable after the upgrade');
            Assert::true(str_starts_with(App::settings()->fresh($name), 'v2:'), $name . ' stored as v2');
        }
        $totp = (string) $ctx->db->query("SELECT totp_secret_enc FROM users WHERE id = {$uid}")->fetchColumn();
        Assert::same('JBSWY3DPEHPK3PXP', $crypto->decryptFor('totp:' . $uid, $totp), 'TOTP seed bound to its user');

        $before = App::settings()->fresh('smtp_password');
        $migration['up']($ctx->db, $m);
        Assert::same($before, App::settings()->fresh('smtp_password'), 'running twice changes nothing');

        // Someone with database access copies the ITFlow key's value into the SMTP password: it doesn't decrypt.
        App::settings()->set('smtp_password', App::settings()->fresh('itflow_api_key'));
        Assert::same('', App::settings()->getSecret('smtp_password'), 'a value moved to another setting is refused');
        App::settings()->setSecret('smtp_password', '');
        App::settings()->setSecret('itflow_api_key', '');
        $ctx->db->exec("DELETE FROM users WHERE id = {$uid}");
    },
];
