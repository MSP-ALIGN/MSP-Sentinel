<?php

declare(strict_types=1);

/**
 * Migration 0063 (1.63): "Connect to Microsoft 365" replaces the PowerShell setup script and its one-time codes, so the
 * settings that held a pending code (sso_setup_code, sso_setup_expires, sso_setup_by, sso_setup_new_tenant) are
 * removed. The saved app details (tenant, client, secret) are kept.
 *
 * Idempotent: deleting rows that are already gone changes nothing. Safe to run twice.
 */

use Sentinel\Migrations\Migrator;

return [
    'description' => 'Remove the old Sign in with Microsoft setup-code settings',
    'up' => static function (PDO $db, Migrator $m): void {
        $db->exec("DELETE FROM settings WHERE name IN ('sso_setup_code', 'sso_setup_expires', 'sso_setup_by', 'sso_setup_new_tenant')");
    },
];
