<?php

declare(strict_types=1);

namespace Sentinel\Auth;

use Sentinel\Core\App;

/**
 * Helpers for "Sign in with Microsoft" setup, shared by the Integrations page and EntraAppSetup (1.63, which replaced
 * the PowerShell setup script and its one-time codes).
 *
 * Security assumptions: no input; callers are an Admin's request (already authorized) or EntraAppSetup inside its save
 * transaction.
 */
final class SsoSetup
{
    /**
     * Forget every user's Microsoft link (another tenant means other accounts) and turn password sign-in back on for
     * them, signing them out, so nobody whose password sign-in was off is locked out (1.46.1). Returns how many.
     */
    public static function clearAllLinks(): int
    {
        return (int) App::db()->exec("UPDATE users SET sso_subject = NULL, sso_name = '', password_login = 1, session_version = session_version + 1,
                                      updated_at = UTC_TIMESTAMP() WHERE sso_subject IS NOT NULL");
    }

    /**
     * Days until the saved client secret expires (negative when it has), or null when the date is unknown (a secret
     * typed in by hand).
     */
    public static function secretDaysLeft(): ?int
    {
        $at = App::settings()->get('sso_entra_secret_expires');
        $ts = $at === '' ? false : strtotime($at . ' UTC');
        return $ts === false ? null : (int) floor(($ts - time()) / 86400);
    }
}
