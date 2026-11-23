<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Auth\UserRepository;
use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Core\View;

/**
 * Base class for controllers: rendering and current-user helpers.
 *
 * Security assumptions:
 * - By the time a controller method runs, the kernel has already checked
 *   authentication, CSRF and the route's minimum role.
 * - Views only ever get the user's public fields (no password hash or TOTP
 *   secret).
 */
abstract class Controller
{
    /**
     * Render a page in the main layout.
     *
     * @param array<string,mixed> $data
     */
    protected function page(string $template, string $title, array $data = [], int $status = 200): Response
    {
        $user = App::auth()->user();
        // Pages about one existing client (forms, device page, ...) keep that client's menu in the sidebar.
        $section = ['inventory/' => 'devices', 'authorisations/' => 'authorisations', 'agents/' => 'agents', 'clients/form' => 'overview'];
        if (!isset($data['clientNav']) && is_array($data['client'] ?? null) && isset($data['client']['id'], $data['client']['name'])) {
            foreach ($section as $prefix => $key) {
                if (str_starts_with($template, $prefix)) {
                    $data['clientNav'] = ClientController::nav($data['client'], $key, App::findings()->counts((int) $data['client']['id']));
                    break;
                }
            }
        }
        $html = View::render($template, $data + [
            'title' => $title,
            'currentUser' => $user === null ? null : UserRepository::publicFields($user),
            'flashes' => Session::takeFlashes(),
        ], 'app');
        return Response::html($html, $status);
    }

    /**
     * Render a page in the minimal sign-in layout.
     *
     * @param array<string,mixed> $data
     */
    protected function authPage(string $template, string $title, array $data = [], int $status = 200): Response
    {
        $html = View::render($template, $data + ['title' => $title, 'flashes' => Session::takeFlashes()], 'auth');
        return Response::html($html, $status);
    }

    /**
     * The signed-in user (guaranteed on 'user' routes).
     *
     * @return array<string,mixed>
     */
    protected function user(): array
    {
        return App::auth()->user() ?? throw new HttpException(403);
    }

    /** Log an action by the current user. */
    protected function audit(Request $request, string $action, ?string $targetType = null, ?int $targetId = null, array $details = []): void
    {
        $user = App::auth()->user();
        App::audit()->log($action, $user === null ? null : (int) $user['id'], $user === null ? null : (string) $user['username'],
            $targetType, $targetId, $details, $request->ip());
    }

    /**
     * Re-authenticate the signed-in user with their current password before a sensitive action (profile changes,
     * moving agents), with throttling (REAUTH_MAX_FAILS per REAUTH_WINDOW seconds, shared by every such form) and an
     * audit entry for each failure. $password is untrusted.
     *
     * @param array<string,mixed> $user the signed-in user's row (with password_hash)
     * @return string|null Error message, or null when the password is right.
     */
    protected function checkCurrentPassword(Request $request, array $user, string $password): ?string
    {
        $bucket = 'reauth-user:' . (int) $user['id'];
        $limiter = App::limiter();
        if ($limiter->tooMany($bucket, self::REAUTH_MAX_FAILS, self::REAUTH_WINDOW)) {
            return __('Too many failed attempts. Please wait 15 minutes and try again.');
        }
        if ($password === '' || !\Sentinel\Auth\Passwords::verify($password, (string) ($user['password_hash'] ?? ''))) {
            $limiter->hit($bucket);
            $this->audit($request, 'auth.reauth_failed', 'user', (int) $user['id']);
            return __('Your current password is not correct.');
        }
        $limiter->clear($bucket);
        return null;
    }

    /** Failed password re-checks allowed per window, and the window (seconds). */
    protected const REAUTH_MAX_FAILS = 5;
    protected const REAUTH_WINDOW = 900;
}
