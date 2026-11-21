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
}
