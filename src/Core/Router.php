<?php

declare(strict_types=1);

namespace Sentinel\Core;

use Sentinel\Auth\Permissions;

/**
 * Maps a method and path to a controller action and its access rules.
 *
 * Every route states who can reach it:
 * - 'auth' => 'public'  : anyone (login page, logout)
 * - 'auth' => 'pending' : password checked, second factor still needed
 * - 'auth' => 'user'    : fully signed-in user (the default)
 * - 'passive' => true    : background request (auto-refresh); does not reset the idle sign-out timer
 * - 'perm' => the permission a 'user' route needs, or a list of which any one will do (default: none, any
 *   signed-in user). Names come from Sentinel\Auth\Permissions (1.40; replaces the old minimum role).
 * - 'client' => the kind of record {id} names (Sentinel\Auth\ClientAccess::RECORDS, e.g. 'finding'): the kernel looks
 *   up its client and answers 404 to a user who doesn't see that client (1.41). Routes under /clients/{id} are
 *   checked by their client ID without it.
 * - 'all_clients' => true: an org-wide page or action (the kill switch for every client, settings, integrations,
 *   the system, the audit log): only for users who see every client (1.42.1).
 *
 * Security assumptions:
 * - The default is the most restrictive useful option: signed in plus 2FA.
 *   A route has to opt out explicitly to be public.
 * - Path parameters only match digits ({id}, {device}, ...), so
 *   controllers receive pre-validated IDs. They still check the ID exists.
 */
final class Router
{
    /** @var list<array{method:string,regex:string,handler:array{class-string,string},opts:array<string,mixed>}> */
    private array $routes = [];

    /**
     * Register a route.
     *
     * @param string                    $method  HTTP method (GET or POST).
     * @param string                    $pattern Path like "/users/{id}". Every {name} parameter matches digits only.
     * @param array{class-string,string} $handler [ControllerClass, method].
     * @param array<string,mixed>       $opts    Access rules: auth, perm, allow_password_change, passive.
     */
    public function add(string $method, string $pattern, array $handler, array $opts = []): void
    {
        $opts += ['auth' => 'user', 'perm' => [], 'allow_password_change' => false, 'passive' => false, 'client' => null, 'all_clients' => false];
        if ($opts['client'] !== null && !isset(\Sentinel\Auth\ClientAccess::RECORDS[$opts['client']])) {
            throw new \InvalidArgumentException('Unknown record kind for route ' . $pattern);
        }
        if (!in_array($opts['auth'], ['public', 'pending', 'user'], true)) {
            throw new \InvalidArgumentException('Unknown auth level for route ' . $pattern);
        }
        if (isset($opts['role'])) {
            throw new \InvalidArgumentException('Routes take a permission (perm), not a role: ' . $pattern);
        }
        foreach ((array) $opts['perm'] as $p) {
            if (!is_string($p) || !Permissions::isValid($p)) {
                throw new \InvalidArgumentException('Unknown permission for route ' . $pattern);
            }
        }
        // Every {name} parameter (e.g. {id}, {device}) matches a positive whole number only.
        $regex = '#^' . preg_replace('/\\\\\{([a-z]{1,20})\\\\\}/', '(?P<$1>[1-9][0-9]{0,18})', preg_quote($pattern, '#')) . '$#';
        // A parameter name the pattern above doesn't accept, or a repeated name, would make the route silently unreachable.
        if (str_contains($regex, '\\{') || @preg_match($regex, '') === false) {
            throw new \InvalidArgumentException('Invalid route pattern: ' . $pattern);
        }
        $opts['client_path'] = str_starts_with($pattern, '/clients/{id}'); // the client's own pages (1.41)
        $this->routes[] = ['method' => strtoupper($method), 'regex' => $regex, 'handler' => $handler, 'opts' => $opts];
    }

    /**
     * Find the route for a request.
     *
     * @return array{handler:array{class-string,string},opts:array<string,mixed>,params:array<string,string>}
     * @throws HttpException 404 when no path matches, 405 when the path matches but the method doesn't.
     */
    public function match(string $method, string $path): array
    {
        $pathMatched = false;
        foreach ($this->routes as $route) {
            if (!preg_match($route['regex'], $path, $m)) {
                continue;
            }
            $pathMatched = true;
            if ($route['method'] !== $method) {
                continue;
            }
            $params = array_filter($m, 'is_string', ARRAY_FILTER_USE_KEY);
            return ['handler' => $route['handler'], 'opts' => $route['opts'], 'params' => $params];
        }
        throw new HttpException($pathMatched ? 405 : 404);
    }

    /**
     * For a GET on an address that only takes form posts (/clients/7/sites, /admin/alerts), the nearest page above it
     * that can be opened (/clients/7, /admin), or '/' (1.34: a bookmarked or typed form address used to show
     * "Method not allowed"). Only paths of known routes are returned, so the redirect stays inside Sentinel.
     */
    public function formPage(string $path): string
    {
        $parts = explode('/', trim($path, '/'));
        while (count($parts) > 1) {
            array_pop($parts);
            $candidate = '/' . implode('/', $parts);
            foreach ($this->routes as $route) {
                if ($route['method'] === 'GET' && preg_match($route['regex'], $candidate) === 1) {
                    return $candidate;
                }
            }
        }
        return '/';
    }
}
