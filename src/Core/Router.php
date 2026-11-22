<?php

declare(strict_types=1);

namespace Sentinel\Core;

use Sentinel\Auth\Role;

/**
 * Maps a method and path to a controller action and its access rules.
 *
 * Every route states who can reach it:
 * - 'auth' => 'public'  : anyone (login page, logout)
 * - 'auth' => 'pending' : password checked, second factor still needed
 * - 'auth' => 'user'    : fully signed-in user (the default)
 * - 'passive' => true    : background request (auto-refresh); does not reset the idle sign-out timer
 * - 'role' => minimum role for 'user' routes (default: viewer)
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
     * @param array<string,mixed>       $opts    Access rules: auth, role, allow_password_change.
     */
    public function add(string $method, string $pattern, array $handler, array $opts = []): void
    {
        $opts += ['auth' => 'user', 'role' => Role::VIEWER, 'allow_password_change' => false, 'passive' => false];
        if (!in_array($opts['auth'], ['public', 'pending', 'user'], true)) {
            throw new \InvalidArgumentException('Unknown auth level for route ' . $pattern);
        }
        if (!Role::isValid((string) $opts['role'])) {
            throw new \InvalidArgumentException('Unknown role for route ' . $pattern);
        }
        // Every {name} parameter (e.g. {id}, {device}) matches a positive whole number only.
        $regex = '#^' . preg_replace('/\\\\\{([a-z]{1,20})\\\\\}/', '(?P<$1>[1-9][0-9]{0,18})', preg_quote($pattern, '#')) . '$#';
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
}
