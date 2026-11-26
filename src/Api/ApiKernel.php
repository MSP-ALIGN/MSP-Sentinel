<?php

declare(strict_types=1);

namespace Sentinel\Api;

use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;

/**
 * Handles every request under /api/: token check, routing, JSON errors.
 *
 * It never starts a session or reads cookies, so a browser can't be tricked
 * into making API calls with someone's login (no CSRF exposure); calls must
 * carry "Authorization: Bearer <token>". No CORS headers are sent, so other
 * web sites can't read responses either.
 *
 * Security assumptions:
 * - Every route requires a valid token (TokenService::authenticate) and
 *   declares its permission: read (all tokens), triage or scan (opt-in per token).
 * - Client limits are enforced in ApiController on every query.
 * - Errors never include internal details; unexpected ones are logged.
 */
final class ApiKernel
{
    /** method, path regex, handler method, permission. */
    private const ROUTES = [
        ['GET', '#^/api/v1/openapi\.json$#', 'openapi', 'read'],
        ['GET', '#^/api/v1/me$#', 'me', 'read'],
        ['GET', '#^/api/v1/clients$#', 'clients', 'read'],
        ['GET', '#^/api/v1/clients/(?P<id>[1-9][0-9]{0,9})$#', 'client', 'read'],
        ['GET', '#^/api/v1/clients/(?P<id>[1-9][0-9]{0,9})/summary$#', 'summary', 'read'],
        ['GET', '#^/api/v1/clients/(?P<id>[1-9][0-9]{0,9})/score-history$#', 'scoreHistory', 'read'],
        ['POST', '#^/api/v1/clients/(?P<id>[1-9][0-9]{0,9})/scans$#', 'queueScan', 'scan'],
        ['GET', '#^/api/v1/assets$#', 'assets', 'read'],
        ['GET', '#^/api/v1/findings$#', 'findings', 'read'],
        ['GET', '#^/api/v1/findings/(?P<id>[1-9][0-9]{0,9})$#', 'finding', 'read'],
        ['POST', '#^/api/v1/findings/(?P<id>[1-9][0-9]{0,9})/triage$#', 'triage', 'triage'],
        ['GET', '#^/api/v1/scans$#', 'scans', 'read'],
        ['GET', '#^/api/v1/scans/(?P<id>[1-9][0-9]{0,9})$#', 'scan', 'read'],
        ['GET', '#^/api/v1/reports$#', 'reports', 'read'],
        ['GET', '#^/api/v1/reports/(?P<id>[1-9][0-9]{0,9})$#', 'report', 'read'],
        ['GET', '#^/api/v1/reports/(?P<id>[1-9][0-9]{0,9})/html$#', 'reportHtml', 'read'],
        ['GET', '#^/api/v1/reports/(?P<id>[1-9][0-9]{0,9})/csv$#', 'reportCsv', 'read'],
    ];

    /** Handle one API request. */
    public static function handle(Request $request): Response
    {
        try {
            $route = null;
            $pathMatched = false;
            foreach (self::ROUTES as [$method, $regex, $handler, $permission]) {
                if (preg_match($regex, $request->path, $m)) {
                    $pathMatched = true;
                    if ($method === $request->method) {
                        $route = [$handler, $permission, array_filter($m, 'is_string', ARRAY_FILTER_USE_KEY)];
                        break;
                    }
                }
            }
            if ($route === null) {
                return self::error($pathMatched ? 405 : 404, $pathMatched ? 'Method not allowed.' : 'Not found.');
            }
            $token = App::apiTokens()->authenticate($request->header('Authorization'), $request->ip());
            if (isset($token['error'])) {
                $res = self::error($token['error'][0], $token['error'][1]);
                return $token['error'][0] === 401 ? $res->header('WWW-Authenticate', 'Bearer') : $res;
            }
            [$handler, $permission, $params] = $route;
            if ($permission === 'triage' && (int) $token['can_triage'] !== 1 || $permission === 'scan' && (int) $token['can_scan'] !== 1) {
                return self::error(403, 'This token does not have the "' . $permission . '" permission.');
            }
            return (new ApiController($token, $request))->$handler($params);
        } catch (ApiError $ex) {
            return self::error($ex->status, $ex->getMessage());
        } catch (\Throwable $ex) {
            error_log('[msp-sentinel] API ' . get_class($ex) . ': ' . $ex->getMessage() . ' in ' . $ex->getFile() . ':' . $ex->getLine());
            return self::error(500, 'Internal error. It has been logged for the administrator.');
        }
    }

    /** A JSON response with the API's headers. */
    public static function json(mixed $data, int $status = 200): Response
    {
        return (new Response((string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRETTY_PRINT), $status))
            ->header('Content-Type', 'application/json; charset=UTF-8')
            ->header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; sandbox");
    }

    /** A JSON error. */
    public static function error(int $status, string $message): Response
    {
        return self::json(['error' => ['status' => $status, 'message' => $message]], $status);
    }
}
