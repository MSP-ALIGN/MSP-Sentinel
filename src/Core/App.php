<?php

declare(strict_types=1);

namespace Sentinel\Core;

use PDO;
use Sentinel\Auth\Auth;
use Sentinel\Auth\RecoveryCodes;
use Sentinel\Auth\Role;
use Sentinel\Auth\UserRepository;
use Sentinel\Clients\ClientRepository;
use Sentinel\Scope\AuthorisationRepository;
use Sentinel\Scope\ScopeParser;
use Sentinel\Scope\ScopeService;

/**
 * Application container and HTTP kernel.
 *
 * Holds the shared services (config, database, auth...) and runs each web
 * request through one fixed pipeline:
 *
 *   security headers -> session -> route match -> CSRF check (all
 *   state-changing methods) -> authentication -> forced password change ->
 *   role check -> controller
 *
 * Security assumptions:
 * - Authentication, CSRF and role checks happen HERE, before any controller
 *   runs. A controller can add finer checks but can never skip these.
 * - Errors never show internal details. Unexpected exceptions are logged to
 *   the PHP error log and the user sees a generic 500 page.
 */
final class App
{
    private static ?Config $config = null;
    private static ?PDO $db = null;
    private static ?Translator $translator = null;
    private static ?Settings $settings = null;
    private static ?Auth $auth = null;
    private static ?Audit $audit = null;
    private static ?Crypto $crypto = null;
    private static ?string $version = null;

    /** Load configuration (and nothing else). Safe for CLI tools. */
    public static function boot(?Config $config = null): void
    {
        self::$config = $config ?? Config::load();
        self::$translator = Translator::load((string) self::$config->get('app.locale', 'en'));
        self::$db = null;
        self::$settings = null;
        self::$auth = null;
        self::$audit = null;
        self::$crypto = null;
    }

    /** The loaded configuration. Throws if boot() has not run. */
    public static function config(): Config
    {
        return self::$config ?? throw new \LogicException('App not booted.');
    }

    /** Lazily-opened database connection. */
    public static function db(): PDO
    {
        return self::$db ??= Database::connect(self::config());
    }

    /** Interface string translator. */
    public static function translator(): Translator
    {
        // Views may be rendered before boot (e.g. a fatal config error page), so fall back to English.
        return self::$translator ??= Translator::load('en');
    }

    /** Admin-editable settings (lazily created). */
    public static function settings(): Settings
    {
        return self::$settings ??= new Settings(self::db());
    }

    /** The audit logger. */
    public static function audit(): Audit
    {
        return self::$audit ??= new Audit(self::db());
    }

    /** Secret encryption with keys derived from the app key. */
    public static function crypto(): Crypto
    {
        return self::$crypto ??= new Crypto(self::config()->appKey());
    }

    /** The sign-in state machine (one per request). */
    public static function auth(): Auth
    {
        return self::$auth ??= new Auth(self::users(), self::limiter(), self::audit());
    }

    /** Failure counter used for throttling. */
    public static function limiter(): RateLimiter
    {
        return new RateLimiter(self::db());
    }

    /** User account repository. */
    public static function users(): UserRepository
    {
        return new UserRepository(self::db());
    }

    /** Client and site store. */
    public static function clients(): ClientRepository
    {
        return new ClientRepository(self::db());
    }

    /** Scan authorisation store. */
    public static function authorisations(): AuthorisationRepository
    {
        return new AuthorisationRepository(self::db());
    }

    /** The scope gatekeeper every scan must ask first. */
    public static function scope(): ScopeService
    {
        return new ScopeService(self::authorisations(), self::settings(), self::clients());
    }

    /**
     * Scope entry parser. Documentation ranges and example domains are only
     * accepted when the config sets testing.allow_documentation_ranges (test suite only).
     */
    public static function scopeParser(): ScopeParser
    {
        return new ScopeParser((bool) self::config()->get('testing.allow_documentation_ranges', false));
    }

    /** Recovery code store. */
    public static function recoveryCodes(): RecoveryCodes
    {
        return new RecoveryCodes(self::db(), self::crypto());
    }

    /** Configured URL base path ("" at the web root). Validated in Config. */
    public static function basePath(): string
    {
        return self::$config === null ? '' : (string) self::$config->get('app.base_path', '');
    }

    /** Release version from the VERSION file. */
    public static function version(): string
    {
        return self::$version ??= trim((string) @file_get_contents(SENTINEL_ROOT . '/VERSION')) ?: 'unknown';
    }

    /** Product name for the UI (white-label setting). Falls back to the default if the database is unavailable. */
    public static function productName(): string
    {
        try {
            return self::settings()->get('product_name');
        } catch (\Throwable) {
            return Settings::DEFAULTS['product_name'];
        }
    }

    /**
     * Handle one web request from start to finish.
     */
    public static function handleRequest(Router $router): Response
    {
        $config = self::config();
        $trusted = array_values(array_filter((array) $config->get('app.trusted_proxies', []), 'is_string'));
        $request = Request::fromGlobals(self::basePath(), $trusted);
        $behindProxy = in_array((string) ($_SERVER['REMOTE_ADDR'] ?? ''), $trusted, true);
        $secure = $request->isSecure($behindProxy);

        try {
            Session::start($secure || (bool) $config->get('app.force_secure_cookies', false), self::basePath());
            $response = self::dispatch($router, $request);
        } catch (HttpException $ex) {
            $response = self::errorResponse($ex->status, $ex->getMessage());
        } catch (\Throwable $ex) {
            // Log the details for the admin. Show the user nothing internal.
            error_log('[msp-sentinel] ' . get_class($ex) . ': ' . $ex->getMessage() . ' in ' . $ex->getFile() . ':' . $ex->getLine());
            $response = self::errorResponse(500, '');
        }
        return SecurityHeaders::apply($response, $secure);
    }

    /**
     * Route, check access and run the controller.
     *
     * @throws HttpException
     */
    private static function dispatch(Router $router, Request $request): Response
    {
        $route = $router->match($request->method, $request->path);
        $opts = $route['opts'];

        // CSRF: every state-changing request, on every route (public ones too, such as login).
        if (in_array($request->method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $token = $request->input(Csrf::FIELD) ?: $request->header('X-CSRF-Token');
            if (!Csrf::isValid($token)) {
                throw new HttpException(400, __('Your form expired or was sent from another site. Please go back, reload the page and try again.'));
            }
        }

        $auth = self::auth();
        if ($opts['auth'] === 'pending') {
            if ($auth->pendingUser() === null) {
                return Response::redirect('/login');
            }
        } elseif ($opts['auth'] === 'user') {
            $user = $auth->user();
            if ($user === null) {
                return Response::redirect('/login');
            }
            if ((int) $user['must_change_password'] === 1 && !$opts['allow_password_change']) {
                return Response::redirect('/profile/password');
            }
            if (!Role::atLeast((string) $user['role'], (string) $opts['role'])) {
                self::audit()->log('access.denied', (int) $user['id'], (string) $user['username'], null, null,
                    ['path' => mb_substr($request->path, 0, 200), 'required' => $opts['role']], $request->ip());
                throw new HttpException(403);
            }
        }

        [$class, $method] = $route['handler'];
        $controller = new $class();
        return $controller->$method($request, $route['params']);
    }

    /** A friendly error page. Uses the app layout only if the user is signed in. */
    public static function errorResponse(int $status, string $message): Response
    {
        $titles = [
            400 => __('Request could not be processed'),
            403 => __('Access denied'),
            404 => __('Page not found'),
            405 => __('Method not allowed'),
            500 => __('Something went wrong'),
        ];
        $defaults = [
            403 => __('Your role does not allow this page. Ask an admin if you need access.'),
            404 => __('The page you asked for does not exist.'),
            405 => __('This page does not accept that kind of request.'),
            500 => __('An unexpected error occurred. It has been logged for the administrator.'),
        ];
        $title = $titles[$status] ?? __('Error');
        $text = $message !== '' ? $message : ($defaults[$status] ?? '');
        try {
            $user = self::$config !== null && session_status() === PHP_SESSION_ACTIVE ? self::auth()->user() : null;
        } catch (\Throwable) {
            $user = null;
        }
        $layout = $user !== null ? 'app' : 'auth';
        $html = View::render('errors/error', [
            'title' => $title,
            'status' => $status,
            'message' => $text,
            'currentUser' => $user === null ? null : UserRepository::publicFields($user),
        ], $layout);
        return Response::html($html, $status);
    }
}
