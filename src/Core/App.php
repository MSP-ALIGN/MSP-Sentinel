<?php

declare(strict_types=1);

namespace Sentinel\Core;

use PDO;
use Sentinel\Alerts\AlertService;
use Sentinel\Api\EventPublisher;
use Sentinel\Api\TokenService;
use Sentinel\Alerts\Outbox;
use Sentinel\Alerts\WebhookSender;
use Sentinel\Auth\Auth;
use Sentinel\Auth\RecoveryCodes;
use Sentinel\Auth\Role;
use Sentinel\Auth\UserRepository;
use Sentinel\Clients\ClientRepository;
use Sentinel\System\HealthCheck;
use Sentinel\System\Housekeeping;
use Sentinel\System\Retention;
use Sentinel\System\UpdateChecker;
use Sentinel\Reports\Branding;
use Sentinel\Reports\ReportBuilder;
use Sentinel\Reports\ReportRenderer;
use Sentinel\Reports\ReportRepository;
use Sentinel\Reports\ReportService;
use Sentinel\Reports\StatsRecorder;
use Sentinel\Discovery\CrtShClient;
use Sentinel\Findings\FindingRepository;
use Sentinel\Findings\FindingsEngine;
use Sentinel\Discovery\DiscoveryService;
use Sentinel\Discovery\DnsClient;
use Sentinel\Discovery\SuggestionRepository;
use Sentinel\Scanning\Connector;
use Sentinel\Scanning\EndpointRepository;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Scanning\NmapRunner;
use Sentinel\Scanning\TlsChecker;
use Sentinel\Scanning\ScanRepository;
use Sentinel\Scanning\ScanWorker;
use Sentinel\Scope\AuthorisationRepository;
use Sentinel\Vulns\FeedUpdater;
use Sentinel\Vulns\VulnMatcher;
use Sentinel\Vulns\VulnRepository;
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
    /** @var array{branch:string,commit:string,sha:string,repo:string}|false|null */
    private static array|false|null $build = null;

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
        return self::$settings ??= new Settings(self::db(), self::crypto());
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

    /** Target suggestion and discovery-run store. */
    public static function suggestions(): SuggestionRepository
    {
        return new SuggestionRepository(self::db());
    }

    /**
     * Passive discovery, wired from config: dns.resolver/port/timeout, crtsh.*,
     * discovery.crtsh_delay. Throws DnsException if no resolver can be found.
     */
    public static function discovery(): DiscoveryService
    {
        $config = self::config();
        return new DiscoveryService(
            self::db(), self::clients(), self::authorisations(), self::suggestions(), self::scope(), self::scopeParser(),
            DnsClient::fromConfig($config), CrtShClient::fromConfig($config), (float) $config->get('discovery.crtsh_delay', 1.0),
        );
    }

    /** Scan job, scan log, asset and service store. */
    public static function scans(): ScanRepository
    {
        return new ScanRepository(self::db());
    }

    /**
     * The scan worker, wired from config (scanner.nmap_path, dns.*).
     *
     * @param callable(string):void|null $log
     */
    public static function scanWorker(?callable $log = null): ScanWorker
    {
        $config = self::config();
        try {
            $dns = DnsClient::fromConfig($config);
        } catch (\RuntimeException) {
            $dns = null; // without a resolver, only listed IP addresses are scanned
        }
        $connector = Connector::fromConfig($config);
        $caFile = (string) $config->get('tls.ca_file', '');
        return new ScanWorker(self::db(), self::clients(), self::authorisations(), self::scans(), self::scope(), NmapRunner::fromConfig($config), $dns, $log,
            new TlsChecker($connector, $caFile === '' ? null : $caFile), new HttpProbe($connector), self::endpoints(), self::vulnMatcher(15), self::findingsEngine(), self::alerts(), self::outbox(), self::reportService(), new StatsRecorder(self::db()), self::events(), self::housekeeping(),
            new \Sentinel\Web\WebsiteChecker(new HttpProbe($connector)), new \Sentinel\Web\WebsiteRepository(self::db()), $dns === null ? null : new \Sentinel\Web\EmailChecker($dns), self::fixWorkflow(),
            self::inventorySources() === [] ? null : self::inventorySync(), self::agentService());
    }

    /** Vulnerability data and match store. */
    public static function vulns(): VulnRepository
    {
        return new VulnRepository(self::db());
    }

    /** Threat feed updater (NVD, KEV, EPSS), wired from config. */
    public static function feedUpdater(): FeedUpdater
    {
        return FeedUpdater::fromConfig(self::config(), self::vulns());
    }

    /**
     * Service-to-CVE matcher (may fetch missing NVD answers within a budget).
     *
     * @param int $timeout Per-request NVD timeout (the scan worker uses a short one).
     */
    public static function vulnMatcher(int $timeout = 60): VulnMatcher
    {
        return new VulnMatcher(self::db(), self::vulns(), FeedUpdater::fromConfig(self::config(), self::vulns(), $timeout));
    }

    /** Alert creation (in-app notifications, queued emails and webhooks). */
    public static function alerts(): AlertService
    {
        return new AlertService(self::db(), self::settings(), rtrim((string) self::config()->get('app.public_url', ''), '/'), self::events());
    }

    /** Sends queued emails and webhook posts. */
    public static function outbox(): Outbox
    {
        $caFile = (string) self::config()->get('tls.ca_file', '');
        return new Outbox(self::db(), self::settings(), $caFile === '' ? null : $caFile,
            new WebhookSender(self::webhookTestMode()));
    }

    /**
     * True only inside the test suite: webhooks may then go to http://127.0.0.1.
     * Needs BOTH the config flag and the SENTINEL_TEST_MODE=1 environment
     * variable (set only by tests/run.php), so a config change alone can't
     * open loopback services to webhook requests in production.
     */
    public static function webhookTestMode(): bool
    {
        return self::config()->get('testing.allow_documentation_ranges', false) === true && getenv('SENTINEL_TEST_MODE') === '1';
    }

    /** Daily update check (config updates.url). */
    public static function updates(): UpdateChecker
    {
        return new UpdateChecker(self::settings(), (string) self::config()->get('updates.url', UpdateChecker::DEFAULT_URL), self::version(), self::webhookTestMode(),
            self::build(), (string) self::config()->get('updates.compare_url', UpdateChecker::DEFAULT_COMPARE_URL));
    }

    /** Data retention (admin settings). */
    /** "Update now" requests and the root-owned runner's status (see WebUpdate). */
    public static function webUpdate(): \Sentinel\System\WebUpdate
    {
        return new \Sentinel\System\WebUpdate((string) self::config()->get('web_update.state_dir', '/var/lib/msp-sentinel-update'), SENTINEL_ROOT . '/storage/update-request');
    }

    public static function retention(): Retention
    {
        return new Retention(self::db(), self::settings(), self::audit());
    }

    /** Heartbeat, update check and retention, run by the worker. */
    public static function housekeeping(): Housekeeping
    {
        return new Housekeeping(self::settings(), self::updates(), self::retention(), static fn (): ?string => self::itflowSync()->syncIfDue(),
            static fn (): ?string => self::itflowTickets()->runIfDue());
    }

    /** Install health checks (bin/doctor.php, admin System page). */
    public static function health(): HealthCheck
    {
        return new HealthCheck(self::db(), self::config(), self::settings(), SENTINEL_ROOT, self::updates());
    }

    /** Dashboard numbers (main dashboard and client overviews). */
    public static function dashboard(): \Sentinel\Dashboard\DashboardData
    {
        return new \Sentinel\Dashboard\DashboardData(self::db(), self::settings());
    }

    /** Outbound events (event webhook). */
    public static function events(): EventPublisher
    {
        return new EventPublisher(self::db(), self::settings());
    }

    /** API tokens. */
    public static function apiTokens(): TokenService
    {
        return new TokenService(self::db(), self::crypto(), self::limiter());
    }

    /** Stored reports. */
    public static function reports(): ReportRepository
    {
        return new ReportRepository(self::db());
    }

    /** Creates reports and runs the monthly schedule. */
    public static function reportService(): ReportService
    {
        $builder = new ReportBuilder(self::db(), self::settings(), self::authorisations(), SENTINEL_ROOT . '/storage/branding', self::version());
        return new ReportService(self::db(), $builder, new ReportRenderer(SENTINEL_ROOT . '/views/reports'), self::reports(), self::alerts(), self::events());
    }

    /** Report logo storage. */
    public static function branding(): Branding
    {
        return new Branding(SENTINEL_ROOT . '/storage/branding');
    }

    /** Findings store (list, history, triage). */
    public static function findings(): FindingRepository
    {
        return new FindingRepository(self::db());
    }

    /** Builds findings from the current scan data. */
    public static function findingsEngine(): FindingsEngine
    {
        return new FindingsEngine(self::db(), self::endpoints(), self::vulns(), new \Sentinel\Web\WebsiteRepository(self::db()), self::fixWorkflow(), self::inventory());
    }

    /**
     * Configured inventory sources by name. The fixture source exists only in the test suite (config flag AND
     * SENTINEL_TEST_MODE=1, like webhookTestMode()). The NinjaOne connector is added here when it is configured.
     *
     * @return array<string,\Sentinel\Inventory\InventorySource>
     */
    public static function inventorySources(): array
    {
        $sources = [];
        $fixture = (string) self::config()->get('testing.inventory_fixture', '');
        if ($fixture !== '' && self::webhookTestMode()) {
            $sources['ninjaone'] = new \Sentinel\Inventory\FixtureSource($fixture);
            return $sources;
        }
        $ninja = self::ninjaOne();
        if ($ninja !== null && self::settings()->get('ninjaone_enabled') === '1') {
            $sources['ninjaone'] = $ninja;
        }
        return $sources;
    }

    /**
     * The NinjaOne connector from Administration > Integrations, or null while it isn't filled in.
     * The test suite may point it at a local mock (config testing.ninjaone_base_url, test mode only).
     */
    public static function ninjaOne(): ?\Sentinel\Inventory\NinjaOneSource
    {
        $s = self::settings();
        $host = $s->get('ninjaone_host');
        $id = $s->get('ninjaone_client_id');
        $secret = $s->getSecret('ninjaone_client_secret');
        if ($host === '' || $id === '' || $secret === '') {
            return null;
        }
        $base = self::webhookTestMode() ? (string) self::config()->get('testing.ninjaone_base_url', '') : '';
        return new \Sentinel\Inventory\NinjaOneSource($host, $id, $secret, $base);
    }

    /**
     * The MSP Align reader from Administration > Integrations, or null while it is off or not filled in.
     * Plain http is accepted only in the test suite.
     */
    public static function align(bool $evenIfOff = false): ?\Sentinel\Compliance\AlignClient
    {
        $s = self::settings();
        $url = $s->fresh('mspalign_url');
        $key = $s->getSecret('mspalign_api_key');
        if ($url === '' || $key === '' || (!$evenIfOff && $s->fresh('mspalign_enabled') !== '1')) {
            return null;
        }
        return new \Sentinel\Compliance\AlignClient($url, $key, self::webhookTestMode());
    }

    /** The ITFlow API client from Administration > Integrations, or null while it isn't filled in. */
    public static function itflow(): ?\Sentinel\Itflow\ItflowClient
    {
        $s = self::settings();
        $url = $s->fresh('itflow_url'); // fresh: a long-running process sees a changed address at once
        $key = $s->getSecret('itflow_api_key');
        return $url === '' || $key === '' ? null : new \Sentinel\Itflow\ItflowClient($url, $key, self::webhookTestMode());
    }

    /** ITFlow client sync (worker every 15 minutes, and "Sync now"). */
    public static function itflowSync(): \Sentinel\Itflow\ItflowSync
    {
        return new \Sentinel\Itflow\ItflowSync(self::db(), self::settings(), self::audit(), self::itflow(), self::align());
    }

    /** ITFlow tickets from findings (worker every 5 minutes, and "Open tickets now"). */
    public static function itflowTickets(): \Sentinel\Itflow\ItflowTickets
    {
        return new \Sentinel\Itflow\ItflowTickets(self::db(), self::settings(), self::audit(), self::itflow(), (string) self::config()->get('app.public_url', ''));
    }

    /** Inventory sync service (worker and "Sync now"). */
    public static function inventorySync(): \Sentinel\Inventory\InventorySync
    {
        return new \Sentinel\Inventory\InventorySync(self::db(), self::inventory(), self::inventorySources(), self::vulnMatcher(15), self::findingsEngine(), self::alerts());
    }

    /** Signs internal authorisations and agent jobs (key derived from the config file's app key). */
    public static function agentSigner(): \Sentinel\Agent\Signer
    {
        return \Sentinel\Agent\Signer::fromAppKey(self::config()->appKey());
    }

    /** Agents, enrolment codes, internal authorisations and agent jobs. */
    public static function agents(): \Sentinel\Agent\AgentRepository
    {
        return new \Sentinel\Agent\AgentRepository(self::db(), self::crypto(), self::agentSigner());
    }

    /**
     * The agent move an admin set (Administration, System): url, ca, requested_at; url '' when none. Stored encrypted and
     * authenticated with the app key (config file), so a database write alone can't produce one.
     *
     * @return array{url:string, ca:string, requested_at:string, id:string, complete:bool} id: this move's own identifier;
     *         complete: no more move instructions, but moved agents keep the address
     */
    public static function agentMove(): array
    {
        $m = json_decode(self::settings()->getSecret('agent_move'), true);
        return is_array($m) && is_string($m['url'] ?? null) && is_string($m['ca'] ?? null) && is_string($m['requested_at'] ?? null) && is_string($m['id'] ?? null)
            ? ['url' => $m['url'], 'ca' => $m['ca'], 'requested_at' => $m['requested_at'], 'id' => $m['id'], 'complete' => ($m['complete'] ?? false) === true]
            : ['url' => '', 'ca' => '', 'requested_at' => '', 'id' => '', 'complete' => false];
    }

    /**
     * The agent release key made on the System page (one secret setting, authenticated with the app key: a database write
     * alone can't change it; if it doesn't decrypt, there is no key from the System page, and AgentRelease falls back to
     * install/release-key.pub in the code tree when a maintainer key ships there). chain: the rotations, oldest first, each a statement
     * naming the next key and signed by the key before it; an agent holding any key of the chain can follow it to the
     * current key. A chain that doesn't end at the current key, or doesn't link up, is dropped.
     *
     * @return array{key:string, created_at:string, chain:list<array{statement:string, signature:string, old_key:string, new_key:string}>}
     */
    public static function releaseKey(): array
    {
        $none = ['key' => '', 'created_at' => '', 'chain' => []];
        $r = json_decode(self::settings()->getSecret('release_key'), true);
        if (!is_array($r) || !is_string($r['key'] ?? null) || !\Sentinel\System\ReleaseManifest::validPublicKey($r['key'])) {
            return $none;
        }
        $chain = [];
        $next = null;
        foreach (is_array($r['chain'] ?? null) ? array_values($r['chain']) : [] as $link) {
            $st = is_array($link) && is_string($link['statement'] ?? null) ? json_decode($link['statement'], true) : null;
            if (!is_array($st) || !is_string($link['signature'] ?? null) || !is_string($st['old_key'] ?? null) || !is_string($st['new_key'] ?? null)
                || ($next !== null && $st['old_key'] !== $next)) {
                $chain = [];
                break;
            }
            $chain[] = ['statement' => $link['statement'], 'signature' => $link['signature'], 'old_key' => $st['old_key'], 'new_key' => $st['new_key']];
            $next = $st['new_key'];
        }
        if ($chain !== [] && $next !== $r['key']) {
            $chain = [];
        }
        return ['key' => $r['key'], 'created_at' => is_string($r['created_at'] ?? null) ? $r['created_at'] : '', 'chain' => $chain];
    }

    /**
     * Save the release key (see releaseKey()). The caller has checked the key and, for a rotation, the statement.
     *
     * @param list<array{statement:string, signature:string}> $chain
     */
    public static function setReleaseKey(string $key, array $chain): void
    {
        $chain = array_slice(array_map(static fn (array $l): array => ['statement' => $l['statement'], 'signature' => $l['signature']], $chain), -\Sentinel\System\ReleaseManifest::MAX_ROTATIONS);
        self::settings()->setSecret('release_key', $key === '' ? '' : (string) json_encode(['key' => $key, 'created_at' => (string) self::db()->query('SELECT UTC_TIMESTAMP()')->fetchColumn(),
            'chain' => $chain], JSON_UNESCAPED_SLASHES));
    }

    /** The signed agent release this installation can hand to agents (test suite: testing.release_root). */
    public static function agentRelease(): \Sentinel\Agent\AgentRelease
    {
        $test = self::config()->get('testing.allow_documentation_ranges', false) === true ? (string) self::config()->get('testing.release_root', '') : '';
        $key = self::releaseKey()['key'];
        return $test !== '' ? new \Sentinel\Agent\AgentRelease($test, self::version(), true, $key, (string) self::config()->get('testing.release_ui_dir', ''))
            : new \Sentinel\Agent\AgentRelease(dirname(__DIR__, 2), self::version(), false, $key, SENTINEL_ROOT . '/storage/agent-release');
    }

    /** Active Directory settings per site and the sealed password relay to agents. */
    public static function directory(): \Sentinel\Agent\DirectoryRepository
    {
        return new \Sentinel\Agent\DirectoryRepository(self::db());
    }

    /** Agent scheduling, job signing and results. */
    public static function agentService(): \Sentinel\Agent\AgentService
    {
        // Seconds a full scan listens for name requests: 120, or a few seconds in the test suite.
        $listen = self::config()->get('testing.allow_documentation_ranges', false) === true ? (int) self::config()->get('testing.agent_listen_seconds', \Sentinel\Agent\AgentService::LISTEN_SECONDS) : \Sentinel\Agent\AgentService::LISTEN_SECONDS;
        return new \Sentinel\Agent\AgentService(self::db(), self::agents(), self::agentSigner(), self::scope(), self::inventory(), self::vulnMatcher(15), self::findingsEngine(), self::alerts(),
            self::directory(), $listen);
    }

    /** Internal devices from inventory sources. */
    public static function inventory(): \Sentinel\Inventory\InventoryRepository
    {
        return new \Sentinel\Inventory\InventoryRepository(self::db());
    }

    /** Fix workflow: assignment, due dates. */
    public static function fixWorkflow(): \Sentinel\Findings\FixWorkflow
    {
        return new \Sentinel\Findings\FixWorkflow(self::db(), self::settings());
    }

    /** TLS endpoint and web page store. */
    public static function endpoints(): EndpointRepository
    {
        return new EndpointRepository(self::db());
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

    /**
     * Where this install's code came from, from the BUILD file the one-line installer and msp-sentinel-update
     * write (branch and commit). Null for release archives and manual installs, which have no BUILD file.
     *
     * Untrusted: the file is root-owned, but it is still parsed strictly (branch-name and hex-commit patterns)
     * and anything else is ignored; views escape the values as always.
     *
     * @return array{branch:string,commit:string,sha:string,repo:string,development:bool}|null
     */
    public static function build(): ?array
    {
        if (self::$build === null) {
            self::$build = false;
            $raw = @file_get_contents(SENTINEL_ROOT . '/BUILD', false, null, 0, 1024);
            if (is_string($raw)
                && preg_match('/^branch=([A-Za-z0-9][A-Za-z0-9._\/-]{0,59})$/m', $raw, $b) === 1 && !str_contains($b[1], '..')
                && preg_match('/^commit=([0-9a-f]{7,40})$/m', $raw, $c) === 1) {
                $repo = preg_match('/^repo=([A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100})$/m', $raw, $r) === 1 ? $r[1] : '';
                self::$build = ['branch' => $b[1], 'commit' => substr($c[1], 0, 12), 'sha' => $c[1], 'repo' => $repo];
            }
        }
        return self::$build === false ? null : self::$build + ['development' => self::$build['branch'] !== 'main'];
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

        // On-premises agents have their own kernel too: agent tokens, signed jobs, JSON only.
        if (str_starts_with($request->path, '/agent/v1/')) {
            return SecurityHeaders::apply(\Sentinel\Agent\AgentKernel::handle($request), $secure);
        }
        // The API has its own kernel: bearer tokens, no session or cookies, JSON errors.
        if ($request->path === '/api' || str_starts_with($request->path, '/api/')) {
            return SecurityHeaders::apply(\Sentinel\Api\ApiKernel::handle($request), $secure);
        }
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
        if ($opts['passive'] === true) {
            $auth->markPassive();
        }
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
