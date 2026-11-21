<?php

declare(strict_types=1);

/**
 * End-to-end test runner.
 *
 * What it does:
 *  1. Creates a throwaway database and database user with a random password.
 *  2. Writes a temporary config (random app key) under tests/output/.
 *  3. Runs migrations through the real CLI, twice (idempotency check).
 *  4. Creates the first admin through the real CLI (bin/create-admin.php).
 *  5. Starts PHP's built-in web server on 127.0.0.1 and runs every test in
 *     tests/e2e/ and tests/unit/ against it.
 *  6. Drops the database and the user again.
 *
 * Usage:
 *   php tests/run.php [filter]       run tests whose name contains [filter]
 *   php tests/run.php --serve        set up, seed demo users, keep the server running (for screenshots)
 *
 * Environment (database admin used only to create and drop the throwaway database):
 *   SENTINEL_TEST_DB_ADMIN_DSN   default "mysql:unix_socket=/run/mysqld/mysqld.sock"
 *   SENTINEL_TEST_DB_ADMIN_USER  default "root"
 *   SENTINEL_TEST_DB_ADMIN_PASS  default ""
 *
 * Security assumptions: only 127.0.0.1 is contacted. All data is made up.
 * No real client data and no real hosts are used.
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}

require dirname(__DIR__) . '/src/bootstrap.php';
require __DIR__ . '/lib/TestKit.php';

use Sentinel\Tests\AssertionFailed;
use Sentinel\Tests\TestContext;

$args = array_slice($argv, 1);
$serve = in_array('--serve', $args, true);
$filter = '';
foreach ($args as $arg) {
    if (!str_starts_with($arg, '--')) {
        $filter = $arg;
    }
}

$root = dirname(__DIR__);
$runId = bin2hex(random_bytes(4));
$outDir = $root . '/tests/output/run-' . $runId;
mkdir($outDir, 0700, true);

$dbName = 'sentinel_test_' . $runId;
$dbUser = 'st_' . $runId;
$dbPass = bin2hex(random_bytes(16));

$server = null;
$mocks = [];
$admin = new PDO(
    getenv('SENTINEL_TEST_DB_ADMIN_DSN') ?: 'mysql:unix_socket=/run/mysqld/mysqld.sock',
    getenv('SENTINEL_TEST_DB_ADMIN_USER') ?: 'root',
    getenv('SENTINEL_TEST_DB_ADMIN_PASS') ?: '',
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);
$configPath = $outDir . '/config.php';
$keepOutput = true;
// Defined before anything is created, so every exit path drops the database and user again.
$cleanup = static function () use (&$server, &$mocks, &$keepOutput, $admin, $dbName, $dbUser, $outDir): void {
    foreach (array_merge([$server], $mocks) as $proc) {
        if (is_resource($proc)) {
            proc_terminate($proc);
            proc_close($proc);
        }
    }
    $admin->exec("DROP DATABASE IF EXISTS `{$dbName}`");
    $admin->exec("DROP USER IF EXISTS '{$dbUser}'@'127.0.0.1'");
    @unlink($outDir . '/config.php');
    // Keep the server log of a failed run for debugging; remove the folder after a clean run.
    if (!$keepOutput) {
        array_map('unlink', glob($outDir . '/*') ?: []);
        @rmdir($outDir);
    }
};

/** Run a CLI script with the test config. Returns [exit code, output]. */
$cli = static function (string $script, array $scriptArgs = [], string $stdin = '') use ($root, $configPath): array {
    $cmd = array_merge([PHP_BINARY, $root . '/' . $script], $scriptArgs);
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, ['SENTINEL_CONFIG' => $configPath, 'PATH' => getenv('PATH')]);
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    $code = proc_close($proc);
    return [$code, $out];
};

$exitCode = 0;
try {
    $admin->exec("CREATE DATABASE `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $admin->exec("CREATE USER '{$dbUser}'@'127.0.0.1' IDENTIFIED BY '{$dbPass}'");
    $admin->exec("GRANT ALL ON `{$dbName}`.* TO '{$dbUser}'@'127.0.0.1'");
    file_put_contents($configPath, '<?php return ' . var_export([
        'app_key' => base64_encode(random_bytes(32)),
        'db' => ['host' => '127.0.0.1', 'port' => 3306, 'name' => $dbName, 'user' => $dbUser, 'pass' => $dbPass],
        'app' => ['base_path' => '', 'force_secure_cookies' => false, 'trusted_proxies' => [], 'locale' => 'en'],
        // Tests may only use documentation addresses and *.example names, never real ones.
        'testing' => ['allow_documentation_ranges' => true],
    ], true) . ";\n");
    chmod($configPath, 0600);

    // Migrations through the CLI, twice: the second run must change nothing.
    [$code, $out] = $cli('bin/migrate.php');
    if ($code !== 0) {
        throw new RuntimeException("First migration run failed:\n" . $out);
    }
    [$code, $out] = $cli('bin/migrate.php');
    if ($code !== 0 || !str_contains($out, 'up to date')) {
        throw new RuntimeException("Second migration run was not a no-op:\n" . $out);
    }

    // First admin through the CLI, password on stdin.
    [$code, $out] = $cli('bin/create-admin.php', ['--username=admin', '--name=Alex Admin', '--email=admin@msp.example'], "Admin-Pass-0001!\n");
    if ($code !== 0) {
        throw new RuntimeException("create-admin failed:\n" . $out);
    }

    $freePort = static function (): int {
        $sock = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr(strrchr(stream_socket_get_name($sock, false), ':'), 1);
        fclose($sock);
        return $port;
    };
    // Mock outside services, all on 127.0.0.1: DNS (UDP+TCP) and crt.sh (HTTP).
    $dnsPort = $freePort();
    $dnsLog = $outDir . '/dns-queries.log';
    $mocks[] = proc_open([PHP_BINARY, __DIR__ . '/mocks/dns_server.php', (string) $dnsPort, __DIR__ . '/fixtures/dns_zone.json', $dnsLog],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', $outDir . '/mock-dns.log', 'a'], 2 => ['file', $outDir . '/mock-dns.log', 'a']], $pipes);
    $crtshPort = $freePort();
    $mocks[] = proc_open([PHP_BINARY, '-S', "127.0.0.1:{$crtshPort}", __DIR__ . '/mocks/crtsh_router.php'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', $outDir . '/mock-crtsh.log', 'a'], 2 => ['file', $outDir . '/mock-crtsh.log', 'a']], $pipes);
    $cfg = require $configPath;
    $cfg['dns'] = ['resolver' => '127.0.0.1', 'port' => $dnsPort, 'timeout' => 0.3];
    $cfg['crtsh'] = ['enabled' => true, 'base_url' => "http://127.0.0.1:{$crtshPort}", 'timeout' => 5];
    $cfg['discovery'] = ['crtsh_delay' => 0, 'manual_budget' => 25];
    // Fake nmap: a wrapper script so the fake can record its arguments for this run. It never sends packets.
    $nmapWrapper = $outDir . '/fake-nmap.sh';
    file_put_contents($nmapWrapper, "#!/bin/sh\nexec " . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/mocks/fake_nmap.php') . ' '
        . escapeshellarg($outDir . '/nmap-args.log') . " \"\$@\"\n");
    chmod($nmapWrapper, 0700);
    $cfg['scanner'] = ['nmap_path' => $nmapWrapper, 'host_timeout' => 60];
    file_put_contents($configPath, '<?php return ' . var_export($cfg, true) . ";\n");
    for ($i = 0; $i < 50 && @fsockopen('127.0.0.1', $crtshPort) === false; $i++) {
        usleep(100000);
    }

    // Built-in web server on a free local port.
    $port = $freePort();
    $logFile = $outDir . '/server.log';
    $server = proc_open(
        [PHP_BINARY, '-S', "127.0.0.1:{$port}", '-t', $root . '/public', $root . '/public/index.php'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', $logFile, 'a'], 2 => ['file', $logFile, 'a']],
        $pipes,
        $root,
        ['SENTINEL_CONFIG' => $configPath, 'PATH' => getenv('PATH')]
    );
    $baseUrl = "http://127.0.0.1:{$port}";
    for ($i = 0; $i < 50; $i++) {
        if (@fsockopen('127.0.0.1', $port) !== false) {
            break;
        }
        usleep(100000);
    }

    $appConfig = require $configPath;
    $db = new PDO("mysql:host=127.0.0.1;port=3306;dbname={$dbName};charset=utf8mb4", $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $db->exec("SET time_zone = '+00:00'");
    $ctx = new TestContext($baseUrl, $db, $root, $configPath);
    $ctx->dnsPort = $dnsPort;
    $ctx->dnsLog = $dnsLog;
    $ctx->crtshUrl = "http://127.0.0.1:{$crtshPort}";
    $ctx->nmapLog = $outDir . '/nmap-args.log';
    \Sentinel\Core\App::boot(\Sentinel\Core\Config::fromArray($appConfig));

    if ($serve) {
        // Demo users for screenshots: made-up names only.
        $ctx->createUser('tina', 'technician', 'Tech-Pass-0001!');
        $ctx->createUser('victor', 'viewer', 'View-Pass-0001!');
        file_put_contents($outDir . '/serve.json', json_encode(['url' => $baseUrl, 'dir' => $outDir], JSON_PRETTY_PRINT));
        fwrite(STDOUT, "Serving {$baseUrl} (output in {$outDir}). Press Ctrl+C to stop.\n");
        pcntl_async_signals(true);
        $stop = false;
        pcntl_signal(SIGTERM, static function () use (&$stop): void { $stop = true; });
        pcntl_signal(SIGINT, static function () use (&$stop): void { $stop = true; });
        while (!$stop) {
            sleep(1);
        }
        $cleanup();
        exit(0);
    }

    // Collect tests: each file returns ['name' => fn(TestContext $ctx)].
    $tests = [];
    foreach (array_merge(glob(__DIR__ . '/unit/*_test.php') ?: [], glob(__DIR__ . '/e2e/*_test.php') ?: []) as $file) {
        foreach (require $file as $name => $fn) {
            $tests[basename($file, '_test.php') . ': ' . $name] = $fn;
        }
    }

    $passed = 0;
    $failed = [];
    foreach ($tests as $name => $fn) {
        if ($filter !== '' && !str_contains($name, $filter)) {
            continue;
        }
        $ctx->clearThrottle();
        try {
            $fn($ctx);
            $passed++;
            fwrite(STDOUT, "  \033[32m✔\033[0m {$name}\n");
        } catch (AssertionFailed $ex) {
            $failed[$name] = $ex->getMessage();
            fwrite(STDOUT, "  \033[31m✘\033[0m {$name}\n      " . $ex->getMessage() . "\n");
        } catch (\Throwable $ex) {
            $failed[$name] = get_class($ex) . ': ' . $ex->getMessage();
            fwrite(STDOUT, "  \033[31m✘\033[0m {$name}\n      " . get_class($ex) . ': ' . $ex->getMessage() . ' @ ' . $ex->getFile() . ':' . $ex->getLine() . "\n");
        }
    }

    // Server-side PHP warnings or errors fail the run, even if every assertion passed.
    $log = (string) @file_get_contents($logFile);
    if (preg_match_all('/(PHP (Warning|Notice|Deprecated|Fatal error|Parse error)|\[msp-sentinel\]).*$/m', $log, $m)) {
        $failed['server log'] = implode("\n      ", array_unique($m[0]));
        fwrite(STDOUT, "  \033[31m✘\033[0m server log has PHP warnings/errors:\n      " . $failed['server log'] . "\n");
    }

    fwrite(STDOUT, sprintf("\n%d passed, %d failed\n", $passed, count($failed)));
    $exitCode = $failed === [] ? 0 : 1;
    $keepOutput = $exitCode !== 0;
} catch (\Throwable $ex) {
    fwrite(STDERR, 'Test setup failed: ' . $ex->getMessage() . "\n");
    $exitCode = 1;
} finally {
    $cleanup();
}
exit($exitCode);
