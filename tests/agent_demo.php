<?php

declare(strict_types=1);

/**
 * Screenshot helper: enrol the real agent program with a one-time code against the test server, point it at the
 * fake nmap and mock services (test mode only), and run it once. Never touches real hosts.
 *
 * Usage: php tests/agent_demo.php <app-config.php> <base-url> <code> <agent-dir>
 */

[$self, $configPath, $base, $code, $dir] = $argv + [null, '', '', '', ''];
if (!is_file($configPath) || $code === '' || $dir === '') {
    fwrite(STDERR, "usage: agent_demo.php <config> <base-url> <code> <agent-dir>\n");
    exit(2);
}
$root = dirname(__DIR__);
@mkdir($dir, 0700, true);
$env = ['SENTINEL_TEST_MODE' => '1', 'SENTINEL_ALLOW_ROOT' => '1', 'PATH' => (string) getenv('PATH')];
$run = static function (array $args) use ($root, $env): int {
    $p = proc_open(array_merge([PHP_BINARY, $root . '/bin/sentinel-agent.php'], $args), [1 => STDOUT, 2 => STDERR], $pipes, $root, $env);
    return proc_close($p);
};
if ($run(['enrol', '--server', $base, '--code', $code, '--config', $dir . '/agent.json']) !== 0) {
    exit(1);
}
$app = require $configPath;
$c = json_decode((string) file_get_contents($dir . '/agent.json'), true);
$c['nmap_path'] = $app['scanner']['nmap_path'];
$c['testing'] = ['allow_documentation_ranges' => true, 'redirect_connections' => $app['testing']['redirect_connections']];
file_put_contents($dir . '/agent.json', json_encode($c));
exit($run(['run', '--once', '--config', $dir . '/agent.json']));
