<?php

declare(strict_types=1);

/**
 * Unit tests for NmapRunner's output capture (1.47.2). On Windows nmap's output goes to private temporary files
 * instead of pipes (PHP can't read process pipes there without blocking). The test suite runs on Linux, so it forces
 * that path with the suite's fake nmap and checks it gives the same result as the pipes, honours the stop check and
 * leaves no files behind. The fake nmap never sends packets; documentation addresses only.
 */

use Sentinel\Scanning\NmapRunner;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$fake = static fn (TestContext $ctx): string => (string) (require $ctx->configPath)['scanner']['nmap_path'];
$tempFiles = static fn (): array => array_merge(glob(sys_get_temp_dir() . '/snx*') ?: [], glob(sys_get_temp_dir() . '/sne*') ?: []);

return [
    'nmap output through temporary files (the Windows path) matches the pipes, and leaves nothing behind' => function (TestContext $ctx) use ($fake, $tempFiles): void {
        $before = $tempFiles();
        $never = static fn (): bool => false;
        $pipes = (new NmapRunner($fake($ctx), 60, 'gentle', false))->scan('203.0.113.160', [22, 443, 3389], $never);
        $files = (new NmapRunner($fake($ctx), 60, 'gentle', true))->scan('203.0.113.160', [22, 443, 3389], $never);
        Assert::same(0, $files['exit'], 'nmap ran: ' . $files['stderr']);
        Assert::contains('portid="22"', $files['xml']);
        Assert::same($pipes['xml'], $files['xml'], 'same XML either way');
        Assert::same([false, false, false], [$files['stopped'], $files['timed_out'], $files['overflow']]);
        Assert::same($before, $tempFiles(), 'temporary files removed');
        // withProfile keeps the capture mode.
        $agentFake = (string) (require $ctx->configPath)['testing']['agent_nmap_path']; // accepts the agents' profiles
        $other = (new NmapRunner($agentFake, 60, 'gentle', true))->withProfile('very_gentle')->scan('203.0.113.161', [22], $never);
        Assert::same(0, $other['exit'], 'withProfile: ' . $other['stderr']);
    },
    'nmap through temporary files still stops within seconds when told to' => function (TestContext $ctx) use ($fake, $tempFiles): void {
        $before = $tempFiles();
        $start = microtime(true);
        $checks = 0;
        // The fixture's "slow" host makes the fake nmap sleep 30 seconds; the stop check says stop on its second call.
        $r = (new NmapRunner($fake($ctx), 60, 'gentle', true))->scan('203.0.113.170', [22], static function () use (&$checks): bool {
            return ++$checks >= 2;
        });
        Assert::true($r['stopped'], 'stopped');
        Assert::true(microtime(true) - $start < 10, 'within seconds, not after nmap finished');
        Assert::same($before, $tempFiles(), 'temporary files removed after a stop');
    },
    'nmap through temporary files: its time limit holds, and the version check works the same way' => function (TestContext $ctx) use ($fake, $tempFiles): void {
        $before = $tempFiles();
        $start = microtime(true);
        $r = (new NmapRunner($fake($ctx), 2, 'gentle', true))->scan('203.0.113.170', [22], static fn (): bool => false);
        Assert::true($r['timed_out'], 'timed out');
        Assert::true(microtime(true) - $start < 10, 'stopped at the limit, not after nmap finished');
        Assert::same($before, $tempFiles(), 'temporary files removed after a timeout');
        Assert::same((new NmapRunner($fake($ctx), 60, 'gentle', false))->version(), (new NmapRunner($fake($ctx), 60, 'gentle', true))->version(), 'same version line either way');
    },
];
