<?php

declare(strict_types=1);

/**
 * Unit tests for API helpers: IP allowlists, event signatures, time format.
 */

use Sentinel\Api\ApiController;
use Sentinel\Api\EventPublisher;
use Sentinel\Api\TokenService;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'IP allowlists' => function (TestContext $ctx): void {
        Assert::true(TokenService::ipAllowed('', '203.0.113.9'), 'empty list allows any');
        Assert::true(TokenService::ipAllowed('198.51.100.0/24,203.0.113.9', '203.0.113.9'), 'single address');
        Assert::true(TokenService::ipAllowed('198.51.100.0/24', '198.51.100.200'), 'in network');
        Assert::true(!TokenService::ipAllowed('198.51.100.0/24', '198.51.101.1'), 'outside network');
        Assert::true(TokenService::ipAllowed('2001:db8::/32', '2001:db8::5'), 'IPv6');
        Assert::true(!TokenService::ipAllowed('2001:db8::/32', '203.0.113.9'), 'IPv4 never matches an IPv6 range');
        Assert::true(!TokenService::ipAllowed('198.51.100.0/24', 'garbage'), 'invalid address');
        Assert::same('203.0.113.10', TokenService::normaliseIp('::ffff:203.0.113.10'), 'IPv4-mapped address normalised');
        Assert::same('2001:db8::1', TokenService::normaliseIp('2001:db8::1'));
    },
    'event signatures are HMAC-SHA256 over "timestamp.body"' => function (TestContext $ctx): void {
        Assert::same('t=1700000000,v1=' . hash_hmac('sha256', '1700000000.{"a":1}', 'whsec_test'), EventPublisher::sign('whsec_test', '{"a":1}', 1700000000));
    },
    'API times are ISO 8601 UTC' => function (TestContext $ctx): void {
        Assert::same('2026-11-22T10:05:00Z', ApiController::iso('2026-11-22 10:05:00'));
        Assert::same(null, ApiController::iso(null));
    },
];
