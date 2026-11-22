<?php

declare(strict_types=1);

/**
 * Unit tests for the fix workflow helpers: which target a finding's recheck
 * may touch, and due-date validation.
 */

use Sentinel\Findings\FixWorkflow;
use Sentinel\Findings\VerifyTarget;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'verify targets are parsed strictly from finding keys (IPv4, IPv6, email)' => function (TestContext $ctx): void {
        $cases = [
            'port:203.0.113.5:3389' => ['kind' => 'endpoint', 'ip' => '203.0.113.5', 'port' => 3389],
            'port:2001:db8::5:443' => ['kind' => 'endpoint', 'ip' => '2001:db8::5', 'port' => 443],
            'tls:203.0.113.5:443:www.client.example:cert_expired' => ['kind' => 'endpoint', 'ip' => '203.0.113.5', 'port' => 443],
            'tls:2001:db8::5:8443::cert_self_signed' => ['kind' => 'endpoint', 'ip' => '2001:db8::5', 'port' => 8443],
            'web:203.0.113.5:8443:firewall_admin' => ['kind' => 'endpoint', 'ip' => '203.0.113.5', 'port' => 8443],
            'site:203.0.113.5:80:exposed_git' => ['kind' => 'endpoint', 'ip' => '203.0.113.5', 'port' => 80],
            'vuln:203.0.113.5:22:CVE-2099-0001' => ['kind' => 'endpoint', 'ip' => '203.0.113.5', 'port' => 22],
            'webvuln:203.0.113.5:443:jQuery:CVE-2099-0201' => ['kind' => 'endpoint', 'ip' => '203.0.113.5', 'port' => 443],
            'email:mail.client.example:spf_missing' => ['kind' => 'email', 'domain' => 'mail.client.example'],
        ];
        foreach ($cases as $key => $want) {
            Assert::same($want, VerifyTarget::fromKey($key), $key);
        }
        foreach (['port:203.0.113.5:0', 'port:not-an-ip:22', 'port:203.0.113.5:99999', 'other:203.0.113.5:22', 'site:203.0.113.5:80', 'email:-bad-.example:x',
                  'email:a.example', 'port:203.0.113.5:22#' . str_repeat('a', 64), 'tls:203.0.113.5:443:x'] as $bad) {
            Assert::same(null, VerifyTarget::fromKey($bad), 'rejected: ' . $bad);
        }
    },
    'due dates must be real dates within a sane range' => function (TestContext $ctx): void {
        Assert::true(FixWorkflow::validDate(gmdate('Y-m-d', time() + 86400)), 'tomorrow');
        foreach (['2026-02-30', '26-01-01', gmdate('Y-m-d', time() + 3 * 366 * 86400), '2000-01-01', '2030-1-1', ''] as $bad) {
            Assert::true(!FixWorkflow::validDate($bad), 'rejected: ' . $bad);
        }
    },
];
