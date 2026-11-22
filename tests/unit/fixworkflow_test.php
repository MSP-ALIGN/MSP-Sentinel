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
    'verify outcomes are only "fixed" or "still present" when the target was really rechecked' => function (TestContext $ctx): void {
        $start = '2030-01-01 10:00:00';
        $f = static fn (string $key, string $status = 'open', ?string $resolved = null): array => ['finding_key' => $key, 'status' => $status, 'resolved_at' => $resolved];
        $probe = static fn (array $p, array $extra = []): array => ['refresh_ok' => true, 'verify_probe' => $p] + $extra;
        $r = static fn (array $finding, string $job, array $summary): string => \Sentinel\Findings\VerifyOutcome::decide($finding, $job, $start, $summary)['result'];
        $ip = '203.0.113.5:443';
        Assert::same('fixed', $r($f('port:203.0.113.5:443', 'resolved', '2030-01-01 10:00:05'), 'done', $probe([$ip => ['state' => 'closed']])));
        Assert::same('still_present', $r($f('port:203.0.113.5:443'), 'done', $probe([$ip => ['state' => 'open']])));
        Assert::same('not_verified', $r($f('port:203.0.113.5:443', 'resolved', '2030-01-01 10:00:05'), 'partial', $probe([$ip => ['state' => 'closed']])), 'partial job');
        Assert::same('not_verified', $r($f('port:203.0.113.5:443'), 'done', $probe([$ip => ['state' => 'unknown']])), 'incomplete scan');
        Assert::same('not_verified', $r($f('port:203.0.113.5:443'), 'done', ['verify_probe' => [$ip => ['state' => 'open']]]), 'refresh failed');
        Assert::same('already_resolved', $r($f('port:203.0.113.5:443', 'resolved', '2030-01-01 09:59:00'), 'done', $probe([$ip => ['state' => 'closed']])));
        Assert::same('unreachable', $r($f('tls:203.0.113.5:443:www.client.example:cert_expired', 'resolved', '2030-01-01 10:00:05'), 'done', $probe([$ip => ['state' => 'closed']])), 'closed is not fixed');
        Assert::same('not_verified', $r($f('tls:203.0.113.5:443:www.client.example:cert_expired'), 'done', $probe([$ip => ['state' => 'open', 'tls_ok' => false, 'snis' => ['www.client.example']]])), 'TLS check failed');
        Assert::same('not_verified', $r($f('tls:203.0.113.5:443:www.client.example:cert_expired', 'resolved', '2030-01-01 10:00:05'), 'done', $probe([$ip => ['state' => 'open', 'tls_ok' => true, 'snis' => ['other.client.example']]])), 'name not checked');
        Assert::same('fixed', $r($f('tls:203.0.113.5:443:www.client.example:cert_expired', 'resolved', '2030-01-01 10:00:05'), 'done', $probe([$ip => ['state' => 'open', 'tls_ok' => true, 'snis' => ['www.client.example']]])));
        Assert::same('not_verified', $r($f('site:203.0.113.5:443:exposed_git'), 'done', $probe([$ip => ['state' => 'open', 'web_ok' => true, 'site_complete' => false]])), 'partial exposed-file run');
        Assert::same('still_present', $r($f('site:203.0.113.5:443:exposed_git'), 'done', $probe([$ip => ['state' => 'open', 'web_ok' => true, 'site_complete' => true]])));
        Assert::same('not_verified', $r($f('vuln:203.0.113.5:443:CVE-2099-0001'), 'done', $probe([$ip => ['state' => 'open']], ['vuln_pending' => 1])), 'data pending');
        Assert::same('still_present', $r($f('vuln:203.0.113.5:443:CVE-2099-0001'), 'done', $probe([$ip => ['state' => 'open']], ['vuln_pending' => 0])));
        Assert::same('fixed', $r($f('email:mail.client.example:spf_missing', 'resolved', '2030-01-01 10:00:05'), 'done', $probe(['email' => 'ok'])));
        Assert::same('not_verified', $r($f('email:mail.client.example:spf_missing'), 'done', $probe(['email' => 'failed'])));
    },
    'due dates must be real dates within a sane range' => function (TestContext $ctx): void {
        Assert::true(FixWorkflow::validDate(gmdate('Y-m-d', time() + 86400)), 'tomorrow');
        foreach (['2026-02-30', '26-01-01', gmdate('Y-m-d', time() + 3 * 366 * 86400), '2000-01-01', '2030-1-1', ''] as $bad) {
            Assert::true(!FixWorkflow::validDate($bad), 'rejected: ' . $bad);
        }
    },
];
