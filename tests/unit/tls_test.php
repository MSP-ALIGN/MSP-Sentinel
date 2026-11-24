<?php

declare(strict_types=1);

/**
 * Unit tests for certificate name matching, the exposure rules, page
 * classification and the test-only connection redirect.
 */

use Sentinel\Core\Config;
use Sentinel\Scanning\Connector;
use Sentinel\Scanning\ExposureRules;
use Sentinel\Scanning\HttpProbe;
use Sentinel\Scanning\TlsChecker;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'certificate name matching follows the wildcard rules' => function (TestContext $ctx): void {
        $sans = TlsChecker::sans('DNS:www.client.example, DNS:*.apps.client.example, IP Address:203.0.113.5, DNS:bad name');
        Assert::same(['www.client.example', '*.apps.client.example'], $sans);
        Assert::true(TlsChecker::hostnameMatches('www.client.example', $sans, ''), 'exact');
        Assert::true(TlsChecker::hostnameMatches('crm.apps.client.example', $sans, ''), 'wildcard one label');
        Assert::true(!TlsChecker::hostnameMatches('a.b.apps.client.example', $sans, ''), 'wildcard covers one label only');
        Assert::true(!TlsChecker::hostnameMatches('apps.client.example', $sans, ''), 'wildcard does not cover the bare name');
        Assert::true(!TlsChecker::hostnameMatches('evilwww.client.example', $sans, ''), 'no partial match');
        Assert::true(TlsChecker::hostnameMatches('legacy.example', [], 'legacy.example'), 'CN used only without SANs');
        Assert::true(!TlsChecker::hostnameMatches('legacy.example', ['other.example'], 'legacy.example'), 'CN ignored when SANs exist');
        Assert::true(!TlsChecker::hostnameMatches('x.example', ['*.example'], ''), 'no wildcard directly under a TLD');
    },
    'exposure rules grade certificates as agreed' => function (TestContext $ctx): void {
        $now = strtotime('2026-11-22 12:00:00 UTC');
        $base = ['not_before' => '2026-01-01 00:00:00', 'not_after' => '2027-06-01 00:00:00', 'self_signed' => 0, 'chain_trusted' => 1, 'hostname_match' => 1,
                 'sni' => 'www.client.example', 'accepts_tls10' => 0, 'accepts_tls11' => 0, 'key_type' => 'RSA', 'key_bits' => 2048, 'signature_alg' => 'RSA-SHA256'];
        Assert::same([], ExposureRules::tlsIssues($base, $now), 'healthy certificate');
        $codes = static fn (array $over) => array_column(ExposureRules::tlsIssues($over + $base, $now), 'severity', 'code');
        Assert::same(['cert_expired' => 'fail'], $codes(['not_after' => '2026-11-01 00:00:00']));
        Assert::same(['cert_expiring' => 'warn'], $codes(['not_after' => '2026-12-01 00:00:00']));
        Assert::same([], $codes(['not_after' => '2026-12-31 00:00:00']), '39 days left is fine');
        Assert::same(['cert_self_signed' => 'warn'], $codes(['self_signed' => 1, 'chain_trusted' => 0]));
        Assert::same(['cert_untrusted' => 'warn'], $codes(['chain_trusted' => 0]));
        Assert::same(['cert_name_mismatch' => 'warn'], $codes(['hostname_match' => 0]));
        Assert::same([], $codes(['hostname_match' => null]), 'unknown name (scanned by IP) is not an issue');
        Assert::same(['tls_old_protocol' => 'warn'], $codes(['accepts_tls10' => 1]));
        Assert::same(['cert_weak_key' => 'warn'], $codes(['key_bits' => 1024]));
        Assert::same(['cert_weak_signature' => 'warn'], $codes(['signature_alg' => 'RSA-SHA1']));
        Assert::same('fail', ExposureRules::webIssue('firewall_admin')['severity']);
        Assert::same('warn', ExposureRules::webIssue('vpn_portal')['severity']);
        Assert::same(null, ExposureRules::webIssue(null));
    },
    'page classification is generic and avoids false alarms' => function (TestContext $ctx): void {
        Assert::same('vpn_portal', HttpProbe::classify('SSL VPN Portal', '', [])[0]);
        Assert::same('firewall_admin', HttpProbe::classify('Firewall Administration', '<input type="password">', [])[0]);
        Assert::same('firewall_admin', HttpProbe::classify('Firewall Administration', '', [])[0], 'title alone is enough');
        Assert::same('device_admin', HttpProbe::classify('Router Management', '<input type=password>', [])[0]);
        Assert::same('remote_desktop_web', HttpProbe::classify('RD Web Access', '', [])[0]);
        Assert::same(null, HttpProbe::classify('Example Co', '<p>We sell routers, switches and firewall appliances. Admin console tours daily!</p>', [])[0], 'ordinary website mentioning routers is not flagged');
        Assert::same('login_page', HttpProbe::classify('Customer area', '<form><input type="password"></form>', [])[0]);
        Assert::same('login_page', HttpProbe::classify('', '', ['www-authenticate' => 'Basic realm="x"'])[0]);
        Assert::same(null, HttpProbe::classify('Hello', '<script>var s="ssl vpn login";</script>', [])[0], 'script contents are ignored');
        Assert::same('login_page', HttpProbe::classify('Sign in - Webmail', '<input type=password><a>Switch language</a>', [])[0], 'common words in body text never mean device admin');
        Assert::same('login_page', HttpProbe::classify('Customer portal', '<input type="password"><p>Track your UPS shipment</p>', [])[0]);
        Assert::same('firewall_admin', HttpProbe::classify('Welcome', '<h1>Firewall Administration</h1><input type="password">', [])[0], 'headings count');
        // Named management products (1.28): hypervisors, server remote management, NAS, network controllers.
        foreach (['VMware ESXi' => 'hypervisor_admin', 'Proxmox Virtual Environment' => 'hypervisor_admin', 'vSphere Client' => 'hypervisor_admin',
                  'iDRAC9 - Login' => 'oob_admin', 'Integrated Lights-Out 5' => 'oob_admin', 'Synology DiskStation' => 'nas_admin', 'TrueNAS' => 'nas_admin',
                  'UniFi Network' => 'device_admin', 'RouterOS router configuration page' => 'device_admin'] as $title => $category) {
            Assert::same($category, HttpProbe::classify($title, '<input type="password">', [])[0], $title);
        }
        Assert::same(null, HttpProbe::classify('Example IT', '<p>We manage VMware vSphere, Proxmox and Synology for local businesses.</p>', [])[0], 'products named in body text are not flagged');
        Assert::same('fail', ExposureRules::webIssue('hypervisor_admin')['severity']);
        Assert::same('fail', ExposureRules::webIssue('oob_admin')['severity']);
        Assert::same('fail', ExposureRules::webIssue('nas_admin')['severity']);
        $t = microtime(true);
        HttpProbe::classify('x', str_repeat('<script>', 32768) . '<style>' . str_repeat('a', 1000), []);
        Assert::true(microtime(true) - $t < 0.5, 'hostile unclosed tags are handled in linear time');
        Assert::true(!TlsChecker::hostnameMatches('evil.co.uk', ['*.co.uk'], ''), 'wildcards on public suffixes never match');
    },
    'an extra CA file is added to the system trust store, not used instead of it' => function (TestContext $ctx): void {
        $cfg = require $ctx->configPath;
        $checker = new TlsChecker(Connector::direct(), $cfg['tls']['ca_file']);
        $method = new ReflectionMethod($checker, 'caBundle');
        $bundle = (string) file_get_contents((string) $method->invoke($checker));
        Assert::contains((string) file_get_contents($cfg['tls']['ca_file']), $bundle, 'extra CA included');
        $system = openssl_get_cert_locations()['default_cert_file'] ?? '';
        if (is_readable($system) && filesize($system) > 0) {
            Assert::true(strlen($bundle) > filesize($system), 'system CAs included too');
        }
    },
    'connection redirects only exist in test mode and only to 127.0.0.1' => function (TestContext $ctx): void {
        $prod = Connector::fromConfig(Config::fromArray(['app_key' => base64_encode(random_bytes(32)), 'db' => ['host' => 'h', 'name' => 'n', 'user' => 'u'],
            'testing' => ['redirect_connections' => ['203.0.113.5:443' => 9999]]]));
        Assert::same(['203.0.113.5', 443], $prod->endpoint('203.0.113.5', 443), 'ignored without allow_documentation_ranges');
        $test = Connector::fromConfig(Config::fromArray(['app_key' => base64_encode(random_bytes(32)), 'db' => ['host' => 'h', 'name' => 'n', 'user' => 'u'],
            'testing' => ['allow_documentation_ranges' => true, 'redirect_connections' => ['203.0.113.5:443' => 9999, '203.0.113.6:443' => 'evil.example']]]));
        Assert::same(['127.0.0.1', 9999], $test->endpoint('203.0.113.5', 443));
        try {
            $test->endpoint('203.0.113.6', 443);
            Assert::true(false, 'in test mode an unmapped target must be refused');
        } catch (RuntimeException $ex) {
            Assert::contains('connection refused', $ex->getMessage());
        }
        // Through the checkers: an unmapped endpoint gives an error result, and no connection is attempted.
        $r = (new TlsChecker($test, null, 2.0))->check('203.0.113.6', 443, null);
        Assert::true(!$r['ok'] && str_contains($r['error'], 'Test mode'), 'TLS check refused');
        $w = (new HttpProbe($test, 2))->fetch('203.0.113.6', 80, 'http', null);
        Assert::true(!$w['ok'] && str_contains($w['last_error'], 'Test mode'), 'HTTP check refused');
    },
];
