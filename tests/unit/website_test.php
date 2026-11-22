<?php

declare(strict_types=1);

/**
 * Unit tests for website check rules: content proofs, header/cookie analysis,
 * component detection.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;
use Sentinel\Web\WebsiteChecker;

$resp = static fn (int $status, array $headers, string $body, array $list = []): array => ['status' => $status, 'headers' => $headers, 'body' => $body,
    'header_list' => $list ?: array_map(static fn ($k, $v) => [$k, $v], array_keys($headers), $headers)];

return [
    'exposed files are only reported when the content proves it' => function (TestContext $ctx): void {
        Assert::true(WebsiteChecker::proves('git', "ref: refs/heads/main\n", 'text/plain'), 'git ref');
        Assert::true(!WebsiteChecker::proves('git', '<html>ref: refs/heads/main</html>', 'text/html'), 'HTML mentioning a ref');
        Assert::true(WebsiteChecker::proves('env', "APP_KEY=x\nDB_PASSWORD=y\n", 'text/plain'), 'env file');
        Assert::true(!WebsiteChecker::proves('env', "<!doctype html><p>APP_KEY=x\nDB_PASSWORD=y</p>", 'text/html'), 'soft 404 with env-like text');
        Assert::true(!WebsiteChecker::proves('env', "SINGLE=1\n", 'text/plain'), 'one line is not enough');
        Assert::true(WebsiteChecker::proves('archive', "PK\x03\x04rest", 'application/zip') && WebsiteChecker::proves('archive', "\x1f\x8brest", ''), 'zip and gzip');
        Assert::true(!WebsiteChecker::proves('archive', '<html>backup</html>', 'text/html'), 'HTML is not an archive');
        Assert::true(WebsiteChecker::proves('sql', "-- MySQL dump 10.13\nCREATE TABLE x", 'application/octet-stream'), 'SQL dump');
        Assert::true(WebsiteChecker::proves('dsstore', "\x00\x00\x00\x01Bud1rest", ''), 'DS_Store');
    },
    'headers, HTTPS and cookies are graded as designed' => function (TestContext $ctx) use ($resp): void {
        $a = WebsiteChecker::analyse($resp(200, ['content-type' => 'text/html'], '<form><input type="password"></form>'), 'http');
        Assert::same(['login_over_http'], $a['issues']);
        $a = WebsiteChecker::analyse($resp(200, ['content-type' => 'text/html'], '<p>hi</p>'), 'http');
        Assert::same(['no_https_redirect'], $a['issues']);
        $a = WebsiteChecker::analyse($resp(301, ['location' => 'https://x.example/'], ''), 'http');
        Assert::same([], $a['issues'], 'redirect to HTTPS is fine');
        $a = WebsiteChecker::analyse($resp(200, ['content-type' => 'text/html'], '<title>Index of /files</title>', [['set-cookie', 'session=1; path=/']]), 'https');
        foreach (['missing_hsts', 'missing_csp', 'directory_listing', 'insecure_cookies'] as $code) {
            Assert::true(in_array($code, $a['issues'], true), 'issue ' . $code);
        }
        Assert::true(in_array('missing_frame', $a['info'], true) && in_array('missing_samesite', $a['info'], true), 'advice only');
        $good = WebsiteChecker::analyse($resp(200, ['content-type' => 'text/html', 'strict-transport-security' => 'max-age=600', 'content-security-policy' => "default-src 'self'; frame-ancestors 'none'",
            'x-content-type-options' => 'nosniff', 'referrer-policy' => 'no-referrer'], '<p>ok</p>', [['set-cookie', 'sid=1; Secure; HttpOnly; SameSite=Strict']]), 'https');
        Assert::same([], $good['issues']);
        Assert::same(['short_hsts'], $good['info'], 'a short HSTS is advice only');
    },
    'review cases: phpinfo, compressed soft-404s, HTTP-to-HTTP redirects, cookie names' => function (TestContext $ctx) use ($resp): void {
        $php = '<!DOCTYPE html><html><head><style>body{}</style><title>PHP 8.3.4 - phpinfo()</title></head><body><div class="center"><table><tr class="h"><td><h1 class="p">PHP Version 8.3.4</h1></td></tr>';
        Assert::true(WebsiteChecker::proves('phpinfo', $php, 'text/html'), 'a real phpinfo page start');
        Assert::true(!WebsiteChecker::proves('phpinfo', '<p>Read about phpinfo() and PHP Version </p>', 'text/html'), 'a page about phpinfo');
        Assert::true(!WebsiteChecker::proves('archive', "\x1f\x8b compressed html", 'text/html; charset=utf-8'), 'a gzip-compressed HTML page is not a backup');
        Assert::same(['no_https_redirect'], WebsiteChecker::analyse($resp(301, ['location' => 'http://www.x.example/'], ''), 'http')['issues'], 'redirect to another HTTP address');
        Assert::same(['no_https_redirect'], WebsiteChecker::analyse($resp(302, ['location' => '/home'], ''), 'http')['issues'], 'relative redirect stays on HTTP');
        $a = WebsiteChecker::analyse($resp(200, ['content-type' => 'text/plain'], 'x', [['set-cookie', 'outside_pref=1; Secure'], ['set-cookie', 'connect.sid=1; Secure']]), 'https');
        Assert::same(['connect.sid'], $a['cookies'] ?? [], 'only session-like names need HttpOnly');
    },
    'CMS and libraries are detected with versions from page markup only' => function (TestContext $ctx): void {
        $c = WebsiteChecker::components('<meta name="generator" content="WordPress 6.4.2"><script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>'
            . '<script src="/js/bootstrap.bundle.min.js?ver=1"></script><script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>', []);
        $byName = array_column($c, 'version', 'name');
        Assert::same(['WordPress' => '6.4.2', 'jQuery' => '3.5.1', 'Vue.js' => '2.6.14'], $byName, 'no version guessed for the unversioned Bootstrap file');
        $none = WebsiteChecker::components('<script src="https://cdn.jsdelivr.net/npm/react-bootstrap@2.7.0/dist/x.js"></script><script src="https://unpkg.com/bootstrap-vue@2.23.1/x.js"></script>'
            . '<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-moment@1.0.1/dist/x.js"></script><script src="https://unpkg.com/petite-vue@0.4.1"></script><img src="https://other.example/wp-content/uploads/a.png">', []);
        Assert::same([], $none, 'prefixed packages and hotlinked WordPress images are not detected: ' . json_encode($none));
        Assert::same(['WordPress' => ''], array_column(WebsiteChecker::components('<link href="/wp-content/themes/x/style.css">', []), 'version', 'name'));
        $joomla = \Sentinel\Vulns\Cpe::parse(WebsiteChecker::CPES['Joomla']);
        Assert::true($joomla !== null && str_contains(\Sentinel\Vulns\Cpe::matchString($joomla), 'joomla\\!'), 'Joomla CPE parses and is escaped for NVD');
        Assert::same(['Drupal' => ''], array_column(WebsiteChecker::components('<p>x</p>', ['x-generator' => 'Drupal 10 (https://www.drupal.org)']), 'version', 'name'));
    },
];
