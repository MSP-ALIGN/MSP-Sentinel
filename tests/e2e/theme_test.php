<?php

declare(strict_types=1);

/**
 * End-to-end tests for the console theme: dark by default, a per-user light
 * choice (CSRF-checked, fixed values), local fonts and logo, and the strict
 * CSP still in force (no outside font or style hosts).
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'dark by default, light per user, nothing loaded from other sites' => function (TestContext $ctx): void {
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'themeuser'")->fetchColumn() === 0) {
            $ctx->createUser('themeuser', 'viewer', 'Themeuser-Pass-1!');
        }
        $login = $ctx->client()->get('/login');
        Assert::contains('data-bs-theme="dark"', $login->body, 'sign-in page is dark');
        Assert::contains('img/logo.svg', $login->body);
        $u = $ctx->login('themeuser', 'Themeuser-Pass-1!');
        $page = $u->get('/');
        Assert::contains('<html lang="en" data-bs-theme="dark" ', $page->body, 'dark by default');
        Assert::contains('css/theme.css', $page->body);
        Assert::notContains('fonts.googleapis', $page->body, 'no outside font host');
        Assert::contains("font-src 'self'", (string) $page->header('content-security-policy'), 'CSP unchanged');

        $u->submit('/profile', '/profile/theme', ['ui_theme' => 'light']);
        Assert::contains('<html lang="en" data-bs-theme="light" ', $u->get('/')->body, 'light chosen');
        Assert::same('{"ui_theme":"light"}', (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'user.ui_theme' ORDER BY id DESC LIMIT 1")->fetchColumn(), 'audited');
        $u->submit('/profile', '/profile/theme', ['ui_theme' => '"><script>alert(1)</script>']);
        Assert::same('light', $ctx->db->query("SELECT ui_theme FROM users WHERE username = 'themeuser'")->fetchColumn(), 'only dark or light accepted');
        Assert::status(400, $u->post('/profile/theme', ['ui_theme' => 'dark']), 'CSRF-checked');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $home = $admin->get('/')->body;
        Assert::contains('data-bs-theme="dark"', $home, 'one user\'s choice does not affect others');
        Assert::true((bool) preg_match('/class="brand-link" title="[^"]+"/', $home), 'full product name on hover (long names are shortened)');

        foreach (['/assets/img/logo.svg' => 'image/svg', '/assets/css/theme.css' => 'text/css', '/assets/vendor/fonts/chakra-petch-600.woff2' => ''] as $path => $type) {
            $res = $ctx->client()->get($path);
            Assert::same(200, $res->status, $path);
            if ($type !== '') {
                Assert::contains($type, (string) $res->header('content-type'), $path);
            }
        }
        $svg = (string) file_get_contents(dirname(__DIR__, 2) . '/public/assets/img/logo.svg');
        Assert::notContains('<script', $svg, 'logo has no script');
        Assert::notContains('href="http', $svg, 'logo loads nothing from elsewhere');
    },
];
