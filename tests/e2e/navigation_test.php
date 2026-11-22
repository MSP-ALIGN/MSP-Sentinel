<?php

declare(strict_types=1);

/**
 * End-to-end tests for navigation: Administration is a separate section reached
 * from the user drop-down, with its own left menu; the main menu stays short;
 * non-admins never see admin links and can't open admin pages.
 */

use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

return [
    'administration is its own section, reached from the user menu' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $home = $admin->get('/')->body;
        $sidebar = substr($home, (int) strpos($home, '<aside'), (int) strpos($home, '</aside>') - (int) strpos($home, '<aside'));
        Assert::notContains('/admin/audit', $sidebar, 'main left menu has no admin items');
        Assert::notContains('href="/users"', $sidebar);
        Assert::contains('Reports', $sidebar);
        $dropdown = substr($home, (int) strpos($home, 'dropdown-menu'), 3000);
        foreach (['/admin"', '/users"', '/admin/settings"', '/admin/api"', '/admin/system"', '/admin/audit"'] as $href) {
            Assert::contains('href="' . $href, $dropdown, 'user menu links to ' . $href);
        }

        $over = $admin->get('/admin');
        Assert::status(200, $over);
        $adminSidebar = substr($over->body, (int) strpos($over->body, '<aside'), (int) strpos($over->body, '</aside>') - (int) strpos($over->body, '<aside'));
        Assert::contains('class="admin-mode"', $adminSidebar, 'admin section is marked');
        Assert::contains('Back to Sentinel', $adminSidebar);
        Assert::notContains('href="/clients"', $adminSidebar, 'admin menu replaces the main menu');
        Assert::true((bool) preg_match('#href="/admin" class="nav-link active"#', $adminSidebar), 'Overview active on /admin');
        $settings = $admin->get('/admin/settings')->body;
        Assert::true((bool) preg_match('#href="/admin/settings" class="nav-link active"#', $settings) && !preg_match('#href="/admin" class="nav-link active"#', $settings), 'only Settings active on settings');
        Assert::contains('class="admin-mode"', $admin->get('/users')->body, 'users pages are in the admin section');
        foreach (['Users', 'Settings', 'API', 'System', 'Audit log'] as $t) {
            Assert::contains('admin-card-title">' . $t, $over->body);
        }

        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'navtech'")->fetchColumn() === 0) {
            $ctx->createUser('navtech', 'technician', 'Navtech-Pass-01!');
        }
        $tech = $ctx->login('navtech', 'Navtech-Pass-01!');
        $page = $tech->get('/')->body;
        Assert::notContains('/admin/settings', $page, 'non-admins see no admin links');
        Assert::notContains('Administration', $page);
        Assert::status(403, $tech->get('/admin'));
        $denied = $tech->get('/admin/settings');
        Assert::status(403, $denied);
        Assert::notContains('class="admin-mode"', $denied->body, 'a refused page shows the normal menu, not the admin one');

        // Trailing slash and encoded paths get the same menu state as the router.
        $slash = $admin->get('/admin/')->body;
        Assert::true((bool) preg_match('#href="/admin" class="nav-link active" aria-current="page"#', $slash), 'Overview active on /admin/ too');
        Assert::contains('class="admin-mode"', $admin->get('/%61dmin')->body);
        Assert::contains('Help', substr($slash, (int) strpos($slash, '<aside'), 4000), 'Help reachable from the admin menu');
        Assert::notContains('role="menu"', $slash, 'plain navigation lists, not ARIA menus');
    },
];
