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
    'client pages: one page per section, with the client menu in the sidebar' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $id = (int) $ctx->db->query('SELECT id FROM clients WHERE is_archived = 0 ORDER BY id LIMIT 1')->fetchColumn();
        Assert::true($id > 0, 'a client exists');
        foreach (\Sentinel\Controllers\ClientController::SECTIONS as $section) {
            $path = '/clients/' . $id . ($section === 'overview' ? '' : '/' . $section);
            $res = $admin->get($path);
            Assert::same(200, $res->status, $path);
            Assert::contains('aria-label="Client sections"', $res->body, "{$path}: client menu");
            Assert::contains('All clients', $res->body, "{$path}: way back");
            Assert::true((bool) preg_match('#href="' . preg_quote($path, '#') . '" class="nav-link active" aria-current="page"#', $res->body), "{$path}: its own item is active");
            // 1.51: Dashboard, all findings and Help stay reachable; the heading is the section, the tab names the client.
            foreach (['href="/" class="nav-link"', 'href="/findings" class="nav-link"', 'href="/help" class="nav-link"'] as $link) {
                Assert::contains($link, $res->body, "{$path}: main pages kept ({$link})");
            }
            $label = \Sentinel\Controllers\ClientController::sectionLabel($section);
            Assert::contains('<h1 class="h3 mb-0">' . e($label) . '</h1>', $res->body, "{$path}: heading is the section");
            Assert::true((bool) preg_match('#<title>[^<]+ · ' . preg_quote(e($label), '#') . ' · #', $res->body), "{$path}: tab reads Client · Section");
            Assert::true((bool) preg_match('#class="nav-link( active)?"( aria-current="page")?>\s*<i class="nav-icon bi [^"]+" aria-hidden="true"></i><p>' . preg_quote(e($label), '#') . '#', $res->body), "{$path}: menu label matches the heading");
        }
        // A finding's own page keeps its client's menu (1.51).
        $fid = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$id} LIMIT 1")->fetchColumn();
        if ($fid > 0) {
            Assert::contains('aria-label="Client sections"', $admin->get('/findings/' . $fid)->body, 'finding page: client menu');
        }
        // Each section shows only itself: discovery isn't on the findings page, and so on.
        Assert::notContains('Discover now', $admin->get('/clients/' . $id . '/findings')->body);
        Assert::status(404, $admin->get('/clients/' . $id . '/nonsense'));
        Assert::status(404, $admin->get('/clients/999999/findings'));
        // Pages about the client (edit form, new authorisation) keep its menu; the client list doesn't.
        Assert::contains('aria-label="Client sections"', $admin->get('/clients/' . $id . '/edit')->body);
        Assert::contains('aria-label="Client sections"', $admin->get('/clients/' . $id . '/authorisations/new')->body);
        Assert::notContains('aria-label="Client sections"', $admin->get('/clients')->body);
        // Viewers get the same pages.
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'navview'")->fetchColumn() === 0) {
            $ctx->createUser('navview', 'viewer', 'Navview-Pass-01!');
        }
        $view = $ctx->login('navview', 'Navview-Pass-01!');
        Assert::contains('aria-label="Client sections"', $view->get('/clients/' . $id . '/devices')->body);
    },
    'administration is its own section, reached from the user menu' => function (TestContext $ctx): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $home = $admin->get('/')->body;
        $sidebar = substr($home, (int) strpos($home, '<aside'), (int) strpos($home, '</aside>') - (int) strpos($home, '<aside'));
        Assert::notContains('/admin/audit', $sidebar, 'main left menu has no admin items');
        Assert::notContains('href="/users"', $sidebar);
        Assert::contains('Reports', $sidebar);
        $dropdown = substr($home, (int) strpos($home, 'dropdown-menu'), 3000);
        // 1.51: one Administration entry (its own menu lists the rest), and Help.
        foreach (['/admin"', '/help"', '/profile"'] as $href) {
            Assert::contains('href="' . $href, $dropdown, 'user menu links to ' . $href);
        }
        Assert::notContains('href="/admin/audit"', $dropdown, 'admin pages are not repeated in the user menu');

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
