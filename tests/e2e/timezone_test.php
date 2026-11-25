<?php

declare(strict_types=1);

/**
 * End-to-end tests for time zones (1.48): times are stored in UTC and shown in the organisation's time zone (Settings)
 * or the user's own (My profile); new clients, also from ITFlow, start in the organisation's zone; clients still on UTC
 * can be moved once; reports show their client's zone. Made-up names and documentation addresses only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

/** Put the organisation's zone and clients back, whatever happened in a test (1.48.1). */
$restore = static function (TestContext $ctx, array $utcClientIds = []): void {
    App::settings()->set('display_timezone', 'UTC');
    $ctx->db->exec("UPDATE users SET timezone = '' WHERE username = 'admin'");
    foreach ($utcClientIds as $id) {
        $ctx->db->exec('UPDATE clients SET timezone = \'UTC\' WHERE id = ' . (int) $id);
    }
};

return [
    'time zones (1.48): when() shows a stored UTC time in a zone, labeled; bad values pass through' => function (TestContext $ctx): void {
        $la = new DateTimeZone('America/Los_Angeles');
        Assert::same('2026-01-15 13:33 PST', when('2026-01-15 21:33:00', $la), 'winter');
        Assert::same('2026-07-15 14:33 PDT', when('2026-07-15 21:33:00', $la), 'summer: daylight saving');
        Assert::same('2026-01-15 16:33:05 EST', when('2026-01-15 21:33:05', new DateTimeZone('America/New_York'), '–', true), 'with seconds');
        Assert::same('–', when(null, $la));
        Assert::same('never', when('', $la, 'never'));
        Assert::same('not a date', when('not a date', $la), 'anything else is shown as it is');
        Assert::same('2026-01-15 13:33 PST', when('2026-01-15T21:33:00.123Z', $la), 'ISO with fractions and Z');
        Assert::true(valid_timezone('America/Los_Angeles') && !valid_timezone('Mars/Olympus_Mons') && !valid_timezone(''), 'real zones accepted (and any older aliases PHP knows), made-up names not');
    },
    'time zones (1.48): the organization\'s zone is shown everywhere, each user may pick their own' => function (TestContext $ctx) use ($restore): void {
        try {
        $s = App::settings();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $adminId = (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        $ctx->db->prepare("INSERT INTO notifications (user_id, kind, severity, title, body, link, created_at) VALUES (:u, 'security', 'info', 'Time zone test notice', '', '/', '2026-01-15 21:33:00')")
            ->execute(['u' => $adminId]);
        Assert::contains('2026-01-15 21:33 UTC', $admin->get('/notifications')->body, 'UTC by default, labeled');
        // A zone that isn't in the list is refused; a real one is saved.
        $base = ['product_name' => $s->get('product_name'), 'source_url' => $s->get('source_url')];
        Assert::status(422, $admin->submit('/admin/settings', '/admin/settings', $base + ['display_timezone' => 'Mars/Olympus_Mons']));
        Assert::same('UTC', $s->fresh('display_timezone'));
        $admin->submit('/admin/settings', '/admin/settings', $base + ['display_timezone' => 'America/Los_Angeles']);
        Assert::same('America/Los_Angeles', $s->fresh('display_timezone'));
        Assert::contains('2026-01-15 13:33 PST', $admin->get('/notifications')->body, 'shown in the organization\'s zone');
        Assert::contains((new DateTimeImmutable('now', new DateTimeZone('America/Los_Angeles')))->format('T'), $admin->get('/admin/audit')->body, 'audit log in the zone');
        // My profile: my own zone, then back to the organisation's.
        $admin->submit('/profile', '/profile/timezone', ['timezone' => 'Nowhere/Land']);
        Assert::same('', (string) $ctx->db->query("SELECT timezone FROM users WHERE id = {$adminId}")->fetchColumn(), 'invalid zone refused');
        $admin->submit('/profile', '/profile/timezone', ['timezone' => 'America/New_York']);
        Assert::contains('2026-01-15 16:33 EST', $admin->get('/notifications')->body, 'shown in my own zone');
        $admin->submit('/profile', '/profile/timezone', ['timezone' => '']);
        Assert::contains('2026-01-15 13:33 PST', $admin->get('/notifications')->body, 'empty: the organization\'s again');
        // A missing field (an older form) keeps the zone.
        $admin->submit('/admin/settings', '/admin/settings', $base);
        Assert::same('America/Los_Angeles', $s->fresh('display_timezone'), 'missing field: unchanged');
        } finally {
            $restore($ctx);
        }
    },
    'time zones (1.48): new clients start in the organization\'s zone; clients on UTC can be moved once' => function (TestContext $ctx) use ($restore): void {
        // Other tests' clients on UTC are put back afterwards, so later tests keep their windows.
        $othersOnUtc = array_map('intval', $ctx->db->query("SELECT id FROM clients WHERE timezone = 'UTC'")->fetchAll(PDO::FETCH_COLUMN));
        try {
        $s = App::settings();
        $s->set('display_timezone', 'America/Los_Angeles');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('value="America/Los_Angeles"', $admin->get('/clients/new')->body, 'new client form starts in the organization\'s zone');
        // Made by the ITFlow sync: the organisation's zone too.
        $base = str_replace('/ninja', '/itflow', (string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
        file_put_contents(dirname($ctx->feedsLog) . '/itflow-clients.json', json_encode([['client_id' => 880, 'client_name' => 'Pacific Example Co', 'client_archived_at' => null, 'client_updated_at' => '2026-11-22 10:00:00']]));
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base, 'api_key' => 'itflow-test-key-0123456789abcdef', 'enabled' => '1']);
        App::itflowSync()->sync();
        Assert::same('America/Los_Angeles', (string) $ctx->db->query('SELECT timezone FROM clients WHERE itflow_client_id = 880')->fetchColumn(), 'ITFlow client in the organization\'s zone');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base, 'api_key' => 'itflow-test-key-0123456789abcdef', 'enabled' => '0']);
        // Clients still on UTC: listed, and moved by the button (window times kept).
        $ctx->db->exec("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, created_at, updated_at)
                        VALUES ('Still UTC Example', 'UTC', '10:00:00', '12:00:00', '', '', '', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $page = $admin->get('/admin/settings')->body;
        Assert::contains('Clients still on UTC', $page);
        Assert::contains('Still UTC Example', $page);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'tztech'")->fetchColumn() === 0) {
            $ctx->createUser('tztech', 'technician', 'Tztech-Pass-00001!');
        }
        $tech = $ctx->login('tztech', 'Tztech-Pass-00001!');
        Assert::status(403, $tech->post('/admin/settings/clients-timezone', ['_csrf' => $tech->get('/')->csrf()]), 'technicians cannot');
        // Manage settings without Edit clients: refused by the action itself.
        $admin->submit('/admin/roles/new', '/admin/roles', ['name' => 'Settings only', 'my_password' => 'Admin-Pass-0001!', 'permissions[0]' => 'settings.manage']);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'tzsettings'")->fetchColumn() === 0) {
            $ctx->createUser('tzsettings', 'Settings only', 'Tzsettings-Pass-01!');
        }
        $so = $ctx->login('tzsettings', 'Tzsettings-Pass-01!');
        Assert::status(403, $so->post('/admin/settings/clients-timezone', ['_csrf' => $so->get('/admin/settings')->csrf()]), 'needs Edit clients too');
        Assert::notContains('Clients still on UTC', $so->get('/admin/settings')->body, 'not offered without Edit clients');
        $admin->submit('/admin/settings', '/admin/settings/clients-timezone', []);
        $row = $ctx->db->query("SELECT timezone, scan_window_start FROM clients WHERE name = 'Still UTC Example'")->fetch();
        Assert::same(['America/Los_Angeles', '10:00:00'], [$row['timezone'], $row['scan_window_start']], 'moved, window times kept');
        Assert::contains('Still UTC Example', (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'clients.timezone_moved' ORDER BY id DESC LIMIT 1")->fetchColumn(), 'audited with the names');
        Assert::notContains('Clients still on UTC', $admin->get('/admin/settings')->body, 'nothing left to move');
        // After a failed save the button still names the stored zone, which is the one it uses.
        $s->set('display_timezone', 'America/Los_Angeles');
        $ctx->db->exec("UPDATE clients SET timezone = 'UTC' WHERE name = 'Still UTC Example'");
        $page = $admin->submit('/admin/settings', '/admin/settings', ['product_name' => $s->get('product_name'), 'source_url' => 'not a url', 'display_timezone' => 'Europe/Berlin'])->body;
        Assert::contains('Move 1 client(s) to America/Los_Angeles', $page, 'the stored zone, not the one just typed');
        $ctx->db->exec("UPDATE clients SET timezone = 'America/Los_Angeles' WHERE name = 'Still UTC Example'");
        } finally {
            $restore($ctx, $othersOnUtc);
        }
    },
    'time zones (1.48): a report shows its client\'s time zone' => function (TestContext $ctx) use ($restore): void {
        $restore($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $ctx->db->exec("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, created_at, updated_at)
                        VALUES ('Eastern Report Example', 'America/New_York', '22:00:00', '06:00:00', '', '', '', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Eastern Report Example'")->fetchColumn();
        $admin->post('/reports', ['_csrf' => $admin->get('/reports')->csrf(), 'client_id' => (string) $cid, 'kind' => 'executive', 'period' => '30']);
        $html = (string) $ctx->db->query("SELECT html FROM reports WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::true($html !== '', 'report made');
        $label = (new DateTimeImmutable('now', new DateTimeZone('America/New_York')))->format('T');
        Assert::true(preg_match('/Generated \d{4}-\d\d-\d\d \d\d:\d\d ' . $label . '/', $html) === 1, 'generated time in the client\'s zone (' . $label . ')');
    },
];
