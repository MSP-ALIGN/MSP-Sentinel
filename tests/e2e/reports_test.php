<?php

declare(strict_types=1);

/**
 * End-to-end tests for reports: creating (roles), the frozen document and its
 * strict CSP, escaping, client isolation, accepted risks shown separately,
 * CSV export, deleting, branding (logo upload re-encoded), the monthly
 * schedule with emailed attachments, and the trend chart. Made-up data only;
 * scans use the fake nmap and mock servers on 127.0.0.1.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$setup = static function (TestContext $ctx): int {
    $id = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Reports Example'")->fetchColumn();
    if ($id > 0) {
        return $id;
    }
    $admin = $ctx->login('admin', 'Admin-Pass-0001!');
    $now = (int) gmdate('G');
    $res = $admin->submit('/clients/new', '/clients', ['name' => 'Reports Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
        'scan_window_start' => sprintf('%02d:00', ($now + 23) % 24), 'scan_window_end' => sprintf('%02d:00', ($now + 1) % 24), 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
    $cid = (int) basename((string) $res->location());
    $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
        'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
        'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '', 'scope' => '203.0.113.160', 'confirm' => '1']);
    $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
    $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
    $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
    return $cid;
};
$users = static function (TestContext $ctx): void {
    foreach ([['rtech', 'technician', 'Rtech-Pass-0001!'], ['rview', 'viewer', 'Rview-Pass-0001!']] as [$u, $role, $pw]) {
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = " . $ctx->db->quote($u))->fetchColumn() === 0) {
            $ctx->createUser($u, $role, $pw);
        }
    }
};

return [
    'technicians create reports; viewers read them but cannot create or delete' => function (TestContext $ctx) use ($setup, $users): void {
        $cid = $setup($ctx);
        $users($ctx);
        $view = $ctx->login('rview', 'Rview-Pass-0001!');
        $t = $view->get('/clients/' . $cid)->csrf();
        Assert::status(403, $view->post('/clients/' . $cid . '/reports', ['_csrf' => $t, 'kind' => 'both', 'period' => '30']));

        $tech = $ctx->login('rtech', 'Rtech-Pass-0001!');
        $rdp = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$cid} AND finding_key = 'port:203.0.113.160:3389'")->fetchColumn();
        $warn = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$cid} AND status = 'open' AND severity = 'warn' ORDER BY id LIMIT 1")->fetchColumn();
        $tech->submit('/findings/' . $warn, '/findings/' . $warn . '/triage', ['status' => 'accepted', 'note' => 'Client accepts this until the Q3 upgrade.']);
        $res = $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'both', 'period' => '30']);
        Assert::redirect('/reports?client=' . $cid, $res);
        $rows = $ctx->db->query("SELECT id, kind, generated_by, period_start, period_end FROM reports WHERE client_id = {$cid} ORDER BY id")->fetchAll();
        Assert::same(['executive', 'technical'], array_column($rows, 'kind'));
        Assert::same(gmdate('Y-m-d', time() - 29 * 86400), $rows[0]['period_start']);
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'report.created'")->fetchColumn() > 0, 'audited');
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'everything', 'period' => '30']);
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$cid}")->fetchColumn(), 'an unknown type creates nothing');
        // From the Reports page with a client picker (1.34), and staying on the client's page when created there.
        $before = (int) $ctx->db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$cid}")->fetchColumn();
        $res = $tech->submit('/reports', '/reports', ['client_id' => (string) $cid, 'kind' => 'executive', 'period' => '30']);
        Assert::true(str_starts_with((string) $res->location(), '/reports/'), 'one report: opened');
        Assert::same($before + 1, (int) $ctx->db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$cid}")->fetchColumn());
        Assert::redirect('/reports', $tech->submit('/reports', '/reports', ['client_id' => '999999', 'kind' => 'both', 'period' => '30']), 'unknown client');
        Assert::redirect('/clients/' . $cid . '/reports', $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'both', 'period' => '30', 'back' => 'client']));
        Assert::status(403, $view->post('/reports', ['_csrf' => $view->get('/reports')->csrf(), 'client_id' => (string) $cid, 'kind' => 'both', 'period' => '30']), 'viewers cannot create');
    },
    'the report document: frozen, escaped, strict CSP, accepted risks separate, no other client' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        // Another client's finding must never appear.
        $ctx->db->exec("INSERT INTO clients (name, timezone, created_at, updated_at) VALUES ('Other Example', 'UTC', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $other = (int) $ctx->db->lastInsertId();
        $ctx->db->exec("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, target, status, first_seen, last_seen)
                        VALUES ({$other}, 'port:198.51.100.77:3389', 'port', 'fail', 'OTHER-CLIENT-ONLY finding', '198.51.100.77:3389', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $tech = $ctx->login('rtech', 'Rtech-Pass-0001!');
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'technical', 'period' => '90']);
        $id = (int) $ctx->db->query("SELECT MAX(id) FROM reports WHERE client_id = {$cid} AND kind = 'technical'")->fetchColumn();
        $view = $ctx->login('rview', 'Rview-Pass-0001!');
        $doc = $view->get('/reports/' . $id . '/view');
        Assert::status(200, $doc);
        $csp = (string) $doc->header('content-security-policy');
        Assert::true(str_contains($csp, "default-src 'none'") && str_contains($csp, 'sandbox') && !str_contains($csp, 'script-src'), 'strict report CSP: ' . $csp);
        Assert::contains('Reports Example', $doc->body);
        // The level follows the dashboard's rule (1.58.2); the fixture's depends on made-up CVE data earlier tests add.
        $rows = $ctx->db->query("SELECT f.severity, f.source, (k.cve_id IS NOT NULL) AS in_kev FROM findings f
                                 LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id WHERE f.client_id = {$cid} AND f.status = 'open'")->fetchAll();
        Assert::contains(['risk' => 'At risk', 'attention' => 'Needs attention', 'good' => 'Good'][\Sentinel\Dashboard\DashboardData::rate($rows)['level']], $doc->body);
        Assert::contains('Remote Desktop open to the internet', $doc->body);
        Assert::contains('How to fix', $doc->body);
        Assert::contains('Accepted risks and false positives', $doc->body);
        Assert::contains('Client accepts this until the Q3 upgrade.', $doc->body);
        Assert::contains('not a PCI ASV scan', $doc->body);
        Assert::contains('203.0.113.160', $doc->body, 'scope listed');
        Assert::notContains('<script', $doc->body, 'scan data escaped (the fixture CVE text holds a script tag)');
        Assert::contains('&lt;script&gt;', $doc->body);
        Assert::notContains('OTHER-CLIENT-ONLY', $doc->body, 'no other client data');
        Assert::notContains('198.51.100.77', $doc->body);
        Assert::contains('The trend chart appears once', $doc->body, 'no chart before a full month is recorded');

        // Frozen: later changes don't alter it; the stored hash matches what is served.
        $ctx->db->exec("UPDATE findings SET title = 'Changed later' WHERE client_id = {$cid} AND finding_key = 'port:203.0.113.160:3389'");
        $again = $view->get('/reports/' . $id . '/view')->body;
        Assert::same($doc->body, $again);
        Assert::same(hash('sha256', $again), (string) $ctx->db->query("SELECT html_sha256 FROM reports WHERE id = {$id}")->fetchColumn());
        $ctx->db->exec("UPDATE findings SET title = 'Remote Desktop open to the internet' WHERE client_id = {$cid} AND finding_key = 'port:203.0.113.160:3389'");

        // Executive summary: plain-English top risks.
        $exec = (int) $ctx->db->query("SELECT MIN(id) FROM reports WHERE client_id = {$cid} AND kind = 'executive'")->fetchColumn();
        $body = $view->get('/reports/' . $exec . '/view')->body;
        Assert::contains('Top risks', $body);
        Assert::contains('What it means for you', $body);
        Assert::true(substr_count($body, 'class="risk ') <= 5, 'at most 5 top risks');
        Assert::status(404, $view->get('/reports/999999/view'));
    },
    'the rating matches the dashboard: same score and level in the report, its page and the API (1.58.2)' => function (TestContext $ctx) use ($users): void {
        $users($ctx);
        // A client with made-up findings only (no scan): each step adds findings and checks all three places agree.
        $ctx->db->exec("INSERT INTO clients (name, timezone, created_at, updated_at) VALUES ('Rating Match Example', 'UTC', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $cid = (int) $ctx->db->lastInsertId();
        $ctx->db->exec("INSERT IGNORE INTO kev_catalog (cve_id, vendor, product, name) VALUES ('CVE-2099-0588', 'Example', 'Example', 'Made-up test entry')");
        $add = static function (string $key, string $sev, string $source, ?string $cve = null) use ($ctx, $cid): void {
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, target, status, source, cve_id, first_seen, last_seen)
                               VALUES (:c, :k, 'port', :s, :t, '203.0.113.188:1', 'open', :src, :cve, UTC_TIMESTAMP(), UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 'k' => $key, 's' => $sev, 't' => 'Rating test ' . $key, 'src' => $source, 'cve' => $cve]);
        };
        $plain = App::apiTokens()->create('Rating token', false, [$cid], false, false, [], 30,
            (int) $ctx->db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn())[1];
        $ctx->db->exec("DELETE FROM auth_throttle");
        $view = $ctx->login('rview', 'Rview-Pass-0001!');
        $check = static function (int $score, string $level, string $words, string $reason) use ($ctx, $cid, $plain, $view): void {
            $dash = (new \Sentinel\Dashboard\DashboardData($ctx->db, App::settings()))->clients($cid)[0];
            Assert::same([$score, $level], [$dash['score'], $dash['level']], 'dashboard');
            $id = App::reportService()->generate(App::clients()->find($cid), 'executive', gmdate('Y-m-d', time() - 29 * 86400), gmdate('Y-m-d'), null, 'Test');
            $snap = json_decode((string) $ctx->db->query("SELECT snapshot FROM reports WHERE id = {$id}")->fetchColumn(), true);
            Assert::same([$score, $level], [$snap['rating']['score'], $snap['rating']['level']], 'report snapshot');
            $doc = $view->get('/reports/' . $id . '/view')->body;
            Assert::contains($words, $doc);
            Assert::contains($reason, $doc);
            Assert::contains('Risk score ' . $score . ' of 100', $doc);
            Assert::contains('Risk score ' . $score . ' of 100', $view->get('/reports/' . $id)->body, 'report page shows the score');
            $sum = json_decode($ctx->api('GET', '/api/v1/clients/' . $cid . '/summary', $plain)->body, true)['data'];
            Assert::same([$score, ['risk' => 'at_risk', 'attention' => 'needs_attention', 'good' => 'good'][$level]], [$sum['score'], $sum['rating']], 'API summary');
        };
        try {
            $add('w1', 'warn', 'external');
            $add('w2', 'warn', 'external');
            $add('w3', 'warn', 'external');
            $check(10, 'good', 'Good', '3 minor item(s) are listed in this report');   // used to be "Needs attention" in reports
            $add('f1', 'fail', 'agent');
            $check(15, 'attention', 'Needs attention', '1 serious problem(s) should be fixed soon');
            $add('k1', 'fail', 'external', 'CVE-2099-0588');
            $check(39, 'risk', 'At risk', '1 known-exploited weakness(es) can be reached from the internet');
            // Warnings alone can reach At risk (21 on the internet = 42 points = 50): the reason names them.
            $ctx->db->exec("DELETE FROM findings WHERE client_id = {$cid}");
            for ($i = 1; $i <= 21; $i++) {
                $add('many' . $i, 'warn', 'external');
            }
            $check(50, 'risk', 'At risk', 'No serious problems, but 21 item(s) together put the client at risk');
        } finally {
            // Cleaned up even when a check fails, so a rerun starts clean.
            $ctx->db->exec("DELETE FROM reports WHERE client_id = {$cid}");
            $ctx->db->exec("DELETE FROM findings WHERE client_id = {$cid}");
            $ctx->db->exec("DELETE FROM api_tokens WHERE name = 'Rating token'");
            $ctx->db->exec("DELETE FROM clients WHERE id = {$cid}");
        }
    },
    'downloads: HTML and CSV with safe names; CSV formulas neutralised' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $id = (int) $ctx->db->query("SELECT MIN(id) FROM reports WHERE client_id = {$cid} AND kind = 'technical'")->fetchColumn();
        $view = $ctx->login('rview', 'Rview-Pass-0001!');
        $dl = $view->get('/reports/' . $id . '/download');
        Assert::true((bool) preg_match('/^attachment; filename="report-' . $id . '-technical-\d{4}-\d{2}-\d{2}\.html"$/', (string) $dl->header('content-disposition')), 'safe file name');
        $csv = $view->get('/reports/' . $id . '/csv');
        Assert::contains('text/csv', (string) $csv->header('content-type'));
        $lines = array_map('str_getcsv', preg_split('/\r?\n/', trim(substr($csv->body, 3))));
        Assert::same('status', $lines[0][0]);
        Assert::true(count(array_filter($lines, static fn (array $l): bool => ($l[3] ?? '') === 'Remote Desktop open to the internet')) === 1, 'RDP row present');
        Assert::true(count(array_filter($lines, static fn (array $l): bool => ($l[0] ?? '') === 'accepted')) >= 1, 'accepted rows included');
    },
    'admins delete reports (audited); others cannot' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $id = (int) $ctx->db->query("SELECT MAX(id) FROM reports WHERE client_id = {$cid}")->fetchColumn();
        $tech = $ctx->login('rtech', 'Rtech-Pass-0001!');
        Assert::status(403, $tech->post('/reports/' . $id . '/delete', ['_csrf' => $tech->get('/reports/' . $id)->csrf()]));
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('Delete report', $admin->get('/reports/' . $id)->body);
        Assert::redirect('/reports', $admin->submit('/reports/' . $id, '/reports/' . $id . '/delete', []));
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM reports WHERE id = {$id}")->fetchColumn());
        Assert::contains('"sha256"', (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'report.deleted' ORDER BY id DESC LIMIT 1")->fetchColumn());
    },
    'branding: logo is checked and re-encoded, applies to new reports only' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $old = (int) $ctx->db->query("SELECT MIN(id) FROM reports WHERE client_id = {$cid}")->fetchColumn();
        $oldHtml = (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$old}")->fetchColumn();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $dir = sys_get_temp_dir() . '/sentinel-test-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $img = imagecreatetruecolor(800, 200);
        imagefill($img, 0, 0, imagecolorallocate($img, 31, 78, 121));
        imagepng($img, $dir . '/logo.png');
        file_put_contents($dir . '/logo.png', "trailing-junk-after-image", FILE_APPEND);
        file_put_contents($dir . '/fake.png', "<?php echo 'not an image';");
        $fields = ['brand_name' => 'Example MSP Ltd', 'brand_color' => '#7a1f5c', 'brand_footer' => "Example MSP · support@msp.example\n555-0100", 'report_paper' => 'Letter', 'report_powered_by' => '1',
            // The branding suite (1.59).
            'brand_accent' => '#2b8a3e', 'report_cover' => 'white', 'brand_address' => "1 Example Road\nExample Town", 'brand_phone' => '555-0199',
            'brand_email' => 'hello@msp.example', 'brand_website' => 'www.msp.example', 'report_prepared_by' => 'Sam Example', 'report_prepared_title' => 'Security lead',
            'report_signoff' => "Thank you.\n<b>Not bold</b>", 'report_confidential' => 'Private for {client} "quoted" </style><script>'];

        $admin->upload('/admin/settings', '/admin/branding', $fields, 'brand_logo', $dir . '/fake.png', 'image/png');
        Assert::contains('PNG or JPEG image', $admin->get('/admin/settings')->body, 'a non-image is refused');
        $admin->submit('/admin/settings', '/admin/branding', ['brand_color' => 'red;}body{display:none'] + $fields);
        Assert::contains('The color must look like', $admin->get('/admin/settings')->body);
        // Every new field is checked: accent color, cover style, email, website, line breaks in one-line fields, lengths.
        foreach ([['brand_accent' => 'blue'], ['report_cover' => 'neon'], ['brand_email' => 'not-an-address'], ['brand_website' => 'javascript:alert(1)'],
                  ['report_prepared_by' => "Sam\nExample"], ['brand_logo_bg' => 'transparent'], ['report_confidential' => str_repeat('x', 121)], ['report_signoff' => str_repeat('x', 601)]] as $bad) {
            $admin->submit('/admin/settings', '/admin/branding', $bad + $fields);
            Assert::true(App::settings()->fresh('brand_name') !== 'Example MSP Ltd', 'refused: ' . json_encode($bad));
        }

        $admin->upload('/admin/settings', '/admin/branding', $fields, 'brand_logo', $dir . '/logo.png', 'image/png');
        $hash = App::settings()->fresh('brand_logo');
        Assert::true((bool) preg_match('/^[a-f0-9]{64}$/', $hash), 'logo stored');
        $stored = SENTINEL_ROOT . '/storage/branding/logo-' . $hash . '.png';
        $size = getimagesize($stored);
        Assert::same([600, 150], [$size[0], $size[1]], 'scaled to fit 600x200');
        Assert::notContains('trailing-junk', (string) file_get_contents($stored), 're-encoded: extra bytes dropped');
        Assert::contains('data:image/png;base64,', $admin->get('/admin/settings')->body, 'preview shown');
        Assert::same('settings.branding_updated', $ctx->db->query("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")->fetchColumn());

        $tech = $ctx->login('rtech', 'Rtech-Pass-0001!');
        Assert::status(403, $tech->post('/admin/branding', ['_csrf' => $tech->get('/')->csrf()] + $fields));
        // The preview (1.59): made-up data with the saved branding, strict report CSP, admins only.
        foreach (['executive' => 'Security summary', 'technical' => 'Technical findings'] as $kind => $title) {
            $pre = $admin->get('/admin/branding/preview?kind=' . $kind);
            Assert::status(200, $pre);
            Assert::contains($title, $pre->body);
            Assert::contains('Example Client Co.', $pre->body);
            Assert::contains('Sam Example', $pre->body);
            Assert::contains("default-src 'none'", (string) $pre->header('content-security-policy'));
        }
        Assert::status(403, $tech->get('/admin/branding/preview'));
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'executive', 'period' => 'month']);
        $new = (string) $ctx->db->query("SELECT html FROM reports WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::contains('Example MSP Ltd', $new);
        Assert::contains('--brand: #7a1f5c', $new);
        Assert::contains('size: Letter', $new);
        Assert::contains('data:image/png;base64,', $new);
        Assert::contains('Generated by MSP Sentinel', $new);
        // The branding suite (1.59): cover, contact block, sign-off, accent; the label is in the page margins as a CSS
        // string with every special character escaped, so it can't break out of the stylesheet.
        Assert::contains('class="cover white"', $new);
        Assert::contains('--accent: #2b8a3e', $new);
        foreach (['1 Example Road', 'Example Town', '555-0199', 'hello@msp.example', 'www.msp.example', 'Sam Example', 'Security lead', 'Thank you.', '&lt;b&gt;Not bold&lt;/b&gt;'] as $want) {
            Assert::contains($want, $new);
        }
        Assert::contains('Private for Reports Example &quot;quoted&quot; &lt;/style&gt;&lt;script&gt;', $new, 'confidential label on the cover, escaped');
        Assert::contains('content: "Private for Reports Example \\000022 quoted\\000022  \\00003C \\00002F style\\00003E ', $new, 'label in the page margin as an escaped CSS string');
        Assert::same(1, substr_count($new, '</style>'), 'the label never closes the stylesheet');
        Assert::notContains('<script', $new);
        Assert::same($oldHtml, (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$old}")->fetchColumn(), 'saved reports keep their branding');
        // White-label: the "Generated by" line can be turned off.
        $admin->submit('/admin/settings', '/admin/branding', ['report_powered_by' => '0'] + $fields);
        App::settings()->set('report_powered_by', App::settings()->fresh('report_powered_by'));
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'executive', 'period' => 'month']);
        Assert::notContains('Generated by MSP Sentinel', (string) $ctx->db->query("SELECT html FROM reports WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetchColumn());
        // A logo that includes the company name (1.60): the cover shows the logo alone; the name stays in the sign-off.
        Assert::contains('<span class="bname">Example MSP Ltd</span>', $new, 'by default the name sits beside the logo');
        $admin->submit('/admin/settings', '/admin/branding', ['brand_logo_has_name' => '1'] + $fields);
        Assert::same('1', App::settings()->fresh('brand_logo_has_name'));
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'executive', 'period' => 'month']);
        $logoOnly = (string) $ctx->db->query("SELECT html FROM reports WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::contains('class="brandrow logo-only"', $logoOnly);
        Assert::notContains('class="bname"', $logoOnly);
        Assert::contains('<div class="contact"><b>Example MSP Ltd</b>', $logoOnly, 'the name is still in the contact block');
        Assert::contains('<br><span class="small muted">Example MSP Ltd</span>', $logoOnly, 'and in the sign-off');
        App::settings()->set('brand_logo_has_name', '0'); // back to the default for later tests
        array_map('unlink', glob($dir . '/*'));
        rmdir($dir);
    },
    'monthly schedule: once per month, emailed to MSP staff with both reports attached' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/report-schedule', ['report_monthly' => '1', 'report_recipients' => "ok@msp.example, bad\r\nBcc: x@evil.example"]);
        Assert::contains('Report recipients', $ctx->clientSection($admin, (int) $cid, 'reports'));
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/report-schedule', ['report_monthly' => '1', 'report_recipients' => '']);
        Assert::contains('at least one recipient', $ctx->clientSection($admin, (int) $cid, 'reports'));
        $tech = $ctx->login('rtech', 'Rtech-Pass-0001!');
        Assert::status(403, $tech->post('/clients/' . $cid . '/report-schedule', ['_csrf' => $tech->get('/')->csrf(), 'report_monthly' => '0']));
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/report-schedule', ['report_monthly' => '1', 'report_recipients' => 'accounts@msp.example']);
        Assert::same(['1', 'accounts@msp.example'], array_map('strval', $ctx->db->query("SELECT report_monthly, report_recipients FROM clients WHERE id = {$cid}")->fetch(PDO::FETCH_NUM)));

        $s = App::settings();
        foreach (['email_enabled' => '1', 'smtp_host' => '127.0.0.1', 'smtp_port' => (string) $ctx->smtpPlainPort, 'smtp_security' => 'none', 'smtp_from' => 'sentinel@msp.example'] as $k => $v) {
            $s->set($k, $v);
        }
        $before = count($ctx->mails());
        Assert::true(App::reportService()->runMonthly() >= 1, 'due this month');
        $sched = $ctx->db->query("SELECT id, kind, period_start, period_end FROM reports WHERE client_id = {$cid} AND source = 'scheduled'")->fetchAll();
        Assert::same(['executive', 'technical'], array_column($sched, 'kind'));
        Assert::same(gmdate('Y-m-01', strtotime('first day of last month')), $sched[0]['period_start']);
        App::reportService()->runMonthly();
        Assert::same(2, (int) $ctx->db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$cid} AND source = 'scheduled'")->fetchColumn(), 'never twice for one month');
        App::outbox()->flush(50);
        $mails = array_values(array_filter(array_slice($ctx->mails(), $before), static fn (array $m): bool => in_array('accounts@msp.example', $m['to'], true)));
        Assert::same(1, count($mails), 'one email to the MSP recipient');
        Assert::contains('Monthly security reports', $mails[0]['subject']);
        Assert::same(2, substr_count($mails[0]['raw'], 'Content-Disposition: attachment; filename="report-'), 'both reports attached');
        Assert::contains('multipart/mixed', $mails[0]['raw']);
        // Branded HTML version (1.59) next to the plain text, with the logo inline when one is set.
        Assert::contains('multipart/alternative', $mails[0]['raw']);
        Assert::contains('Content-Type: text/html; charset=UTF-8', $mails[0]['raw']);
        Assert::contains('Monthly', $admin->get('/reports?client=' . $cid)->body);
    },
    'monthly schedule: a failing client is isolated, retried hourly, admins told; deleted reports are not remade' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        $db = $ctx->db;
        // The failing client comes first (lower ID); a later client must still get its reports.
        $bad = $cid;
        $db->exec("INSERT INTO clients (name, timezone, report_monthly, report_recipients, created_at, updated_at) VALUES ('Monthly Good Example', 'UTC', 1, 'accounts@msp.example', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $good = (int) $db->lastInsertId();
        $db->exec("UPDATE clients SET report_monthly = 1, report_recipients = 'accounts@msp.example' WHERE id = {$bad}");
        // Make saving this client's TECHNICAL report fail (after its executive report was saved): nothing may be kept.
        $db->exec("DROP TRIGGER IF EXISTS test_fail_report");
        $db->exec("CREATE TRIGGER test_fail_report BEFORE INSERT ON reports FOR EACH ROW
                   BEGIN IF NEW.client_id = {$bad} AND NEW.kind = 'technical' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'test failure'; END IF; END");
        $when = new DateTimeImmutable('2027-03-05 01:00:00', new DateTimeZone('UTC'));
        $notesBefore = (int) $db->query("SELECT COUNT(*) FROM notifications WHERE kind = 'report_failed'")->fetchColumn();
        App::reportService()->runMonthly($when);
        $run = $db->query("SELECT status, attempts FROM report_runs WHERE client_id = {$bad} AND period_start = '2027-02-01'")->fetch();
        Assert::same(['failed', 1], [$run['status'], (int) $run['attempts']]);
        Assert::same('done', $db->query("SELECT status FROM report_runs WHERE client_id = {$good} AND period_start = '2027-02-01'")->fetchColumn(), 'the next client still got its reports');
        Assert::true((int) $db->query("SELECT COUNT(*) FROM notifications WHERE kind = 'report_failed'")->fetchColumn() > $notesBefore, 'admins told');
        App::reportService()->runMonthly($when);
        Assert::same(1, (int) $db->query("SELECT attempts FROM report_runs WHERE client_id = {$bad} AND period_start = '2027-02-01'")->fetchColumn(), 'not retried within the hour');
        $db->exec("UPDATE report_runs SET last_attempt_at = UTC_TIMESTAMP() - INTERVAL 2 HOUR WHERE client_id = {$bad}");
        App::reportService()->runMonthly($when);
        Assert::same(2, (int) $db->query("SELECT attempts FROM report_runs WHERE client_id = {$bad} AND period_start = '2027-02-01'")->fetchColumn(), 'retried after an hour');
        Assert::same(0, (int) $db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$bad} AND period_start = '2027-02-01'")->fetchColumn(), 'nothing half-made: the executive report was rolled back too');
        $db->exec("DROP TRIGGER test_fail_report");
        $db->exec("UPDATE clients SET report_monthly = 0, report_recipients = '' WHERE id IN ({$bad}, {$good})");

        // An admin deletes the month's reports: they are not created and emailed again.
        Assert::contains('data:image/png', (string) $db->query("SELECT html FROM reports WHERE client_id = {$good} ORDER BY id DESC LIMIT 1")->fetchColumn(), 'logo in the document');
        Assert::notContains('data:image/png', (string) $db->query("SELECT snapshot FROM reports WHERE client_id = {$good} ORDER BY id DESC LIMIT 1")->fetchColumn(), 'but not stored twice');
        $db->exec("DELETE FROM reports WHERE client_id = {$good} AND period_start = '2027-02-01'");
        $db->exec("UPDATE clients SET report_monthly = 1, report_recipients = 'accounts@msp.example' WHERE id = {$good}");
        App::reportService()->runMonthly($when);
        Assert::same(0, (int) $db->query("SELECT COUNT(*) FROM reports WHERE client_id = {$good} AND period_start = '2027-02-01'")->fetchColumn());
        $db->exec("UPDATE clients SET report_monthly = 0, report_recipients = '' WHERE id = {$good}");
        $logo = glob(SENTINEL_ROOT . '/storage/branding/logo-*.png') ?: [];
        Assert::same(1, count($logo), 'old logos removed');
        Assert::same('0640', substr(sprintf('%o', fileperms($logo[0])), -4), 'group-readable for the worker');
    },
    'trend chart uses recorded monthly counts' => function (TestContext $ctx) use ($setup): void {
        $cid = $setup($ctx);
        (new \Sentinel\Reports\StatsRecorder($ctx->db))->recordToday(true);
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM finding_stats WHERE client_id = {$cid} AND day = UTC_DATE()")->fetchColumn());
        $ctx->db->exec("INSERT IGNORE INTO finding_stats (client_id, day, fail_open, warn_open) VALUES
            ({$cid}, LAST_DAY(UTC_DATE() - INTERVAL 2 MONTH), 7, 3), ({$cid}, LAST_DAY(UTC_DATE() - INTERVAL 1 MONTH), 4, 9)");
        $tech = $ctx->login('rtech', 'Rtech-Pass-0001!');
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'executive', 'period' => '90']);
        $html = (string) $ctx->db->query("SELECT html FROM reports WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::contains(gmdate('M Y', strtotime('last day of -2 month')), $html);
        Assert::contains('<polyline', $html);
        Assert::contains('>9</text>', $html);
    },
];
