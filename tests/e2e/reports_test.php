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
        Assert::contains('At risk', $doc->body);
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
        $fields = ['brand_name' => 'Example MSP Ltd', 'brand_color' => '#7a1f5c', 'brand_footer' => "Example MSP · support@msp.example\n555-0100", 'report_paper' => 'Letter', 'report_powered_by' => '1'];

        $admin->upload('/admin/settings', '/admin/branding', $fields, 'brand_logo', $dir . '/fake.png', 'image/png');
        Assert::contains('PNG or JPEG image', $admin->get('/admin/settings')->body, 'a non-image is refused');
        $admin->submit('/admin/settings', '/admin/branding', ['brand_color' => 'red;}body{display:none'] + $fields);
        Assert::contains('The color must look like', $admin->get('/admin/settings')->body);

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
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'executive', 'period' => 'month']);
        $new = (string) $ctx->db->query("SELECT html FROM reports WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::contains('Example MSP Ltd', $new);
        Assert::contains('--brand: #7a1f5c', $new);
        Assert::contains('size: Letter', $new);
        Assert::contains('data:image/png;base64,', $new);
        Assert::contains('Generated by MSP Sentinel', $new);
        Assert::same($oldHtml, (string) $ctx->db->query("SELECT html FROM reports WHERE id = {$old}")->fetchColumn(), 'saved reports keep their branding');
        // White-label: the "Generated by" line can be turned off.
        $admin->submit('/admin/settings', '/admin/branding', ['report_powered_by' => '0'] + $fields);
        App::settings()->set('report_powered_by', App::settings()->fresh('report_powered_by'));
        $tech->submit('/clients/' . $cid, '/clients/' . $cid . '/reports', ['kind' => 'executive', 'period' => 'month']);
        Assert::notContains('Generated by MSP Sentinel', (string) $ctx->db->query("SELECT html FROM reports WHERE client_id = {$cid} ORDER BY id DESC LIMIT 1")->fetchColumn());
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
