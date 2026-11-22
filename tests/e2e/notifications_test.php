<?php

declare(strict_types=1);

/**
 * End-to-end tests: alert settings (encrypted secrets, validation, test buttons),
 * immediate Fail alerts and scan digests by email (fake SMTP on 127.0.0.1) and
 * webhook (fake receiver on 127.0.0.1), in-app notifications, user preferences,
 * retries, STARTTLS with certificate checks. Self-contained; made-up names only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$configure = static function (TestContext $ctx, array $over = [], ?object $admin = null): \Sentinel\Tests\HttpResult {
    $admin ??= $ctx->login('admin', 'Admin-Pass-0001!');
    $feeds = (require $ctx->configPath)['nvd']['base_url'];
    return $admin->submit('/admin/settings', '/admin/alerts', $over + [
        'email_enabled' => '1', 'smtp_host' => '127.0.0.1', 'smtp_port' => (string) $ctx->smtpPlainPort, 'smtp_security' => 'none',
        'smtp_username' => 'sentinel-relay', 'smtp_password' => 'Relay-Secret-123', 'smtp_from' => 'sentinel@msp.example',
        'team_addresses' => 'alerts@msp.example', 'webhook_enabled' => '1', 'webhook_url' => $feeds . '/webhook', 'webhook_format' => 'json',
    ]);
};

return [
    'alert settings: validated, secrets encrypted and never shown, admins only' => function (TestContext $ctx) use ($configure): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $configure($ctx, ['webhook_url' => 'https://10.1.2.3/hook'], $admin);
        Assert::contains('private or reserved address', $admin->get('/admin/settings')->body);
        $configure($ctx, ['smtp_host' => 'mail.example.com', 'smtp_security' => 'none'], $admin);
        Assert::contains('only allowed to a relay on this server', $admin->get('/admin/settings')->body);
        $configure($ctx, ['team_addresses' => "ok@msp.example, bad\r\nBcc: x@evil.example"], $admin);
        Assert::contains('Team addresses', $admin->get('/admin/settings')->body);

        Assert::redirect('/admin/settings#alerts', $configure($ctx));
        $stored = $ctx->db->query("SELECT name, value FROM settings WHERE name IN ('smtp_password', 'webhook_url')")->fetchAll(PDO::FETCH_KEY_PAIR);
        Assert::true(str_starts_with($stored['smtp_password'], 'v1:') && str_starts_with($stored['webhook_url'], 'v1:'), 'secrets stored encrypted');
        $page = $admin->get('/admin/settings')->body;
        Assert::notContains('Relay-Secret-123', $page, 'password never shown');
        Assert::notContains('/webhook', $page, 'webhook URL never shown');
        Assert::contains('Saved (leave empty to keep)', $page);
        // Saving again with empty secret fields keeps them.
        $configure($ctx, ['smtp_password' => '', 'webhook_url' => '']);
        Assert::same('Relay-Secret-123', App::settings()->getSecret('smtp_password'));
        $audit = (string) $ctx->db->query("SELECT details FROM audit_log WHERE action = 'settings.alerts_updated' ORDER BY id DESC LIMIT 1")->fetchColumn();
        Assert::notContains('Relay-Secret-123', $audit, 'secret not in the audit log');

        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'atech'")->fetchColumn() === 0) {
            $ctx->createUser('atech', 'technician', 'Atech-Pass-0001!');
        }
        $tech = $ctx->login('atech', 'Atech-Pass-0001!');
        $t = $tech->get('/')->csrf();
        Assert::status(403, $tech->post('/admin/alerts', ['_csrf' => $t, 'email_enabled' => '0']), 'technicians cannot change alert settings');
        Assert::status(403, $tech->post('/admin/alerts/test', ['_csrf' => $t, 'channel' => 'email']));
    },
    'test buttons send right away through the fake mail server and webhook' => function (TestContext $ctx) use ($configure): void {
        $configure($ctx);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $before = count($ctx->mails());
        $admin->submit('/admin/settings', '/admin/alerts/test', ['channel' => 'email']);
        Assert::contains('Test email sent to admin@msp.example', $admin->get('/admin/settings')->body);
        $mail = array_slice($ctx->mails(), $before)[0];
        Assert::same(['admin@msp.example'], $mail['to']);
        Assert::same('MSP Sentinel test email', $mail['subject']);
        Assert::same('sentinel-relay', $mail['auth_user'], 'authenticated with the saved user name');
        @unlink($ctx->webhookLog);
        $admin->submit('/admin/settings', '/admin/alerts/test', ['channel' => 'webhook']);
        Assert::contains('Test webhook message sent', $admin->get('/admin/settings')->body);
        $post = json_decode(trim((string) file_get_contents($ctx->webhookLog)), true);
        Assert::same('msp-sentinel', $post['source']);
    },
    'a scan sends immediate Fail alerts and a digest, by preference' => function (TestContext $ctx) use ($configure): void {
        $configure($ctx);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'dana'")->fetchColumn() === 0) {
            $id = $ctx->createUser('dana', 'viewer', 'Dana-Pass-00001!');
            $ctx->db->exec("UPDATE users SET email = 'dana@msp.example', alert_email = 'digest' WHERE id = {$id}");
            $id2 = $ctx->createUser('quiet', 'viewer', 'Quiet-Pass-0001!');
            $ctx->db->exec("UPDATE users SET email = 'quiet@msp.example', alert_email = 'none' WHERE id = {$id2}");
            $id3 = $ctx->createUser('gone', 'viewer', 'Gone-Pass-00001!');
            $ctx->db->exec("UPDATE users SET email = 'gone@msp.example', alert_email = 'immediate' WHERE id = {$id3}");
        }
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $now = (int) gmdate('G');
        $res = $admin->submit('/clients/new', '/clients', ['name' => 'Alerts Example', 'itflow_client_id' => '', 'timezone' => 'UTC',
            'scan_window_start' => sprintf('%02d:00', ($now + 23) % 24), 'scan_window_end' => sprintf('%02d:00', ($now + 1) % 24), 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
        $cid = (int) basename((string) $res->location());
        $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
            'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '', 'scope' => '203.0.113.160', 'confirm' => '1']);
        $admin->submit('/clients/' . $cid, '/clients/' . $cid . '/scan', []);
        $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid}")->fetchColumn();
        $before = count($ctx->mails());
        @unlink($ctx->webhookLog);
        [$code, $out] = $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
        Assert::contains('Alerts:', $out, 'outbox flushed by the same worker run');

        $mails = array_slice($ctx->mails(), $before);
        $fails = array_values(array_filter($mails, static fn (array $m): bool => str_contains($m['subject'], 'Fail: Remote Desktop open to the internet')));
        $to = array_merge(...array_map(static fn (array $m): array => $m['to'], $fails));
        sort($to);
        Assert::same(['admin@msp.example', 'alerts@msp.example'], $to,
            'immediate alert: one email each to the admin (immediate) and the team; the digest-only, no-email and bad-address users get none');
        foreach ($fails as $m) {
            Assert::same(1, count($m['to']), 'one recipient per message: nobody sees the other addresses');
        }
        Assert::contains('https://sentinel.example/findings/', $fails[0]['body'], 'links back to Sentinel');
        $digest = array_values(array_filter($mails, static fn (array $m): bool => str_contains($m['subject'], 'Scan summary')));
        $dto = array_merge(...array_map(static fn (array $m): array => $m['to'], $digest));
        sort($dto);
        Assert::same(['alerts@msp.example', 'dana@msp.example'], $dto, 'digest goes to digest users and the team');
        Assert::contains('FAIL: Remote Desktop open to the internet', $digest[0]['body']);
        $bad = $ctx->db->query("SELECT status, last_error FROM deliveries WHERE recipient = 'gone@msp.example' ORDER BY id DESC LIMIT 1")->fetch();
        Assert::same('pending', $bad['status'], 'the bad address is retried on its own');
        Assert::contains('550', $bad['last_error']);

        $posts = array_map(static fn (string $l): array => json_decode($l, true), file($ctx->webhookLog, FILE_IGNORE_NEW_LINES));
        Assert::true(count($posts) >= 2, 'webhook got the immediate alert and the digest');
        foreach ($posts as $p) {
            Assert::same(['source', 'severity', 'client', 'title', 'text', 'items', 'link', 'sent_at'], array_keys($p), 'summary only');
        }

        $page = $admin->get('/')->body;
        Assert::true((bool) preg_match('/notification-count">\d+</', $page), 'unread count shown in the header');
        $list = $admin->get('/notifications')->body;
        Assert::contains('Fail: Remote Desktop open to the internet', $list);
        Assert::notContains('notification-count', $admin->get('/')->body, 'opening the list marks them read');
    },
    'accepted findings stay quiet; failed deliveries are retried then given up' => function (TestContext $ctx) use ($configure): void {
        $configure($ctx);
        $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Alerts Example'")->fetchColumn();
        $rdp = (int) $ctx->db->query("SELECT id FROM findings WHERE client_id = {$cid} AND finding_key = 'port:203.0.113.160:3389'")->fetchColumn();
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/findings/' . $rdp, '/findings/' . $rdp . '/triage', ['status' => 'accepted', 'note' => 'Supplier access until March.']);
        $svc = "SELECT s.id FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id = {$cid} AND s.port = 3389";
        $ctx->db->exec("UPDATE services SET is_open = 0 WHERE id = ({$svc})");
        App::alerts()->findingsChanged($cid, App::findingsEngine()->refreshClient($cid), false);
        $ctx->db->exec("UPDATE services SET is_open = 1 WHERE id = ({$svc})");
        $result = App::findingsEngine()->refreshClient($cid);
        $queuedBefore = (int) $ctx->db->query("SELECT COUNT(*) FROM deliveries")->fetchColumn();
        App::alerts()->findingsChanged($cid, $result, false);
        Assert::same($queuedBefore, (int) $ctx->db->query("SELECT COUNT(*) FROM deliveries")->fetchColumn(), 'accepted finding came back with its decision: no alert');

        // Mail server down: retried, then marked failed after 3 attempts.
        // Set directly (this also refreshes the test process's settings cache).
        App::settings()->set('smtp_port', '1');
        App::alerts()->queueEmail(['admin@msp.example'], 'Retry test', 'body');
        $id = (int) $ctx->db->query("SELECT MAX(id) FROM deliveries WHERE subject = 'Retry test'")->fetchColumn();
        for ($i = 1; $i <= 3; $i++) {
            $ctx->db->exec("UPDATE deliveries SET next_attempt_at = UTC_TIMESTAMP() WHERE id = {$id}");
            App::outbox()->flush(5, $id);
        }
        $row = $ctx->db->query("SELECT status, attempts, last_error FROM deliveries WHERE id = {$id}")->fetch();
        Assert::same(['failed', 3], [$row['status'], (int) $row['attempts']]);
        Assert::contains('Could not connect', $row['last_error']);
        Assert::notContains('Relay-Secret-123', $row['last_error']);
    },
    'review fixes: no double sending, flapping and escalation, channel off, notifications read' => function (TestContext $ctx) use ($configure): void {
        $configure($ctx);
        App::settings()->set('smtp_port', (string) $ctx->smtpPlainPort); // refresh this process's settings cache
        $cid = (int) $ctx->db->query("SELECT id FROM clients WHERE name = 'Alerts Example'")->fetchColumn();
        $db = $ctx->db;
        // A delivery claimed by another process is not sent again; a stale claim goes back to the queue.
        App::alerts()->queueEmail(['admin@msp.example'], 'Claim test', 'body');
        $id = (int) $db->query("SELECT MAX(id) FROM deliveries WHERE subject = 'Claim test'")->fetchColumn();
        $db->exec("UPDATE deliveries SET status = 'sending', claimed_at = UTC_TIMESTAMP() WHERE id = {$id}");
        Assert::same(['sent' => 0, 'failed' => 0], App::outbox()->flush(5, $id), 'claimed elsewhere: skipped');
        $db->exec("UPDATE deliveries SET claimed_at = UTC_TIMESTAMP() - INTERVAL 11 MINUTE WHERE id = {$id}");
        App::outbox()->flush(5, $id); // recovers the stale claim (as attempt 1, due again in the future)
        $db->exec("UPDATE deliveries SET next_attempt_at = UTC_TIMESTAMP() WHERE id = {$id}");
        App::outbox()->flush(5, $id);
        Assert::same(['sent', 2], array_map(null, [$db->query("SELECT status FROM deliveries WHERE id = {$id}")->fetchColumn(), (int) $db->query("SELECT attempts FROM deliveries WHERE id = {$id}")->fetchColumn()]));

        // Flapping: the RDP finding resolves and comes back within 24 hours: no second immediate alert.
        $rdp = (int) $db->query("SELECT id FROM findings WHERE client_id = {$cid} AND finding_key = 'port:203.0.113.160:3389'")->fetchColumn();
        $db->exec("UPDATE findings SET status = 'open', resolved_from = NULL WHERE id = {$rdp}");
        $svc = "SELECT s.id FROM services s JOIN assets a ON a.id = s.asset_id WHERE a.client_id = {$cid} AND s.port = 3389";
        $db->exec("UPDATE services SET is_open = 0 WHERE id = ({$svc})");
        App::findingsEngine()->refreshClient($cid);
        $db->exec("UPDATE services SET is_open = 1 WHERE id = ({$svc})");
        $res = App::findingsEngine()->refreshClient($cid);
        Assert::true(in_array($rdp, $res['reopened_ids'], true), 'reopened');
        $before = (int) $db->query('SELECT COUNT(*) FROM deliveries')->fetchColumn();
        App::alerts()->findingsChanged($cid, $res, false);
        Assert::same($before, (int) $db->query('SELECT COUNT(*) FROM deliveries')->fetchColumn(), 'already alerted today: no new alert');

        // Escalation: an open Warning that becomes a Fail alerts like a new Fail.
        $db->exec("DELETE FROM finding_events WHERE finding_id = {$rdp} AND event = 'alerted'");
        $db->exec("UPDATE findings SET severity = 'warn' WHERE id = {$rdp}");
        $res = App::findingsEngine()->refreshClient($cid);
        Assert::same([$rdp], $res['escalated_ids']);
        App::alerts()->findingsChanged($cid, $res, false);
        Assert::true((int) $db->query("SELECT COUNT(*) FROM deliveries WHERE subject LIKE '%Fail: Remote Desktop%' AND id > (SELECT MAX(id) FROM deliveries WHERE subject = 'Claim test')")->fetchColumn() >= 2, 'escalation alerted');

        // A channel turned off after queueing: dropped, not sent.
        App::alerts()->queueWebhook(['title' => 'Off test', 'text' => '', 'severity' => 'info', 'client' => '', 'items' => [], 'link' => '']);
        $wid = (int) $db->query("SELECT MAX(id) FROM deliveries WHERE subject = 'Off test'")->fetchColumn();
        App::settings()->set('webhook_enabled', '0');
        App::outbox()->flush(5, $wid);
        Assert::same('failed', $db->query("SELECT status FROM deliveries WHERE id = {$wid}")->fetchColumn());
        App::settings()->set('webhook_enabled', '1');

        // Only the notifications shown are marked read.
        $uid = (int) $db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
        $db->exec("UPDATE notifications SET read_at = NULL WHERE user_id = {$uid}");
        $total = (int) $db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$uid}")->fetchColumn();
        for ($i = $total; $i < 105; $i++) {
            $db->exec("INSERT INTO notifications (user_id, kind, severity, title, created_at) VALUES ({$uid}, 'digest', 'info', 'Filler {$i}', UTC_TIMESTAMP())");
        }
        $ctx->login('admin', 'Admin-Pass-0001!')->get('/notifications');
        Assert::true((int) $db->query("SELECT COUNT(*) FROM notifications WHERE user_id = {$uid} AND read_at IS NULL")->fetchColumn() > 0, 'older rows beyond the list stay unread');
        $db->exec("UPDATE notifications SET read_at = UTC_TIMESTAMP() WHERE user_id = {$uid}");
    },
    'STARTTLS: works with a trusted certificate, refuses a name mismatch' => function (TestContext $ctx) use ($configure): void {
        $configure($ctx, ['smtp_host' => 'localhost', 'smtp_port' => (string) $ctx->smtpTlsPort, 'smtp_security' => 'starttls', 'smtp_password' => '']);
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $before = count($ctx->mails());
        $admin->submit('/admin/settings', '/admin/alerts/test', ['channel' => 'email']);
        $mails = array_slice($ctx->mails(), $before);
        Assert::true($mails !== [] && $mails[0]['tls'] === true, 'delivered over STARTTLS (certificate checked against the test CA)');
        $configure($ctx, ['smtp_host' => '127.0.0.1', 'smtp_port' => (string) $ctx->smtpTlsPort, 'smtp_security' => 'starttls', 'smtp_password' => ''], $admin);
        $admin->submit('/admin/settings', '/admin/alerts/test', ['channel' => 'email']);
        Assert::contains('TLS negotiation with the mail server failed', $admin->get('/admin/settings')->body, 'certificate is for "localhost", not 127.0.0.1');
        $configure($ctx); // back to the plain relay
    },
    'each user chooses their own emails' => function (TestContext $ctx): void {
        $view = $ctx->login('quiet', 'Quiet-Pass-0001!');
        Assert::contains('Email alerts', $view->get('/profile')->body);
        $view->submit('/profile', '/profile/alerts', ['alert_email' => 'both']);
        Assert::same('both', $ctx->db->query("SELECT alert_email FROM users WHERE username = 'quiet'")->fetchColumn());
        $view->submit('/profile', '/profile/alerts', ['alert_email' => 'everything']);
        Assert::same('both', $ctx->db->query("SELECT alert_email FROM users WHERE username = 'quiet'")->fetchColumn(), 'invalid choice refused');
        $view->submit('/profile', '/profile/alerts', ['alert_email' => 'none']);
    },
];
