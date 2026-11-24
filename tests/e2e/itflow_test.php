<?php

declare(strict_types=1);

/**
 * End-to-end tests for the ITFlow integration: client sync (phase 1), tickets from findings (phase 2) and two-way
 * status (phase 3), against the mock ITFlow API (tests/mocks/itflow_mock.php on 127.0.0.1, its client list in
 * itflow-clients.json, tickets in itflow-tickets.json). Rechecks use the test suite's fake nmap. Never contacts a real
 * ITFlow or scans a real host. Made-up data only.
 */

use Sentinel\Core\App;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

$base = static fn (TestContext $ctx): string => str_replace('/ninja', '/itflow', (string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
$alignBase = static fn (TestContext $ctx): string => str_replace('/ninja', '/align', (string) (require $ctx->configPath)['testing']['ninjaone_base_url']);
$setItflow = static function (TestContext $ctx, array $clients): void {
    file_put_contents(dirname($ctx->feedsLog) . '/itflow-clients.json', json_encode(array_map(static fn (array $c): array => [
        'client_id' => $c[0], 'client_name' => $c[1], 'client_archived_at' => $c[2] ?? null, 'client_updated_at' => '2026-11-22 10:00:00',
    ], $clients)));
};
$key = 'itflow-test-key-0123456789abcdef';

return [
    'ITFlow: admins connect it; the key is encrypted and never shown; test connection reads the clients' => function (TestContext $ctx) use ($base, $setItflow, $key): void {
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Co'], [803, 'Gone Example', '2026-01-01 00:00:00']]);
        if ((int) $ctx->db->query("SELECT COUNT(*) FROM users WHERE username = 'ittech'")->fetchColumn() === 0) {
            $ctx->createUser('ittech', 'technician', 'Ittech-Pass-001!');
        }
        $tech = $ctx->login('ittech', 'Ittech-Pass-001!');
        Assert::status(403, $tech->post('/admin/integrations/itflow/sync', ['_csrf' => $tech->get('/')->csrf()]), 'technicians cannot sync');
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        Assert::contains('id="itflow"', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => 'ftp://itflow.example', 'api_key' => $key, 'enabled' => '1']);
        Assert::contains('must be an https:// address', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx) . '/api/v1', 'api_key' => $key, 'enabled' => '0']);
        Assert::same($base($ctx), App::settings()->fresh('itflow_url'), 'a pasted API address becomes ITFlow\'s address');
        $raw = (string) $ctx->db->query("SELECT value FROM settings WHERE name = 'itflow_api_key'")->fetchColumn();
        Assert::true($raw !== '' && !str_contains($raw, $key), 'key stored encrypted');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/test', []);
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('Connected: the key can see 3 client(s) in ITFlow (2 active)', $page);
        Assert::notContains($key, $page, 'key never shown');
        Assert::notContains($key, implode("\n", $ctx->db->query('SELECT details FROM audit_log')->fetchAll(PDO::FETCH_COLUMN)), 'key never audited');
        // Off: Sync now refuses, and the worker doesn't sync.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/sync', []);
        Assert::contains('Turn on the ITFlow client sync', $admin->get('/admin/integrations')->body);
        Assert::same(null, App::itflowSync()->syncIfDue(), 'off: no sync');
        // A wrong key: the test says so.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => 'wrong-key-0123456789abcdef', 'enabled' => '0']);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/test', []);
        Assert::contains('ITFlow refused the API key', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1']);
    },
    'ITFlow sync: new clients are added (never scanned without authorisation), same names linked, archives followed' => function (TestContext $ctx) use ($setItflow, $alignBase): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $mk = static function (string $name) use ($admin): int {
            $res = $admin->submit('/clients/new', '/clients', ['name' => $name, 'itflow_client_id' => '', 'timezone' => 'UTC', 'scan_window_start' => '00:00', 'scan_window_end' => '23:59', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
            return (int) basename((string) $res->location());
        };
        $lighthouse = $mk('lighthouse example'); // same name in another case: linked, not duplicated
        $dock = $mk('Dock Example');
        $ctx->db->exec("UPDATE clients SET itflow_client_id = 899 WHERE id = {$dock}"); // already linked to another ITFlow client
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Co'], [803, 'Gone Example', '2026-01-01 00:00:00'], [804, 'Dock Example'], [805, "Bad\u{202E}Name\x07 Example"]]);
        // MSP Align connected too: ITFlow client 802 is MSP Align client 502 (psa_id 802).
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => $alignBase($ctx), 'api_key' => 'msa_TESTKEY1_' . str_repeat('a', 32), 'enabled' => '1']);

        $admin->submit('/admin/integrations', '/admin/integrations/itflow/sync', []);
        $flash = $admin->get('/admin/integrations')->body;
        Assert::contains('ITFlow sync: 3 new, 1 linked by name', $flash);
        Assert::contains('1 linked to MSP Align by ITFlow ID', $flash);
        $c = static fn (int $itflowId): array => $ctx->db->query("SELECT * FROM clients WHERE itflow_client_id = {$itflowId}")->fetch() ?: [];
        Assert::same($lighthouse, (int) $c(801)['id'], 'linked by name');
        $pier = $c(802);
        Assert::same('Pier Example Co', $pier['name']);
        Assert::same(0, (int) $ctx->db->query('SELECT COUNT(*) FROM scan_authorisations WHERE client_id = ' . (int) $pier['id'])->fetchColumn(), 'no authorisation: never scanned');
        Assert::contains('Not scanned until its authorisation is recorded', (string) $pier['notes']);
        Assert::same(1, (int) $ctx->db->query('SELECT COUNT(*) FROM sites WHERE client_id = ' . (int) $pier['id'])->fetchColumn(), 'default site');
        Assert::same(502, (int) $pier['align_client_id'], 'linked to MSP Align by ITFlow ID');
        Assert::same([], $c(803), 'already archived in ITFlow: not created');
        Assert::same('Dock Example (ITFlow #804)', $c(804)['name'], 'a name clash gets the ITFlow number');
        Assert::same('BadName Example', $c(805)['name'], 'control and direction characters removed');
        Assert::same(null, $c(805)['align_client_id'], 'an ITFlow ID on two MSP Align clients: linked to neither');
        Assert::true((int) $ctx->db->query("SELECT COUNT(*) FROM audit_log WHERE username = 'itflow-sync' AND action = 'client.created'")->fetchColumn() >= 3, 'audited');

        // Not due again for 15 minutes.
        Assert::same(null, App::itflowSync()->syncIfDue(), 'not due');

        // Changes in ITFlow: a rename, an archive; and a client an admin archived in Sentinel.
        $admin->submit('/clients/' . $lighthouse, '/clients/' . $lighthouse . '/archive', ['archive' => '1']); // archived by hand in Sentinel
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Company'], [804, 'Dock Example', '2026-11-20 09:00:00'], [805, 'BadName Example']]);
        $r = App::itflowSync()->sync();
        Assert::contains('1 renamed, 1 archived, 0 restored', $r, $r);
        Assert::same('Pier Example Company', $c(802)['name']);
        Assert::same([1, 1], [(int) $c(804)['is_archived'], (int) $c(804)['itflow_archived']], 'archived because ITFlow archived it');
        Assert::same(1, (int) $c(801)['is_archived'], 'archived by hand in Sentinel: the sync leaves it alone');
        // Unarchived in ITFlow: restored, because the sync archived it.
        $setItflow($ctx, [[801, 'Lighthouse Example'], [802, 'Pier Example Company'], [804, 'Dock Example'], [805, 'BadName Example']]);
        Assert::contains('1 restored', App::itflowSync()->sync());
        Assert::same(0, (int) $c(804)['is_archived']);
        Assert::same(1, (int) $c(801)['is_archived'], 'still archived (an admin did that)');
        // An admin restores a client the sync archived and archives it again by hand: the sync never undoes that.
        $ctx->db->exec('UPDATE clients SET is_archived = 1, itflow_archived = 1 WHERE itflow_client_id = 804');
        $dockId = (int) $c(804)['id'];
        $admin->submit('/clients/' . $dockId, '/clients/' . $dockId . '/archive', ['archive' => '0']);
        $admin->submit('/clients/' . $dockId, '/clients/' . $dockId . '/archive', ['archive' => '1']);
        App::itflowSync()->sync();
        Assert::same(1, (int) $c(804)['is_archived'], 'archived by hand: stays archived although ITFlow has it active');
        // Gone from ITFlow's answer: left alone (the key may not see it any more).
        $setItflow($ctx, [[801, 'Lighthouse Example']]);
        Assert::contains('0 new', App::itflowSync()->sync());
        Assert::same(0, (int) $c(802)['is_archived'], 'not archived just because it is missing');
        // A failed sync is reported and changes nothing.
        App::settings()->setSecret('itflow_api_key', 'wrong-key-0123456789abcdef');
        Assert::contains('Failed: ITFlow refused the API key', App::itflowSync()->sync());
        Assert::same('0', App::settings()->fresh('itflow_last_ok'));
        // Off again for later tests.
        App::settings()->set('itflow_enabled', '0');
        $admin->submit('/admin/integrations', '/admin/integrations/mspalign', ['url' => '', 'clear_key' => '1', 'enabled' => '0']);
    },
    'ITFlow tickets: each Fail its own ticket with how to fix it, never twice; Warnings weekly; known-exploited notes' => function (TestContext $ctx) use ($base, $setItflow, $key): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $setItflow($ctx, [[810, 'Ticket Example Ltd']]);
        @unlink(dirname($ctx->feedsLog) . '/itflow-tickets.json');
        // An old Fail from before tickets are turned on.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1']);
        App::itflowSync()->sync();
        $cid = (int) $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id = 810')->fetchColumn();
        Assert::true($cid > 0, 'client synced');
        $finding = static function (string $key, string $sev, string $title, string $target, int $daysAgo = 0) use ($ctx, $cid): int {
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at, due_at)
                               VALUES (:c, :k, :t, :s, :ti, 'Port 3389/tcp is reachable from the internet.', :tg, '3389|ms-wbt-server', 'open',
                                       UTC_TIMESTAMP() - INTERVAL :d DAY, UTC_TIMESTAMP(), UTC_TIMESTAMP() - INTERVAL :d2 DAY, UTC_TIMESTAMP() + INTERVAL 14 DAY)")
                ->execute(['c' => $cid, 'k' => $key, 't' => explode(':', $key)[0] === 'email' ? 'email' : 'port', 's' => $sev, 'ti' => $title, 'tg' => $target, 'd' => $daysAgo, 'd2' => $daysAgo]);
            return (int) $ctx->db->lastInsertId();
        };
        $old = $finding('port:203.0.113.90:23', 'fail', 'Telnet open to the internet', '203.0.113.90:23', 3);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1', 'tickets' => '1']);
        $rdp = $finding('port:203.0.113.90:3389', 'fail', 'Remote Desktop open <img src=x onerror=alert(1)>', '203.0.113.90:3389');
        $w1 = $finding('email:ticket.example:dmarc_missing', 'warn', 'No DMARC record for this domain', 'ticket.example');

        $admin->submit('/admin/integrations', '/admin/integrations/itflow/tickets', []);
        Assert::contains('ITFlow tickets: 1 finding ticket(s), 1 weekly Warnings ticket(s)', $admin->get('/admin/integrations')->body);
        $sent = static fn (): array => json_decode((string) @file_get_contents(dirname($ctx->feedsLog) . '/itflow-tickets.json'), true) ?: ['tickets' => [], 'replies' => []];
        $t = $sent()['tickets'];
        Assert::same(2, count($t));
        Assert::same([810, 'High'], [(int) $t[0]['client_id'], $t[0]['ticket_priority']]);
        Assert::contains('[Sentinel] Fail: Remote Desktop open', $t[0]['ticket_subject']);
        Assert::contains('How to fix it', $t[0]['ticket_details']);
        Assert::contains('Why it matters', $t[0]['ticket_details']);
        Assert::contains('/findings/' . $rdp, $t[0]['ticket_details'], 'link back to the finding');
        Assert::contains('&lt;img src=x onerror=alert(1)&gt;', $t[0]['ticket_details'], 'escaped');
        Assert::notContains('<img', $t[0]['ticket_details']);
        Assert::same('Medium', $t[1]['ticket_priority']);
        Assert::contains('1 new security warning(s) this week', $t[1]['ticket_subject']);
        Assert::contains('NEW', $t[1]['ticket_details']);
        Assert::contains('No DMARC record', $t[1]['ticket_details']);
        Assert::true(!str_contains(json_encode($t), 'Telnet'), 'findings from before tickets were turned on: none');
        Assert::contains('TCK-5001', $admin->get('/findings/' . $rdp)->body, 'ticket shown on the finding');
        // Service boards (1.44): by default each new ticket is moved to the board named Alerts, unassigned.
        $moves = $sent()['moves'] ?? [];
        Assert::same(2, count($moves), 'both new tickets moved');
        Assert::same([3, 1], [(int) $moves[0]['board_id'], (int) $moves[0]['unassign']], 'to the Alerts board, unassigned');
        Assert::same(810, (int) $moves[0]['client_id']);

        // Never twice; no weekly ticket again within a week.
        App::itflowTickets()->run();
        Assert::same(2, count($sent()['tickets']), 'no duplicates');
        // Known exploited later: one internal note, once.
        $ctx->db->exec("INSERT IGNORE INTO kev_catalog (cve_id, vendor, product, name, date_added, due_date, required_action) VALUES ('CVE-2099-0001', 'Example', 'Example', 'Example', '2026-11-01', '2026-11-22', 'Apply the vendor update.')");
        $ctx->db->exec("UPDATE findings SET cve_id = 'CVE-2099-0001' WHERE id = {$rdp}");
        App::itflowTickets()->run();
        App::itflowTickets()->run();
        $r = $sent()['replies'];
        Assert::same(1, count($r), 'one note');
        Assert::same(['Internal', 5001], [$r[0]['ticket_reply_type'], (int) $r[0]['ticket_id']]);
        Assert::contains('known to be exploited', $r[0]['ticket_reply']);
        // Existing Fails on request.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/tickets', ['existing' => '1']);
        Assert::contains('Telnet open', end($sent()['tickets'])['ticket_subject']);
        // Weekly again after a week, only with new Warnings.
        $ctx->db->exec("UPDATE itflow_tickets SET created_at = UTC_TIMESTAMP() - INTERVAL 8 DAY WHERE kind = 'weekly'");
        $ctx->db->exec("UPDATE findings SET opened_at = UTC_TIMESTAMP() - INTERVAL 9 DAY, first_seen = UTC_TIMESTAMP() - INTERVAL 9 DAY WHERE id = {$w1}"); // in last week's ticket
        $before = count($sent()['tickets']);
        App::itflowTickets()->run();
        Assert::same($before, count($sent()['tickets']), 'no new Warnings: no weekly ticket');
        $finding('email:ticket.example:spf_weak', 'warn', 'SPF does not reject unauthorised senders', 'ticket.example');
        App::itflowTickets()->run();
        Assert::same($before + 1, count($sent()['tickets']), 'new Warning a week later: weekly ticket');
        // Archived clients get no tickets; a failing ITFlow is reported.
        $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$cid}");
        $finding('port:203.0.113.90:445', 'fail', 'Windows file sharing open', '203.0.113.90:445');
        App::itflowTickets()->run();
        Assert::same($before + 1, count($sent()['tickets']), 'archived: no tickets');
        $ctx->db->exec("UPDATE clients SET is_archived = 0 WHERE id = {$cid}");
        App::settings()->setSecret('itflow_api_key', 'wrong-key-0123456789abcdef');
        Assert::contains('Stopped: ITFlow refused', App::itflowTickets()->run());
        App::settings()->set('itflow_enabled', '0');
        App::settings()->set('itflow_tickets_enabled', '0');
    },
    'ITFlow two-way: fixed in Sentinel resolves the ticket; closed in ITFlow rechecks, then reopens or replaces' => function (TestContext $ctx) use ($base, $setItflow, $key): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $dir = dirname($ctx->feedsLog);
        $setItflow($ctx, [[820, 'Twoway Example Ltd'], [821, 'Refused Example Ltd']]);
        @unlink($dir . '/itflow-tickets.json');
        @unlink($dir . '/itflow-fail.json');
        @unlink($dir . '/nmap-closed.json');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1']);
        App::itflowSync()->sync();
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1', 'tickets' => '1']);
        $cid = (int) $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id = 820')->fetchColumn();
        $cid2 = (int) $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id = 821')->fetchColumn();
        $admin->submit('/clients/' . $cid . '/authorisations/new', '/clients/' . $cid . '/authorisations', [
            'approved_by_name' => 'Jo Example', 'approved_by_role' => 'Owner', 'approved_on' => gmdate('Y-m-d'), 'valid_from' => gmdate('Y-m-d', time() - 86400),
            'valid_until' => gmdate('Y-m-d', time() + 86400 * 200), 'document_ref' => '', 'notes' => '', 'scope' => '203.0.113.160', 'confirm' => '1']);
        $ctx->db->exec("UPDATE clients SET scan_window_start = '00:00', scan_window_end = '23:59' WHERE id = {$cid}"); // rechecks wait for the window
        $finding = static function (int $client, string $key, string $title) use ($ctx): int {
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at)
                               VALUES (:c, :k, 'port', 'fail', :ti, 'Reachable from the internet.', :tg, 'open', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP() - INTERVAL 1 HOUR, UTC_TIMESTAMP())")
                ->execute(['c' => $client, 'k' => $key, 'ti' => $title, 'tg' => substr($key, 5)]);
            return (int) $ctx->db->lastInsertId();
        };
        $sent = static fn (): array => json_decode((string) @file_get_contents($dir . '/itflow-tickets.json'), true) ?: ['tickets' => [], 'replies' => [], 'log' => []];
        $setStatus = static function (int $ticket, string $status) use ($dir, $sent): void {
            $st = $sent();
            foreach ($st['tickets'] as &$t) {
                if ((int) $t['id'] === $ticket) {
                    $t['status'] = $status;
                }
            }
            unset($t);
            file_put_contents($dir . '/itflow-tickets.json', json_encode($st));
        };
        $row = static fn (int $f): array|false => $ctx->db->query("SELECT * FROM itflow_tickets WHERE kind = 'finding' AND finding_id = {$f}")->fetch();
        $lastReply = static fn (int $ticket): string => (string) (array_values(array_filter($sent()['replies'], static fn (array $r): bool => (int) $r['ticket_id'] === $ticket))[0] ?? ['ticket_reply' => ''])['ticket_reply'];
        $repliesTo = static fn (int $ticket): array => array_values(array_map(static fn (array $r): string => $r['ticket_reply'], array_filter($sent()['replies'], static fn (array $r): bool => (int) $r['ticket_id'] === $ticket)));
        $recheck = static function () use ($ctx, $cid): int {
            $ctx->db->exec("UPDATE findings SET verify_requested_at = verify_requested_at - INTERVAL 11 MINUTE WHERE client_id = {$cid} AND verify_requested_at IS NOT NULL");
            $job = (int) $ctx->db->query("SELECT MAX(id) FROM scan_jobs WHERE client_id = {$cid} AND job_type = 'verify' AND status = 'queued'")->fetchColumn();
            if ($job > 0) {
                $ctx->cli('bin/worker.php', ['--no-schedule', '--job=' . $job]);
            }
            return $job;
        };

        // A ticket, with a link to ITFlow's agent view; ITFlow's guest link (with its secret key) is never kept.
        $f1 = $finding($cid, 'port:203.0.113.160:3389', 'Remote Desktop open to the internet');
        App::itflowTickets()->run();
        $t1 = (int) $row($f1)['itflow_ticket_id'];
        Assert::true($t1 > 0, 'ticket opened');
        Assert::same('open', $row($f1)['state']);
        Assert::contains('sentinel-', (string) $sent()['tickets'][0]['ticket_vendor_ticket_number'], 'marked, so a timed-out create is found again');
        Assert::notContains('SECRETKEY', json_encode($ctx->db->query('SELECT * FROM itflow_tickets')->fetchAll()), 'guest link not stored');
        $page = $admin->get('/findings/' . $f1)->body;
        Assert::contains('/itflow/agent/ticket.php?client_id=820&amp;ticket_id=' . $t1, $page);
        Assert::notContains('SECRETKEY', $page);

        // A findings refresh from stored data, or a recheck that couldn't tell, is no evidence: the ticket stays as it is.
        $setStatus($t1, 'resolved');
        App::itflowTickets()->run();
        Assert::same('awaiting_check', $row($f1)['state']);
        $ctx->db->exec("UPDATE findings SET last_seen = UTC_TIMESTAMP() + INTERVAL 5 SECOND WHERE id = {$f1}"); // as refreshAll does
        $vj = (int) $ctx->db->query("SELECT verify_job_id FROM findings WHERE id = {$f1}")->fetchColumn();
        \Sentinel\Findings\VerifyOutcome::record($ctx->db, $f1, null, 'not_verified', 'Could not tell.');
        $ctx->db->exec("UPDATE scan_jobs SET status = 'done' WHERE id = {$vj}");
        App::itflowTickets()->run();
        Assert::same('awaiting_check', $row($f1)['state'], 'not reopened without a conclusive recheck');
        Assert::notContains('reopen:', json_encode($sent()['log'] ?? []));
        $setStatus($t1, 'open');
        App::itflowTickets()->run();
        Assert::same('open', $row($f1)['state'], 'reopened by a tech in ITFlow: followed again');

        // Resolved in ITFlow while still open here: Sentinel rechecks at once; still there -> reopened with a note.
        $setStatus($t1, 'resolved');
        App::itflowTickets()->run();
        Assert::same('open', $row($f1)['state'], 'within 10 minutes of the last recheck: waits');
        $ctx->db->exec("UPDATE findings SET verify_requested_at = UTC_TIMESTAMP() - INTERVAL 11 MINUTE WHERE id = {$f1}");
        App::itflowTickets()->run();
        Assert::same('awaiting_check', $row($f1)['state']);
        $job = $recheck();
        Assert::true($job > 0, 'a verify-fix recheck was queued');
        $payload = json_decode((string) $ctx->db->query("SELECT payload FROM scan_jobs WHERE id = {$job}")->fetchColumn(), true);
        Assert::same([['203.0.113.160'], [3389]], [$payload['ips'], $payload['ports']], 'only that address and port');
        Assert::same(0, (int) $ctx->db->query("SELECT outside_window FROM scan_jobs WHERE id = {$job}")->fetchColumn(), 'waits for the scan window');
        Assert::same('still_present', $ctx->db->query("SELECT verify_result FROM findings WHERE id = {$f1}")->fetchColumn());
        $summary = App::itflowTickets()->run();
        Assert::contains('1 reopened', $summary);
        Assert::contains('reopen:' . $t1, json_encode($sent()['log']));
        Assert::contains('still sees this problem', implode(' ', $repliesTo($t1)));
        Assert::same('open', $row($f1)['state']);

        // Closed in ITFlow (can't be reopened) and still there: a new ticket that names the old one.
        $setStatus($t1, 'closed');
        App::itflowTickets()->run();
        $recheck();
        $before = count($sent()['tickets']);
        Assert::contains('1 replaced', App::itflowTickets()->run());
        Assert::same($before + 1, count($sent()['tickets']));
        $t2 = (int) $row($f1)['itflow_ticket_id'];
        Assert::true($t2 !== $t1, 'new ticket');
        Assert::contains('TCK-' . $t1 . ' was closed, but Sentinel still sees this problem', end($sent()['tickets'])['ticket_details']);
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM itflow_tickets WHERE history_finding_id = {$f1} AND state = 'replaced' AND itflow_ticket_id = {$t1}")->fetchColumn());
        Assert::contains('Earlier ITFlow ticket', $admin->get('/findings/' . $f1)->body);

        // Fixed this time: closing the new ticket in ITFlow -> recheck -> finding resolved -> "verified fixed" note.
        file_put_contents($dir . '/nmap-closed.json', json_encode(['203.0.113.160:3389']));
        $setStatus($t2, 'resolved');
        App::itflowTickets()->run();
        $recheck();
        @unlink($dir . '/nmap-closed.json'); // only this recheck sees the port closed (other tests expect it open)
        Assert::same('resolved', $ctx->db->query("SELECT status FROM findings WHERE id = {$f1}")->fetchColumn());
        Assert::contains('1 confirmed fixed', App::itflowTickets()->run());
        Assert::same('done', $row($f1)['state']);
        Assert::contains('Verified fixed by Sentinel', implode(' ', $repliesTo($t2)));

        // Fixed in Sentinel first: a note and the ticket resolved; the problem coming back reopens it.
        $f2 = $finding($cid, 'port:203.0.113.194:445', 'Windows file sharing open');
        App::itflowTickets()->run();
        $t3 = (int) $row($f2)['itflow_ticket_id'];
        $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP() WHERE id = {$f2}");
        Assert::contains('1 resolved as fixed', App::itflowTickets()->run());
        Assert::contains('resolve:' . $t3, json_encode($sent()['log']));
        Assert::contains('Verified fixed by Sentinel', $lastReply($t3));
        Assert::same('sentinel_resolved', $row($f2)['state']);
        $ctx->db->exec("UPDATE findings SET status = 'open', resolved_at = NULL, opened_at = UTC_TIMESTAMP() WHERE id = {$f2}");
        App::itflowTickets()->run();
        Assert::contains('reopen:' . $t3, json_encode($sent()['log']));
        Assert::contains('came back', implode(' ', $repliesTo($t3)));
        Assert::same('open', $row($f2)['state']);
        $hist = implode("\n", $ctx->db->query("SELECT note FROM finding_events WHERE finding_id = {$f2} AND event = 'itflow_ticket'")->fetchAll(PDO::FETCH_COLUMN));
        Assert::contains('resolved: no longer seen by Sentinel', $hist, 'history on the finding');

        // A device finding (no recheck of its own): only device data received after the close, and processed by the
        // findings engine since, counts as still there; a refresh from stored data doesn't.
        $ctx->db->exec("INSERT INTO devices (client_id, source, source_id, name, first_seen, last_seen) VALUES ({$cid}, 'ninjaone', 'tw-1', 'TW-LAPTOP-01', UTC_TIMESTAMP() - INTERVAL 1 DAY, UTC_TIMESTAMP() - INTERVAL 1 HOUR)");
        $dev = (int) $ctx->db->lastInsertId();
        $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at, device_id, source)
                           VALUES (:c, :k, 'device', 'fail', 'Antivirus is off', 'Real-time protection is off.', 'TW-LAPTOP-01', 'av_state=off', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP() - INTERVAL 1 HOUR, UTC_TIMESTAMP(), :d, 'ninjaone')")
            ->execute(['c' => $cid, 'k' => 'dev:ninjaone:tw-1:av_off', 'd' => $dev]);
        $fd = (int) $ctx->db->lastInsertId();
        App::itflowTickets()->run();
        $td = (int) $row($fd)['itflow_ticket_id'];
        $setStatus($td, 'resolved');
        App::itflowTickets()->run();
        Assert::same('awaiting_check', $row($fd)['state']);
        Assert::same(0, (int) $ctx->db->query("SELECT COUNT(*) FROM scan_jobs WHERE job_type = 'verify' AND JSON_EXTRACT(payload, '$.finding_id') = {$fd}")->fetchColumn(), 'devices are never scanned for this');
        $ctx->db->exec("UPDATE findings SET last_seen = UTC_TIMESTAMP() + INTERVAL 5 SECOND WHERE id = {$fd}"); // a refresh from stored data
        App::itflowTickets()->run();
        Assert::same('awaiting_check', $row($fd)['state'], 'old device data: not still there');
        $ctx->db->exec("UPDATE devices SET last_seen = UTC_TIMESTAMP() + INTERVAL 10 SECOND WHERE id = {$dev}"); // a sync after the close...
        App::itflowTickets()->run();
        Assert::same('awaiting_check', $row($fd)['state'], 'new device data not yet processed by the engine: wait');
        $ctx->db->exec("UPDATE findings SET last_seen = UTC_TIMESTAMP() + INTERVAL 20 SECOND WHERE id = {$fd}"); // ...and the engine still sees it
        App::itflowTickets()->run();
        Assert::same('open', $row($fd)['state'], 'still there: ticket reopened');
        Assert::contains('reopen:' . $td, json_encode($sent()['log']));

        // One refused item never holds up the others; it is retried later.
        file_put_contents($dir . '/itflow-fail.json', json_encode(['refuse_clients' => [821]]));
        $f3 = $finding($cid2, 'port:203.0.113.195:3389', 'Remote Desktop open to the internet');
        $f4 = $finding($cid, 'port:203.0.113.194:23', 'Telnet open to the internet');
        $summary = App::itflowTickets()->run();
        Assert::contains('1 refused by ITFlow (retried later)', $summary);
        Assert::notContains('Stopped', $summary);
        Assert::same('open', $row($f4)['state'], 'the next finding still got its ticket');
        Assert::same('failed', $row($f3)['state']);
        Assert::contains('Client not found', $admin->get('/findings/' . $f3)->body, 'the reason is shown on the finding');
        @unlink($dir . '/itflow-fail.json');
        App::itflowTickets()->run();
        Assert::same('failed', $row($f3)['state'], 'not before its retry time');
        $ctx->db->exec("UPDATE itflow_tickets SET retry_at = UTC_TIMESTAMP() - INTERVAL 1 MINUTE WHERE finding_id = {$f3}");
        App::itflowTickets()->run();
        Assert::same('open', $row($f3)['state'], 'retried');

        // An unclear answer (ITFlow saved it, then a 502): the run stops, and the next one finds the ticket instead
        // of opening it twice. The client has a long ticket history: the lookup counts it with small probes and
        // reads from the newest end, never the whole list.
        $st = $sent();
        for ($i = 0; $i < 1500; $i++) {
            $st['tickets'][] = ['id' => 100 + $i, 'status' => 'closed', 'client_id' => 820, 'ticket_subject' => 'Old ticket ' . $i, 'created_at' => '2026-01-01 00:00:00'];
        }
        usort($st['tickets'], static fn (array $a, array $b): int => $a['id'] <=> $b['id']);
        file_put_contents($dir . '/itflow-tickets.json', json_encode($st));
        file_put_contents($dir . '/itflow-fail.json', json_encode(['create_502' => true]));
        $f5 = $finding($cid, 'port:203.0.113.194:21', 'FTP open to the internet');
        Assert::contains('Stopped: ITFlow answered HTTP 502', App::itflowTickets()->run());
        Assert::same('pending', $row($f5)['state']);
        $count = count($sent()['tickets']);
        @unlink($dir . '/itflow-fail.json');
        $reads = static fn (): int => count(array_filter(array_map(static fn (string $l): mixed => json_decode($l, true), file($ctx->feedsLog) ?: []),
            static fn (mixed $e): bool => is_array($e) && str_ends_with((string) $e['path'], '/tickets/read.php') && (string) ($e['query']['client_id'] ?? '') === '820'));
        $readsBefore = $reads();
        App::itflowTickets()->run();
        $n = $reads() - $readsBefore;
        Assert::true($n >= 1 && $n <= 30, 'a few small reads, not the whole list (' . $n . ')');
        Assert::same($count, count($sent()['tickets']), 'not opened twice');
        Assert::same('open', $row($f5)['state']);
        Assert::same((int) end($sent()['tickets'])['id'], (int) $row($f5)['itflow_ticket_id'], 'the saved ticket was adopted');

        // A ticket deleted in ITFlow: given up after two answers an hour apart, then a new ticket while it's open.
        $t4 = (int) $row($f4)['itflow_ticket_id'];
        $setStatus($t4, 'deleted');
        App::itflowTickets()->run();
        Assert::same('open', $row($f4)['state'], 'one "No resource" is not enough');
        $ctx->db->exec("UPDATE itflow_tickets SET gone_seen_at = gone_seen_at - INTERVAL 2 HOUR, status_checked_at = NULL WHERE itflow_ticket_id = {$t4}");
        App::itflowTickets()->run();
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM itflow_tickets WHERE itflow_ticket_id = {$t4} AND state = 'gone' AND history_finding_id = {$f4}")->fetchColumn());
        Assert::true((int) $row($f4)['itflow_ticket_id'] > $t4, 'a new ticket for the open finding');
        $ctx->db->exec("UPDATE clients SET is_demo = 1 WHERE id = {$cid2}");
        $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP() WHERE id = {$f3}");
        $calls = count($sent()['log'] ?? []);
        App::itflowTickets()->run();
        Assert::same($calls, count($sent()['log'] ?? []), 'demo client: nothing sent');
        Assert::same('open', $row($f3)['state']);
        $ctx->db->exec("UPDATE clients SET is_demo = 0, is_archived = 1 WHERE id = {$cid2}");
        App::settings()->set('itflow_enabled', '0');
        App::settings()->set('itflow_tickets_enabled', '0');
        @unlink($dir . '/nmap-closed.json');
    },
    'ITFlow: one ticket per issue; it follows every target, resolves when all are fixed, and moves on when replaced' => function (TestContext $ctx) use ($base, $setItflow, $key): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $dir = dirname($ctx->feedsLog);
        $setItflow($ctx, [[830, 'Grouped Ticket Example Ltd']]);
        @unlink($dir . '/itflow-tickets.json');
        @unlink($dir . '/itflow-fail.json');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1']);
        App::itflowSync()->sync();
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1', 'tickets' => '1']);
        $cid = (int) $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id = 830')->fetchColumn();
        $finding = static function (string $key, string $type, string $title, string $target, ?string $cve) use ($ctx, $cid): int {
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, cve_id, status, first_seen, last_seen, opened_at)
                               VALUES (:c, :k, :t, 'fail', :ti, 'Made-up detail.', :tg, 'made-up evidence', :cve, 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP() - INTERVAL 1 HOUR, UTC_TIMESTAMP())")
                ->execute(['c' => $cid, 'k' => $key, 't' => $type, 'ti' => $title, 'tg' => $target, 'cve' => $cve]);
            return (int) $ctx->db->lastInsertId();
        };
        $sent = static fn (): array => json_decode((string) @file_get_contents($dir . '/itflow-tickets.json'), true) ?: ['tickets' => [], 'replies' => [], 'log' => []];
        $setStatus = static function (int $ticket, string $status) use ($dir, $sent): void {
            $st = $sent();
            foreach ($st['tickets'] as &$t) {
                if ((int) $t['id'] === $ticket) {
                    $t['status'] = $status;
                }
            }
            unset($t);
            file_put_contents($dir . '/itflow-tickets.json', json_encode($st));
        };
        $replies = static fn (int $ticket): string => implode("\n", array_map(static fn (array $r): string => $r['ticket_reply'], array_filter($sent()['replies'], static fn (array $r): bool => (int) $r['ticket_id'] === $ticket)));
        $rowOf = static fn (int $f): array|false => $ctx->db->query("SELECT * FROM itflow_tickets WHERE finding_id = {$f}")->fetch();
        $title = 'Known exploited: CVE-2099-0950 in Example SSH (8.1 High)';

        // The first target opens the ticket; the same CVE on a second server joins it with a note; another issue gets its own.
        $a = $finding('vuln:203.0.113.170:22:CVE-2099-0950', 'vuln', $title, '203.0.113.170:22', 'CVE-2099-0950');
        App::itflowTickets()->run();
        $t = (int) $rowOf($a)['itflow_ticket_id'];
        Assert::true($t > 0, 'ticket opened');
        $b = $finding('vuln:203.0.113.171:22:CVE-2099-0950', 'vuln', $title, '203.0.113.171:22', 'CVE-2099-0950');
        $other = $finding('port:203.0.113.170:3389', 'port', 'Remote Desktop open to the internet', '203.0.113.170:3389', null);
        App::itflowTickets()->run();
        Assert::same(2, count($sent()['tickets']), 'one ticket for the CVE on two servers, one for the other issue');
        $mb = $rowOf($b);
        Assert::true($mb !== false && $mb['kind'] === 'member' && (int) $mb['itflow_ticket_id'] === $t, 'the second server rides on the first ticket');
        Assert::contains('Also found on 203.0.113.171:22', $replies($t));
        Assert::contains('ticket_id=' . $t, $admin->get('/findings/' . $b)->body, 'the finding page links the shared ticket');
        App::itflowTickets()->run();
        Assert::same(1, substr_count($replies($t), 'Also found on 203.0.113.171:22'), 'joined once');

        // One server fixed: a note, the ticket stays open. Both fixed: resolved, with one note for all.
        $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP() WHERE id = {$a}");
        App::itflowTickets()->run();
        Assert::contains('203.0.113.170:22:</strong> verified fixed by Sentinel', $replies($t));
        Assert::contains('Other targets of this ticket are still open', $replies($t));
        Assert::notContains('resolve:' . $t, json_encode($sent()['log'] ?? []), 'not resolved while a target is open');
        App::itflowTickets()->run();
        Assert::same(1, substr_count($replies($t), 'verified fixed by Sentinel (no longer seen'), 'noted once');
        $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP() WHERE id = {$b}");
        App::itflowTickets()->run();
        Assert::contains('resolve:' . $t, json_encode($sent()['log']));
        Assert::contains('Every target of this ticket is fixed or decided in Sentinel', $replies($t));

        // The second server comes back: the resolved ticket is reopened, naming it.
        $ctx->db->exec("UPDATE findings SET status = 'open', resolved_at = NULL, reappeared = 1 WHERE id = {$b}");
        App::itflowTickets()->run();
        Assert::contains('reopen:' . $t, json_encode($sent()['log']));
        Assert::same('open', $rowOf($a)['state']);

        // Closed in ITFlow while the second server is still affected: a conclusive recheck says so, and a new ticket is
        // opened that the still-open server leads (the fixed first server stays with the old ticket).
        $setStatus($t, 'closed');
        App::itflowTickets()->run();
        Assert::same('awaiting_check', $rowOf($a)['state']);
        $job = App::scans()->queue($cid, 'manual', null, true, 'test', ['finding_id' => $b, 'ips' => ['203.0.113.171'], 'ports' => [22]], 'verify');
        $ctx->db->exec("UPDATE scan_jobs SET status = 'done', created_at = UTC_TIMESTAMP() + INTERVAL 1 SECOND WHERE id = {$job}");
        $ctx->db->exec("UPDATE findings SET verify_job_id = {$job}, verify_result = 'still_present', verify_result_at = UTC_TIMESTAMP() + INTERVAL 2 SECOND WHERE id = {$b}");
        App::itflowTickets()->run();
        $nb = $rowOf($b);
        Assert::true($nb !== false && $nb['kind'] === 'finding' && (int) $nb['itflow_ticket_id'] > 0 && (int) $nb['itflow_ticket_id'] !== $t, 'the open server leads a new ticket');
        Assert::same('replaced', (string) $ctx->db->query("SELECT state FROM itflow_tickets WHERE history_finding_id = {$a} AND kind = 'finding'")->fetchColumn());
        Assert::same(3, count($sent()['tickets']), 'one new ticket, not one per server');
        Assert::same(1, (int) $ctx->db->query("SELECT COUNT(*) FROM itflow_tickets WHERE finding_id = {$other}")->fetchColumn(), 'the other issue is untouched');

        // A fixed target released by a replacement gets a ticket again when it comes back.
        $t2 = (int) $nb['itflow_ticket_id'];
        $c = $finding('vuln:203.0.113.172:22:CVE-2099-0950', 'vuln', $title, '203.0.113.172:22', 'CVE-2099-0950');
        App::itflowTickets()->run();
        Assert::same($t2, (int) $rowOf($c)['itflow_ticket_id'], 'joins the new ticket');
        $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP() WHERE id = {$c}");
        App::itflowTickets()->run();
        $setStatus($t2, 'closed');
        App::itflowTickets()->run();
        $job2 = App::scans()->queue($cid, 'manual', null, true, 'test', ['finding_id' => $b, 'ips' => ['203.0.113.171'], 'ports' => [22]], 'verify');
        $ctx->db->exec("UPDATE scan_jobs SET status = 'done', created_at = UTC_TIMESTAMP() + INTERVAL 1 SECOND WHERE id = {$job2}");
        $ctx->db->exec("UPDATE findings SET verify_job_id = {$job2}, verify_result = 'still_present', verify_result_at = UTC_TIMESTAMP() + INTERVAL 2 SECOND WHERE id = {$b}");
        App::itflowTickets()->run();
        $t3 = (int) $rowOf($b)['itflow_ticket_id'];
        Assert::true($t3 > 0 && $t3 !== $t2, 'replaced again');
        Assert::same('gone', (string) $rowOf($c)['state'], 'the fixed target is released, not left behind');
        $ctx->db->exec("UPDATE findings SET status = 'open', resolved_at = NULL, reappeared = 1 WHERE id = {$c}");
        App::itflowTickets()->run();
        $rc = $rowOf($c);
        Assert::true($rc !== false && (int) $rc['itflow_ticket_id'] === $t3 && $rc['kind'] === 'member', 'it came back and joined the current ticket');
        Assert::contains('ticket_id=' . $t3, $admin->get('/findings/' . $c)->body);
        // The leading finding disappears (retention deletes old resolved findings): its members are released and ticketed again.
        $ctx->db->exec("UPDATE itflow_tickets SET finding_id = NULL WHERE kind = 'finding' AND finding_id = {$b}");
        App::itflowTickets()->run();
        $rc = $rowOf($c);
        // (The leading finding lost its row too, so it opens the new ticket and the released target joins it.)
        Assert::true($rc !== false && $rc['state'] === 'open' && (int) $rc['itflow_ticket_id'] > 0 && (int) $rc['itflow_ticket_id'] !== $t3, 'released and ticketed again');
    },
    'ITFlow: a saved key never follows a new address' => function (TestContext $ctx) use ($base, $key): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '0']);
        Assert::true(App::settings()->getSecret('itflow_api_key') !== '', 'saved');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => 'https://itflow-elsewhere.example', 'api_key' => '', 'enabled' => '0']);
        Assert::same('', App::settings()->getSecret('itflow_api_key'), 'a changed address drops the saved key');
        Assert::contains('saved API key was removed', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '0']);
        Assert::true(App::settings()->getSecret('itflow_api_key') !== '', 'entered again with the new address: kept');
        // A new address with an invalid key changes nothing at all (the old key never pairs with the new address).
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', ['url' => 'https://itflow-elsewhere.example', 'api_key' => 'x', 'enabled' => '0']);
        Assert::same($base($ctx), App::settings()->get('itflow_url'), 'address unchanged after an invalid key');
        Assert::true(App::settings()->getSecret('itflow_api_key') !== '', 'key unchanged');
    },

    'ITFlow boards (1.44): the board is chosen on the Integrations page; stock ITFlow and refused moves never lose a ticket' => function (TestContext $ctx) use ($base, $setItflow, $key): void {
        $admin = $ctx->login('admin', 'Admin-Pass-0001!');
        $setItflow($ctx, [[820, 'Board Example Ltd']]);
        $store = dirname($ctx->feedsLog) . '/itflow-tickets.json';
        $failFile = dirname($ctx->feedsLog) . '/itflow-fail.json';
        @unlink($store);
        @unlink($failFile);
        $form = ['url' => $base($ctx), 'api_key' => $key, 'enabled' => '1', 'tickets' => '1'];
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', $form);
        App::itflowSync()->sync();
        $cid = (int) $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id = 820')->fetchColumn();
        $n = 0;
        $fail = static function () use ($ctx, $cid, &$n): void {
            $n++;
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at, due_at)
                               VALUES (:c, :k, 'port', 'fail', :t, 'Open.', :tg, 'x', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 14 DAY)")
                ->execute(['c' => $cid, 'k' => 'port:203.0.113.95:' . (3000 + $n), 't' => 'Board test service ' . $n, 'tg' => '203.0.113.95:' . (3000 + $n)]);
        };
        $sent = static fn (): array => json_decode((string) @file_get_contents($store), true) ?: ['tickets' => [], 'moves' => []];
        // The page never asks ITFlow itself: the boards are listed after Test connection (or a sync or ticket run).
        App::settings()->set('itflow_boards_cache', '');
        Assert::contains('listed after Test connection', $admin->get('/admin/integrations')->body);
        $admin->submit('/admin/integrations', '/admin/integrations/itflow/test', []);
        // The drop-down lists the boards, Alerts first by default.
        $page = $admin->get('/admin/integrations')->body;
        Assert::contains('Board for new tickets', $page);
        Assert::contains('Alerts (the board named &quot;Alerts&quot;)', $page);
        Assert::contains('Projects', $page);
        // A chosen board.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', $form + ['board' => '5']);
        Assert::same('5', App::settings()->fresh('itflow_board'));
        $fail();
        App::itflowTickets()->run();
        Assert::same(5, (int) (end($sent()['moves'])['board_id'] ?? 0), 'moved to the chosen board');
        // An invalid choice keeps the saved one; a board that disappeared is reported.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', $form + ['board' => '-1']);
        Assert::same('5', App::settings()->fresh('itflow_board'), 'invalid input ignored');
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', $form + ['board' => '99']);
        $fail();
        Assert::contains('the chosen board no longer exists', App::itflowTickets()->run());
        // Leave on ITFlow's default board: no move.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', $form + ['board' => '0']);
        $moves = count($sent()['moves'] ?? []);
        $fail();
        App::itflowTickets()->run();
        Assert::same($moves, count($sent()['moves'] ?? []), 'no move when left on the default board');
        // Stock ITFlow (no boards): the ticket is opened as before, nothing else.
        $admin->submit('/admin/integrations', '/admin/integrations/itflow', $form + ['board' => '']);
        file_put_contents($failFile, json_encode(['no_boards' => true]));
        $tickets = count($sent()['tickets']);
        $fail();
        $summary = App::itflowTickets()->run();
        Assert::same($tickets + 1, count($sent()['tickets']), 'ticket opened on stock ITFlow');
        Assert::same($moves, count($sent()['moves'] ?? []), 'no move without boards');
        Assert::notContains('Board:', $summary, 'nothing to report without boards');
        Assert::contains('This ITFlow lists no boards', $admin->get('/admin/integrations')->body);
        // A refused move: the ticket stays (on the default board) and the run says so.
        file_put_contents($failFile, json_encode(['move_refused' => true]));
        $fail();
        $summary = App::itflowTickets()->run();
        Assert::same($tickets + 2, count($sent()['tickets']), 'ticket kept when the move is refused');
        Assert::contains('stayed on the default board', $summary);
        Assert::same('0', App::settings()->fresh('itflow_tickets_last_ok'), 'the run is flagged');
        @unlink($failFile);
    },
];
