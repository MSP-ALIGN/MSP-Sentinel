<?php

declare(strict_types=1);

/**
 * The ticket workflow against an in-memory fake ticketing system (1.53): it runs on the TicketingProvider interface
 * alone, and adapts to what a PSA can do (reopen closed tickets; find a ticket again by its marker) instead of assuming
 * ITFlow. No network: the fake records calls in memory. Made-up names only.
 */

use Sentinel\Core\App;
use Sentinel\Itflow\ItflowTickets;
use Sentinel\Psa\TicketingProvider;
use Sentinel\Tests\Assert;
use Sentinel\Tests\TestContext;

if (!class_exists('FakeTicketingProvider')) {
    /** A ticketing system that only records what it is asked to do (test double). */
    final class FakeTicketingProvider implements TicketingProvider
    {
        /** @var array<string,list<mixed>> */
        public array $calls = ['create' => [], 'note' => [], 'resolve' => [], 'reopen' => [], 'marker' => []];
        /** @var array<string,string> ticket id => status */
        public array $status = [];
        /** When true, opening a ticket is refused (as a PSA refusing one request would). */
        public bool $failCreate = false;
        private int $next = 7000;

        public function __construct(private readonly bool $reopenClosed, private readonly bool $markers)
        {
        }

        public function name(): string
        {
            return 'fakepsa';
        }

        public function label(): string
        {
            return 'Fake PSA';
        }

        public function capabilities(): array
        {
            return ['reopen_closed' => $this->reopenClosed, 'markers' => $this->markers];
        }

        public function createTicket(int|string $clientId, string $subject, string $detailsHtml, string $priority, string $marker = ''): array
        {
            if ($this->failCreate) {
                throw new \Sentinel\Psa\PsaException('Refused by the fake.', \Sentinel\Psa\PsaException::KIND_REFUSED);
            }
            $id = (string) ++$this->next;
            $this->calls['create'][] = [$clientId, $subject, $priority];
            $this->status[$id] = 'open';
            return ['id' => (int) $id, 'reference' => 'FAKE-' . $id];
        }

        public function findByMarker(int|string $clientId, string $marker, string $notBefore = ''): ?array
        {
            $this->calls['marker'][] = $marker;
            return null;
        }

        public function addNote(int|string $clientId, int|string $ticketId, string $html): void
        {
            $this->calls['note'][] = [(string) $ticketId, $html];
        }

        public function ticketStatus(int|string $ticketId): string
        {
            return $this->status[(string) $ticketId] ?? 'gone';
        }

        public function resolveTicket(int|string $clientId, int|string $ticketId): void
        {
            $this->calls['resolve'][] = (string) $ticketId;
            $this->status[(string) $ticketId] = 'resolved';
        }

        public function reopenTicket(int|string $clientId, int|string $ticketId): void
        {
            $this->calls['reopen'][] = (string) $ticketId;
            $this->status[(string) $ticketId] = 'open';
        }

        public function ticketUrl(int|string $clientId, int|string $ticketId): string
        {
            return '';
        }
    }
}

return [
    'ticketing layer (1.53): the workflow runs on any ticketing system and adapts to what it can do' => function (TestContext $ctx): void {
        $s = App::settings();
        // Only this test's client takes part (1.53.1): other tests' linked clients are set aside and put back after.
        $saved = ['itflow_board' => $s->fresh('itflow_board'), 'tickets_since' => $s->fresh('tickets_since')];
        $others = array_map('intval', $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id IS NOT NULL AND itflow_sync_off = 0')->fetchAll(PDO::FETCH_COLUMN));
        if ($others !== []) {
            $ctx->db->exec('UPDATE clients SET itflow_sync_off = 1 WHERE id IN (' . implode(',', $others) . ')');
        }
        $s->set('itflow_board', '0');
        $s->set('tickets_since', gmdate('Y-m-d H:i:s', time() - 3600));
        $ctx->db->exec("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, itflow_client_id, created_at, updated_at)
                        VALUES ('Fake PSA Example', 'UTC', '00:00:00', '23:59:00', '', '', '', 990, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $cid = (int) $ctx->db->lastInsertId();
        (new \Sentinel\Psa\ClientLinks($ctx->db))->set($cid, 'itflow', '990');
        $add = static function (string $key) use ($ctx, $cid): int {
            $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at, due_at)
                               VALUES (:c, :k, 'port', 'fail', 'Telnet open', 'Port 23 open.', '203.0.113.95:23', 'x', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 14 DAY)")
                ->execute(['c' => $cid, 'k' => $key]);
            return (int) $ctx->db->lastInsertId();
        };
        try {
            // Opened and resolved through the interface alone.
            $fake = new FakeTicketingProvider(true, false);
            $tickets = new ItflowTickets($ctx->db, $s, App::audit(), $fake, '');
            $f = $add('port:203.0.113.95:23');
            $tickets->run();
            Assert::same([['990', '[Sentinel] Fail: Telnet open - 203.0.113.95:23', 'High']], array_map(static fn (array $c): array => [$c[0], $c[1], $c[2]], $fake->calls['create']), 'one ticket, for the linked client, High for a Fail: ' . $s->fresh('tickets_last_result'));
            $ticket = (string) $ctx->db->query("SELECT itflow_ticket_id FROM itflow_tickets WHERE finding_id = {$f}")->fetchColumn();
            Assert::same('7001', $ticket, 'the fake\'s ticket ID is stored');
            $ctx->db->exec("UPDATE findings SET status = 'resolved', resolved_at = UTC_TIMESTAMP(), resolved_reason = '' WHERE id = {$f}");
            $tickets->run();
            Assert::same(['7001'], $fake->calls['resolve'], 'fixed in Sentinel: resolved in the PSA');
            // A PSA that can reopen closed tickets gets its ticket reopened, not replaced.
            $r = $ctx->db->query("SELECT t.*, t.id AS row_id, c.itflow_client_id, 'open' AS f_status, f.title, f.target, f.evidence, f.last_seen AS f_last_seen
                                  FROM itflow_tickets t JOIN clients c ON c.id = t.client_id JOIN findings f ON f.id = t.finding_id WHERE t.finding_id = {$f}")->fetch();
            $fake->status['7001'] = 'closed';
            $still = new ReflectionMethod(ItflowTickets::class, 'stillOpen');
            $still->invoke($tickets, $r, [$r], 'closed', 'Seen again.');
            Assert::same(['7001'], $fake->calls['reopen'], 'reopened, because this PSA can');
            Assert::same(1, count($fake->calls['create']), 'no replacement ticket');
            // A PSA without markers: an unclear create is not looked up (it can't be); it is opened again, and says so.
            $g = $add('port:203.0.113.96:23');
            $ctx->db->exec("INSERT INTO itflow_tickets (client_id, kind, finding_id, itflow_ticket_id, severity_at_open, kev_noted, state, marker, marker_at, created_at)
                            VALUES ({$cid}, 'finding', {$g}, 0, 'fail', 0, 'pending', 'sentinel-x-1', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
            $tickets->run();
            Assert::same([], $fake->calls['marker'], 'no lookup by marker');
            Assert::same(2, count($fake->calls['create']), 'opened again in the same run (the row was given up and retried at once)');
            Assert::same('open', (string) $ctx->db->query("SELECT state FROM itflow_tickets WHERE finding_id = {$g}")->fetchColumn());
            Assert::contains('Check for a duplicate', (string) $ctx->db->query("SELECT GROUP_CONCAT(note) FROM finding_events WHERE finding_id = {$g}")->fetchColumn(), 'the possible duplicate is on the finding');
        } finally {
            $ctx->db->exec("DELETE FROM itflow_tickets WHERE client_id = {$cid}");
            $ctx->db->exec("DELETE FROM finding_events WHERE finding_id IN (SELECT id FROM findings WHERE client_id = {$cid})");
            $ctx->db->exec("DELETE FROM findings WHERE client_id = {$cid}");
            (new \Sentinel\Psa\ClientLinks($ctx->db))->set($cid, 'itflow', null);
            $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$cid}");
            if ($others !== []) {
                $ctx->db->exec('UPDATE clients SET itflow_sync_off = 0 WHERE id IN (' . implode(',', $others) . ')');
            }
            foreach ($saved as $k => $v) {
                $s->set($k, $v);
            }
        }
    },
    'ticketing layer (1.53.1): the client sync refuses the tag filter for a PSA without client tags, changing nothing' => function (TestContext $ctx): void {
        $s = App::settings();
        $saved = ['itflow_enabled' => $s->fresh('itflow_enabled'), 'itflow_tag_filter' => $s->fresh('itflow_tag_filter'), 'itflow_tag_name' => $s->fresh('itflow_tag_name')];
        $directory = new class implements \Sentinel\Psa\ClientDirectory {
            /** A client list only: no tags, no boards (test double). */
            public function clients(): array
            {
                return [['id' => 991, 'name' => 'Untagged Directory Example', 'archived' => false]];
            }
        };
        try {
            $s->set('itflow_enabled', '1');
            $s->set('itflow_tag_filter', '1');
            $s->set('itflow_tag_name', 'Sentinel');
            $before = (int) $ctx->db->query('SELECT COUNT(*) FROM clients')->fetchColumn();
            $result = (new \Sentinel\Itflow\ItflowSync($ctx->db, $s, App::audit(), $directory))->sync();
            Assert::contains('has no client tags', $result);
            Assert::same($before, (int) $ctx->db->query('SELECT COUNT(*) FROM clients')->fetchColumn(), 'nothing added');
        } finally {
            foreach ($saved as $k => $v) {
                $s->set($k, $v);
            }
        }
    },
    'client links (1.54): the migration runs twice safely; the link table and the old column always agree; one client per PSA client' => function (TestContext $ctx): void {
        $migration = require dirname(__DIR__, 2) . '/migrations/0059_psa_client_links.php';
        $m = new \Sentinel\Migrations\Migrator($ctx->db, dirname(__DIR__, 2) . '/migrations');
        $migration['up']($ctx->db, $m);
        $migration['up']($ctx->db, $m); // twice: idempotent
        // After every earlier test (forms, the ITFlow sync, links by name, unlinking): both copies say the same.
        $column = $ctx->db->query("SELECT id, CAST(itflow_client_id AS CHAR) FROM clients WHERE itflow_client_id IS NOT NULL ORDER BY id")->fetchAll(PDO::FETCH_KEY_PAIR);
        $table = $ctx->db->query("SELECT client_id, external_id FROM psa_client_links WHERE provider = 'itflow' ORDER BY client_id")->fetchAll(PDO::FETCH_KEY_PAIR);
        Assert::same($column, $table, 'psa_client_links matches clients.itflow_client_id');
        // One Sentinel client per PSA client; text IDs are kept exactly.
        $links = new \Sentinel\Psa\ClientLinks($ctx->db);
        foreach (['Link A Example', 'Link B Example'] as $name) { // two clients of its own, whatever ran before
            $ctx->db->prepare("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, is_archived, created_at, updated_at)
                               VALUES (:n, 'UTC', '22:00:00', '06:00:00', '', '', '', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())")->execute(['n' => $name]);
        }
        [$a, $b] = array_map('intval', $ctx->db->query("SELECT id FROM clients WHERE name IN ('Link A Example', 'Link B Example') ORDER BY id")->fetchAll(PDO::FETCH_COLUMN));
        $links->set($a, 'otherpsa', 'Abc-123');
        Assert::same($a, $links->clientFor('otherpsa', 'Abc-123'));
        Assert::same(null, $links->clientFor('otherpsa', 'abc-123'), 'compared exactly, case included');
        $refused = false;
        try {
            $links->set($b, 'otherpsa', 'Abc-123');
        } catch (\DomainException) {
            $refused = true;
        }
        Assert::true($refused, 'a PSA client already linked elsewhere is refused');
        $links->set($a, 'otherpsa', null);
        Assert::same(null, $links->externalFor($a, 'otherpsa'), 'unlinked');
    },
    'client links (1.54.1): a sync meeting a link held by a demo client carries on; the form says "already in use", never fails' => function (TestContext $ctx): void {
        $s = App::settings();
        $saved = ['itflow_enabled' => $s->fresh('itflow_enabled'), 'itflow_tag_filter' => $s->fresh('itflow_tag_filter')];
        $links = new \Sentinel\Psa\ClientLinks($ctx->db);
        $ctx->db->exec("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, is_demo, created_at, updated_at)
                        VALUES ('Demo Link Example', 'UTC', '22:00:00', '06:00:00', '', '', '', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $demo = (int) $ctx->db->lastInsertId();
        $links->set($demo, 'itflow', '993');
        $ctx->db->exec("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, created_at, updated_at)
                        VALUES ('Same Name Example', 'UTC', '22:00:00', '06:00:00', '', '', '', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $real = (int) $ctx->db->lastInsertId();
        $directory = new class implements \Sentinel\Psa\ClientDirectory {
            /** ITFlow client 993 (linked to the demo client) has the real client's name; 994 is new (test double). */
            public function clients(): array
            {
                return [['id' => 993, 'name' => 'Same Name Example', 'archived' => false], ['id' => 994, 'name' => 'After Conflict Example', 'archived' => false]];
            }
        };
        try {
            $s->set('itflow_enabled', '1');
            $s->set('itflow_tag_filter', '0');
            $result = (new \Sentinel\Itflow\ItflowSync($ctx->db, $s, App::audit(), $directory))->sync();
            Assert::notContains('Failed', $result, $result);
            Assert::contains('1 new', $result, 'the next client is still processed');
            Assert::same(null, $links->externalFor($real, 'itflow'), 'the real client is not linked to a PSA client the demo client holds');
            // The form: an ID linked elsewhere is "already in use" (422), never an error page.
            $admin = $ctx->login('admin', 'Admin-Pass-0001!');
            $res = $admin->submit('/clients/' . $real . '/edit', '/clients/' . $real, ['name' => 'Same Name Example', 'itflow_client_id' => '993', 'timezone' => 'UTC',
                'scan_window_start' => '22:00', 'scan_window_end' => '06:00', 'notes' => '', 'ports_extra' => '', 'ports_excluded' => '']);
            Assert::status(422, $res);
            Assert::contains('already in use', $res->body);
            // ITFlow IDs are whole numbers written plainly.
            $bad = false;
            try {
                $links->set($real, 'itflow', '007');
            } catch (\DomainException) {
                $bad = true;
            }
            Assert::true($bad, 'a non-canonical ITFlow ID is refused');
        } finally {
            foreach ($saved as $k => $v) {
                $s->set($k, $v);
            }
            $created = (int) $ctx->db->query("SELECT client_id FROM psa_client_links WHERE provider = 'itflow' AND external_id = '994'")->fetchColumn();
            foreach (array_filter([$demo, $real, $created]) as $id) {
                $links->set($id, 'itflow', null);
                $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$id}");
            }
        }
    },
    'tickets (1.55): every ticket row has its system and text ID in step with the number; ticket settings moved to neutral names' => function (TestContext $ctx): void {
        // After every earlier ITFlow test: the text ID matches the number (empty for none), and the system is ITFlow.
        $off = (int) $ctx->db->query("SELECT COUNT(*) FROM itflow_tickets WHERE provider <> 'itflow'
                                       OR external_ticket_id <> IF(itflow_ticket_id > 0, CAST(itflow_ticket_id AS CHAR), '')")->fetchColumn();
        Assert::same(0, $off, 'ticket text IDs in step'); // (with no earlier ITFlow tests there are simply no rows: still true)
        // The migration copies old settings to the new names once, keeping a value already there, and runs twice safely.
        $s = App::settings();
        $saved = $s->fresh('tickets_weekly_since');
        $savedSince = $s->fresh('tickets_since');
        try {
            $ctx->db->exec("DELETE FROM settings WHERE name = 'tickets_weekly_since'");
            $ctx->db->exec("REPLACE INTO settings (name, value) VALUES ('itflow_tickets_weekly_since', '2026-01-02 03:04:05'), ('tickets_since', 'kept-value')");
            $ctx->db->exec("REPLACE INTO settings (name, value) VALUES ('itflow_tickets_since', 'old-value')");
            $migration = require dirname(__DIR__, 2) . '/migrations/0060_neutral_tickets.php';
            $m = new \Sentinel\Migrations\Migrator($ctx->db, dirname(__DIR__, 2) . '/migrations');
            $migration['up']($ctx->db, $m);
            $migration['up']($ctx->db, $m);
            Assert::same('2026-01-02 03:04:05', $s->fresh('tickets_weekly_since'), 'copied');
            Assert::same('kept-value', $s->fresh('tickets_since'), 'a value already under the new name is kept');
        } finally {
            $ctx->db->exec("DELETE FROM settings WHERE name IN ('itflow_tickets_weekly_since', 'itflow_tickets_since')");
            $s->set('tickets_weekly_since', $saved);
            $s->set('tickets_since', $savedSince);
        }
    },
    'tickets (1.55.1): a replacement ticket that fails to open leaves no old ticket ID on the targets that moved to it' => function (TestContext $ctx): void {
        $s = App::settings();
        $saved = ['itflow_board' => $s->fresh('itflow_board'), 'tickets_since' => $s->fresh('tickets_since')];
        $others = array_map('intval', $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id IS NOT NULL AND itflow_sync_off = 0')->fetchAll(PDO::FETCH_COLUMN));
        if ($others !== []) {
            $ctx->db->exec('UPDATE clients SET itflow_sync_off = 1 WHERE id IN (' . implode(',', $others) . ')');
        }
        $s->set('itflow_board', '0');
        $s->set('tickets_since', gmdate('Y-m-d H:i:s', time() - 3600));
        $ctx->db->exec("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, created_at, updated_at)
                        VALUES ('Replace Fail Example', 'UTC', '00:00:00', '23:59:00', '', '', '', UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $cid = (int) $ctx->db->lastInsertId();
        (new \Sentinel\Psa\ClientLinks($ctx->db))->set($cid, 'itflow', '995');
        try {
            $add = static function (string $ip) use ($ctx, $cid): int {
                $ctx->db->prepare("INSERT INTO findings (client_id, finding_key, finding_type, severity, title, detail, target, evidence, status, first_seen, last_seen, opened_at, due_at)
                                   VALUES (:c, :k, 'port', 'fail', 'Telnet open', 'Port 23 open.', :t, 'x', 'open', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 14 DAY)")
                    ->execute(['c' => $cid, 'k' => 'port:' . $ip . ':23', 't' => $ip . ':23']);
                return (int) $ctx->db->lastInsertId();
            };
            $f1 = $add('203.0.113.97');
            $f2 = $add('203.0.113.98');
            $fake = new FakeTicketingProvider(false, true);
            $tickets = new ItflowTickets($ctx->db, $s, App::audit(), $fake, '');
            $tickets->run(); // one ticket for the issue; the second target joins it as a member
            $member = $ctx->db->query("SELECT id, external_ticket_id FROM itflow_tickets WHERE finding_id = {$f2} AND kind = 'member'")->fetch();
            Assert::true($member !== false && $member['external_ticket_id'] !== '', 'the member carries the ticket\'s text ID');
            // The ticket was closed while the problem is still there: it is replaced, and opening the new one fails.
            $r = $ctx->db->query("SELECT t.*, t.id AS row_id, pl.external_id AS itflow_client_id, 'open' AS f_status, f.title, f.target, f.evidence, f.last_seen AS f_last_seen
                                  FROM itflow_tickets t JOIN psa_client_links pl ON pl.client_id = t.client_id AND pl.provider = 'itflow'
                                  JOIN findings f ON f.id = t.finding_id WHERE t.finding_id = {$f1} AND t.kind = 'finding'")->fetch();
            $members = (new ReflectionMethod(ItflowTickets::class, 'members'))->invoke($tickets, (int) $r['row_id']);
            $fake->failCreate = true;
            (new ReflectionMethod(ItflowTickets::class, 'replace'))->invoke($tickets, $r, array_merge([$r], $members), 'Closed while still open.');
            $after = $ctx->db->query("SELECT itflow_ticket_id, external_ticket_id FROM itflow_tickets WHERE id = " . (int) $member['id'])->fetch();
            Assert::same(['0', ''], [(string) $after['itflow_ticket_id'], (string) $after['external_ticket_id']], 'number and text ID cleared together');
        } finally {
            $ctx->db->exec("DELETE FROM itflow_tickets WHERE client_id = {$cid}");
            $ctx->db->exec("DELETE FROM finding_events WHERE finding_id IN (SELECT id FROM findings WHERE client_id = {$cid})");
            $ctx->db->exec("DELETE FROM findings WHERE client_id = {$cid}");
            (new \Sentinel\Psa\ClientLinks($ctx->db))->set($cid, 'itflow', null);
            $ctx->db->exec("UPDATE clients SET is_archived = 1 WHERE id = {$cid}");
            if ($others !== []) {
                $ctx->db->exec('UPDATE clients SET itflow_sync_off = 0 WHERE id IN (' . implode(',', $others) . ')');
            }
            foreach ($saved as $k => $v) {
                $s->set($k, $v);
            }
        }
    },
];
