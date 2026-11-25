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
        $saved = ['itflow_board' => $s->fresh('itflow_board'), 'itflow_tickets_since' => $s->fresh('itflow_tickets_since')];
        $others = array_map('intval', $ctx->db->query('SELECT id FROM clients WHERE itflow_client_id IS NOT NULL AND itflow_sync_off = 0')->fetchAll(PDO::FETCH_COLUMN));
        if ($others !== []) {
            $ctx->db->exec('UPDATE clients SET itflow_sync_off = 1 WHERE id IN (' . implode(',', $others) . ')');
        }
        $s->set('itflow_board', '0');
        $s->set('itflow_tickets_since', gmdate('Y-m-d H:i:s', time() - 3600));
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
            Assert::same([['990', '[Sentinel] Fail: Telnet open - 203.0.113.95:23', 'High']], array_map(static fn (array $c): array => [$c[0], $c[1], $c[2]], $fake->calls['create']), 'one ticket, for the linked client, High for a Fail: ' . $s->fresh('itflow_tickets_last_result'));
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
        Assert::true($table !== [], 'there are links to compare');
        // One Sentinel client per PSA client; text IDs are kept exactly.
        $links = new \Sentinel\Psa\ClientLinks($ctx->db);
        [$a, $b] = array_map('intval', $ctx->db->query('SELECT id FROM clients ORDER BY id LIMIT 2')->fetchAll(PDO::FETCH_COLUMN));
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
];
