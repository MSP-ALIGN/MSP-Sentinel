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
        $s->set('itflow_board', '0');
        $s->set('itflow_tickets_since', gmdate('Y-m-d H:i:s', time() - 3600));
        $ctx->db->exec("INSERT INTO clients (name, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, itflow_client_id, created_at, updated_at)
                        VALUES ('Fake PSA Example', 'UTC', '00:00:00', '23:59:00', '', '', '', 990, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
        $cid = (int) $ctx->db->lastInsertId();
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
            Assert::same([[990, '[Sentinel] Fail: Telnet open - 203.0.113.95:23', 'High']], array_map(static fn (array $c): array => [$c[0], $c[1], $c[2]], $fake->calls['create']), 'one ticket, for the linked client, High for a Fail: ' . $s->fresh('itflow_tickets_last_result'));
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
        } finally {
            $ctx->db->exec("DELETE FROM itflow_tickets WHERE client_id = {$cid}");
            $ctx->db->exec("UPDATE clients SET is_archived = 1, itflow_client_id = NULL WHERE id = {$cid}");
        }
    },
];
