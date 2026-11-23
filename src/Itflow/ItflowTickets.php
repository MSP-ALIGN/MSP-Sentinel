<?php

declare(strict_types=1);

namespace Sentinel\Itflow;

use PDO;
use Sentinel\Core\Audit;
use Sentinel\Core\Settings;
use Sentinel\Reports\Guidance;

/**
 * Opens ITFlow tickets from findings (phase 2 of docs/ROADMAP-itflow.md):
 *
 * - Each open Fail finding, and anything known-exploited, gets its own ticket (priority High; Urgent when known
 *   exploited), with what was found, where, the evidence, why it matters, how to fix it, the due date and a link to
 *   the finding in Sentinel.
 * - A finding never gets two tickets (unique key in itflow_tickets). A finding that becomes known-exploited after its
 *   ticket was opened gets an internal note.
 * - Warnings are grouped: one ticket per client, at most once a week, and only when there are Warnings that weren't
 *   in the last weekly ticket (it lists all open Warnings, the new ones marked).
 * - Only clients linked to ITFlow (synced), not archived, not demo. Only findings opened since tickets were turned on
 *   (so turning it on doesn't flood the board), unless an admin asks for the existing ones too.
 * - At most MAX_PER_RUN tickets per run; the rest follow on the next run (every 5 minutes).
 *
 * Tickets are internal (no ticket_notify), so ITFlow doesn't email the client.
 *
 * Two-way status (phase 3), for finding tickets, in twoWay():
 * - Fixed in Sentinel (a later check no longer sees it), or marked accepted risk / false positive there: an internal
 *   note saying so, and the ticket is resolved in ITFlow.
 * - Resolved or closed in ITFlow while the finding is still open: Sentinel checks again. A finding that can be
 *   rechecked on its own gets a "verify fix" recheck straight away; a device finding waits for the device's next
 *   data (NinjaOne sync or agent scan). Fixed: done (with a note while the ticket can still take one). Still there:
 *   a resolved ticket is reopened with a note; a closed one (ITFlow can't reopen those) is replaced by a new ticket
 *   that names the old one. No conclusive answer within UNCONFIRMED_DAYS: Sentinel stops waiting and says so.
 * - A finding that comes back after Sentinel resolved its ticket: the ticket is reopened (or replaced, if closed).
 * - Weekly Warnings tickets are informational and are not followed.
 * Ticket statuses are read from ITFlow (it has no webhooks): at most STATUS_PER_RUN tickets per run, the least
 * recently checked first.
 *
 * Untrusted input: finding titles, targets, details and evidence come from scans and outside systems; every value is
 * escaped (htmlspecialchars) before it goes into the ticket's HTML. Texts written here (Guidance) are trusted.
 */
final class ItflowTickets
{
    /** Minutes between runs. */
    public const INTERVAL_MINUTES = 5;
    /** Tickets opened in one run at most. */
    public const MAX_PER_RUN = 20;
    /** Days between weekly Warnings tickets of one client. */
    public const WEEKLY_DAYS = 7;
    /** Ticket statuses read from ITFlow per run at most. */
    public const STATUS_PER_RUN = 50;
    /** Days to wait for a conclusive check after a ticket was closed in ITFlow. */
    public const UNCONFIRMED_DAYS = 10;
    /** Runs a pending ticket is looked for before it is opened again. */
    public const PENDING_TRIES = 12;
    /** Days a ticket Sentinel resolved is followed (for the problem coming back) while ITFlow doesn't close it. */
    public const RESOLVED_FOLLOW_DAYS = 30;
    /** Rechecks waiting at most, per client and overall (the same caps as the finding page's button). */
    private const VERIFY_MAX_QUEUED = 10;
    private const VERIFY_MAX_QUEUED_TOTAL = 50;

    public function __construct(private readonly PDO $db, private readonly Settings $settings, private readonly Audit $audit,
        private readonly ?ItflowClient $itflow, private readonly string $publicUrl)
    {
    }

    /** Run when due (worker). Returns the summary, or null when nothing ran. */
    public function runIfDue(): ?string
    {
        if ($this->itflow === null || $this->settings->fresh('itflow_tickets_enabled') !== '1') {
            return null;
        }
        $last = $this->settings->fresh('itflow_tickets_last_run');
        if ($last !== '' && strtotime($last . ' UTC') > time() - self::INTERVAL_MINUTES * 60) {
            return null;
        }
        return $this->run();
    }

    /**
     * Open what is due now. Returns a one-line summary; failures are recorded and returned, never thrown.
     *
     * One item that ITFlow refuses (a deleted client, a closed ticket, no access) is recorded on its row and skipped;
     * only a refused key or an unreachable ITFlow stops the run (ItflowException::stopsRun).
     */
    public function run(): string
    {
        if ($this->itflow === null) {
            return 'ITFlow is not connected.';
        }
        $lock = $this->db->quote('msp_sentinel_itflow_tickets_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
            return 'Another ticket run is going.';
        }
        try {
            $this->settings->set('itflow_tickets_last_run', gmdate('Y-m-d H:i:s'));
            $this->n = ['tickets' => 0, 'weekly' => 0, 'notes' => 0, 'resolved' => 0, 'reopened' => 0, 'replaced' => 0, 'rechecks' => 0, 'confirmed' => 0, 'skipped' => 0];
            $this->lastSkip = '';
            $this->budget = self::MAX_PER_RUN;
            $error = '';
            try {
                $this->settlePending();
                $this->twoWay();
                $this->kevNotes();
                $this->findingTickets();
                $this->weeklyTickets();
            } catch (ItflowException $ex) {
                $error = $ex->getMessage();
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] ITFlow tickets: ' . $ex->getMessage());
                $error = 'an unexpected error (see the PHP error log)';
            }
            $n = $this->n;
            $summary = sprintf('%d finding ticket(s), %d weekly Warnings ticket(s), %d note(s); %d resolved as fixed, %d recheck(s) after closing in ITFlow, %d confirmed fixed, %d reopened, %d replaced.',
                    $n['tickets'], $n['weekly'], $n['notes'], $n['resolved'], $n['rechecks'], $n['confirmed'], $n['reopened'], $n['replaced'])
                . ($n['skipped'] > 0 ? sprintf(' %d refused by ITFlow (retried later), last: %s', $n['skipped'], $this->lastSkip) : '')
                . ($error !== '' ? ' Stopped: ' . $error : '');
            $this->settings->set('itflow_tickets_last_result', mb_substr($summary, 0, 500));
            $this->settings->set('itflow_tickets_last_ok', $error === '' && $n['skipped'] === 0 ? '1' : '0');
            return $summary;
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /** @var array<string,int> counters of the current run */
    private array $n = [];
    /** Tickets this run may still open. */
    private int $budget = 0;
    private string $lastSkip = '';

    /** Count an item ITFlow refused; rethrow what should stop the run. */
    private function skip(ItflowException $ex): void
    {
        if ($ex->stopsRun()) {
            throw $ex;
        }
        $this->n['skipped']++;
        $this->lastSkip = mb_substr($ex->getMessage(), 0, 200);
    }

    /**
     * Open a ticket for a row that is written first ('pending'), so a create call that times out is found again by
     * its marker (settlePending) instead of opened twice. ITFlow refusing it marks the row 'failed' with a growing
     * retry delay; an unreachable ITFlow leaves it pending and stops the run.
     *
     * @return array{id:int, reference:string}|null the ticket, or null when ITFlow refused it
     */
    private function openTicket(int $rowId, int $itflowClient, string $subject, string $html, string $priority): ?array
    {
        $marker = 'sentinel-' . $rowId . '-' . bin2hex(random_bytes(4));
        $this->setRow($rowId, ['state' => 'pending', 'marker' => $marker]);
        try {
            $ticket = $this->itflow->createTicket($itflowClient, self::oneLine($subject, 200), $html, $priority, $marker);
        } catch (ItflowException $ex) {
            if ($ex->stopsRun()) {
                throw $ex; // unknown whether ITFlow opened it: settlePending finds out next run
            }
            $this->failRow($rowId, $ex);
            $this->skip($ex);
            return null;
        }
        $this->setRow($rowId, ['state' => 'open', 'itflow_ticket_id' => $ticket['id'], 'reference' => $ticket['reference'], 'attempts' => 0, 'retry_at' => null, 'last_error' => '']);
        $this->budget--;
        return $ticket;
    }

    /** Mark a row's ticket as refused by ITFlow; retried after 1, 2, 4 ... hours (at most a day). */
    private function failRow(int $rowId, ItflowException $ex): void
    {
        // retry_at first: MariaDB applies SET left to right, so it uses the attempts before this one.
        $this->db->prepare("UPDATE itflow_tickets SET retry_at = UTC_TIMESTAMP() + INTERVAL LEAST(1440, 60 * POW(2, LEAST(attempts, 5))) MINUTE,
                            state = 'failed', attempts = attempts + 1, last_error = :e WHERE id = :id")
            ->execute(['e' => mb_substr($ex->getMessage(), 0, 255), 'id' => $rowId]);
    }

    /**
     * Rows left 'pending' by a run that couldn't tell whether ITFlow opened the ticket: look for the ticket by its
     * marker. Found: adopted. Not found twice (runs apart, since ITFlow answers "No resource" for its own errors too):
     * opened again. A row that can't be settled (lookups refused, too many tickets to search, client unlinked) is,
     * after PENDING_TRIES runs, opened again with a warning on the finding to check ITFlow for a duplicate, so it
     * never blocks the finding or the client's weekly ticket for good.
     */
    private function settlePending(): void
    {
        $rows = $this->db->query("SELECT t.*, c.itflow_client_id FROM itflow_tickets t JOIN clients c ON c.id = t.client_id
                                  WHERE t.state = 'pending' AND t.marker <> '' ORDER BY t.attempts, t.id LIMIT 20")->fetchAll();
        foreach ($rows as $r) {
            $rowId = (int) $r['id'];
            $giveUp = static fn (string $why): array => ['state' => 'failed', 'retry_at' => gmdate('Y-m-d H:i:s'), 'attempts' => 0, 'last_error' => mb_substr($why, 0, 255)];
            if ($r['itflow_client_id'] === null) {
                $this->setRow($rowId, $giveUp('The client is no longer linked to ITFlow.'));
                continue;
            }
            try {
                $found = $this->itflow->findByMarker((int) $r['itflow_client_id'], (string) $r['marker']);
            } catch (ItflowException $ex) {
                if ($ex->kind !== ItflowException::KIND_REFUSED) {
                    throw $ex;
                }
                $this->n['skipped']++;
                $this->lastSkip = mb_substr($ex->getMessage(), 0, 200);
                $this->setRow($rowId, (int) $r['attempts'] + 1 >= self::PENDING_TRIES
                    ? $giveUp('Could not confirm whether ITFlow opened this ticket (' . $ex->getMessage() . '); opening it again. Check ITFlow for a duplicate.')
                    : ['attempts' => (int) $r['attempts'] + 1, 'last_error' => mb_substr($ex->getMessage(), 0, 255)]);
                continue;
            }
            if ($found === null) {
                $this->setRow($rowId, (int) $r['attempts'] >= 1 ? $giveUp('Not found in ITFlow after an unclear answer; opening it again.')
                    : ['attempts' => (int) $r['attempts'] + 1, 'last_error' => 'Not found in ITFlow yet; checking again next run.']);
                continue;
            }
            $this->setRow($rowId, ['state' => 'open', 'itflow_ticket_id' => $found['id'], 'reference' => $found['reference'], 'attempts' => 0, 'retry_at' => null, 'last_error' => '']);
            if ($r['finding_id'] !== null) {
                $this->event((int) $r['finding_id'], 'ITFlow ticket ' . ($found['reference'] !== '' ? $found['reference'] : '#' . $found['id']) . ' opened.');
            }
            $this->n[$r['kind'] === 'weekly' ? 'weekly' : 'tickets']++;
        }
    }

    /** Follow the finding tickets both ways (see the class notes). */
    private function twoWay(): void
    {
        $rows = $this->db->query(
            "SELECT t.*, t.id AS row_id, f.status AS f_status, f.resolved_at AS f_resolved_at, f.triage_note, f.verify_result, f.verify_result_at,
                    f.verify_requested_at, f.last_seen AS f_last_seen, f.title, f.target, f.evidence, f.finding_key, c.itflow_client_id,
                    vj.created_at AS vj_created_at, vj.status AS vj_status,
                    IF(d.source = 'agent', d.last_full_seen, d.last_seen) AS d_seen
             FROM itflow_tickets t JOIN findings f ON f.id = t.finding_id
             JOIN clients c ON c.id = t.client_id AND c.is_archived = 0 AND c.is_demo = 0 AND c.itflow_client_id IS NOT NULL
             LEFT JOIN scan_jobs vj ON vj.id = f.verify_job_id
             LEFT JOIN devices d ON d.id = f.device_id
             WHERE t.kind = 'finding' AND (t.state IN ('open', 'sentinel_resolved', 'awaiting_check')
                   OR (t.state = 'done' AND f.status = 'open')            -- done means it was fixed or decided: open again = came back
                   OR (t.state = 'unconfirmed' AND f.status <> 'open'))   -- fixed later: resolve the ticket after all
             ORDER BY t.status_checked_at IS NOT NULL, t.status_checked_at, t.id LIMIT " . self::STATUS_PER_RUN
        )->fetchAll();
        foreach ($rows as $r) {
            try {
                $this->follow($r);
            } catch (ItflowException $ex) {
                $this->setRow((int) $r['row_id'], ['last_error' => mb_substr($ex->getMessage(), 0, 255)]);
                $this->skip($ex);
            }
        }
    }

    /** One finding ticket's two-way step. @param array<string,mixed> $r */
    private function follow(array $r): void
    {
        $rowId = (int) $r['row_id'];
        $findingId = (int) $r['finding_id'];
        $itflowClient = (int) $r['itflow_client_id'];
        $ticket = (int) $r['itflow_ticket_id'];
        $ref = $r['reference'] !== '' ? $r['reference'] : '#' . $ticket;
        $fixedInSentinel = $r['f_status'] !== 'open';
        $status = $this->itflow->ticketStatus($ticket);
        $now = $this->dbNow(); // the database's clock, like findings.last_seen and scan_jobs.created_at
        $this->setRow($rowId, ['itflow_status' => $status, 'status_checked_at' => $now, 'last_error' => '']);
        if ($status === 'gone') {
            // ITFlow answers "No resource" for its own query errors too: give up only on a second answer an hour later.
            if ($r['gone_seen_at'] === null || strtotime($r['gone_seen_at'] . ' UTC') > strtotime($now . ' UTC') - 3600) {
                if ($r['gone_seen_at'] === null) {
                    $this->setRow($rowId, ['gone_seen_at' => $now]);
                }
                return;
            }
            $this->setRow($rowId, ['state' => 'gone']);
            $this->event($findingId, 'ITFlow ticket ' . $ref . ' is gone from ITFlow (deleted, or the API key can no longer see it). Sentinel stops following it'
                . ($fixedInSentinel ? '.' : ' and opens a new ticket while the problem is open.'));
            return;
        }
        if ($r['gone_seen_at'] !== null) {
            $this->setRow($rowId, ['gone_seen_at' => null]);
        }
        switch ($r['state']) {
            case 'open':
                if ($fixedInSentinel) {
                    // Fixed (or decided) in Sentinel: say so and resolve the ticket.
                    if ($status === 'open') {
                        $this->fixedNoteOnce($r);
                        $this->itflow->resolveTicket($itflowClient, $ticket);
                        $this->n['resolved']++;
                        $this->event($findingId, 'ITFlow ticket ' . $ref . ' resolved: ' . ($r['f_status'] === 'resolved' ? 'no longer seen by Sentinel.' : 'decided in Sentinel.'));
                    }
                    $this->setRow($rowId, ['state' => $status === 'closed' ? 'done' : 'sentinel_resolved', 'last_note_at' => $now]);
                } elseif ($status !== 'open') {
                    // Resolved or closed in ITFlow, still open here: check again.
                    $verify = $this->requestVerify($r);
                    if ($verify === 'later') {
                        $this->setRow($rowId, ['status_checked_at' => null]); // recheck limits reached: try again next run
                        return;
                    }
                    $this->setRow($rowId, ['state' => 'awaiting_check', 'closed_seen_at' => $now]);
                    $this->n['rechecks'] += $verify === 'queued' ? 1 : 0;
                    $this->event($findingId, 'ITFlow ticket ' . $ref . ' was ' . $status . ' in ITFlow; '
                        . ($verify === 'queued' ? 'Sentinel is rechecking it (in the client\'s scan window).' : 'Sentinel checks again with its next scan or device data.'));
                }
                return;
            case 'awaiting_check':
                if ($fixedInSentinel) {
                    if ($status === 'resolved') {
                        $this->fixedNoteOnce($r);
                    }
                    $this->setRow($rowId, ['state' => 'done']);
                    $this->event($findingId, 'Confirmed fixed by Sentinel after ITFlow ticket ' . $ref . ' was closed.');
                    $this->n['confirmed']++;
                    return;
                }
                if ($status === 'open') {
                    $this->setRow($rowId, ['state' => 'open', 'closed_seen_at' => null]); // reopened in ITFlow by someone
                    return;
                }
                if ($this->stillThere($r)) {
                    $this->stillOpen($r, $status, 'ITFlow ticket ' . $ref . ' was closed, but Sentinel still sees this problem.');
                    return;
                }
                if (strtotime($r['closed_seen_at'] . ' UTC') < time() - self::UNCONFIRMED_DAYS * 86400) {
                    $this->setRow($rowId, ['state' => 'unconfirmed']);
                    $this->event($findingId, 'ITFlow ticket ' . $ref . ' was closed, and Sentinel could not confirm the fix within ' . self::UNCONFIRMED_DAYS . ' days. The finding stays open here.');
                }
                return;
            case 'unconfirmed':
                // Fixed in Sentinel after all (selected only then): say so, and resolve the ticket if it was reopened.
                if ($status !== 'closed') {
                    $this->fixedNoteOnce($r);
                }
                if ($status === 'open') {
                    $this->itflow->resolveTicket($itflowClient, $ticket);
                }
                $this->setRow($rowId, ['state' => 'done']);
                $this->event($findingId, 'Confirmed fixed by Sentinel after ITFlow ticket ' . $ref . ' was closed.');
                $this->n['confirmed']++;
                return;
            default:
                // sentinel_resolved (or done with the finding open again): the problem came back.
                if (!$fixedInSentinel) {
                    $this->stillOpen($r, $status, 'This problem came back after ITFlow ticket ' . $ref . ' was resolved.');
                } elseif ($status === 'closed' || ($r['last_note_at'] !== null && strtotime($r['last_note_at'] . ' UTC') < time() - self::RESOLVED_FOLLOW_DAYS * 86400)) {
                    $this->setRow($rowId, ['state' => 'done']); // closed, or resolved long enough: stop reading it
                }
        }
    }

    /**
     * The problem is (still or again) there while the ticket is resolved or closed: reopen a resolved ticket with a
     * note; replace a closed one (ITFlow can't reopen those). An open ticket only needs following again.
     *
     * @param array<string,mixed> $r
     */
    private function stillOpen(array $r, string $status, string $why): void
    {
        $rowId = (int) $r['row_id'];
        if ($status === 'open') {
            $this->setRow($rowId, ['state' => 'open', 'closed_seen_at' => null]);
            return;
        }
        if ($status === 'resolved') {
            $this->itflow->reopenTicket((int) $r['itflow_client_id'], (int) $r['itflow_ticket_id']);
            $this->itflow->addNote((int) $r['itflow_client_id'], (int) $r['itflow_ticket_id'], '<p><strong>' . self::h($why) . '</strong> The ticket was reopened.</p>' . $this->evidenceHtml($r));
            $this->setRow($rowId, ['state' => 'open', 'closed_seen_at' => null, 'fixed_noted_at' => null, 'last_note_at' => gmdate('Y-m-d H:i:s')]);
            $this->event((int) $r['finding_id'], $why . ' Ticket reopened.');
            $this->n['reopened']++;
            return;
        }
        if ($this->budget > 0) {
            $this->replace($r, $why);
        } else {
            $this->setRow($rowId, ['status_checked_at' => null]); // first in line next run
        }
    }

    /**
     * Whether a check after the ticket was closed in ITFlow conclusively saw the problem again. Only new observations
     * count, never a findings refresh from stored data (which moves last_seen for every current issue):
     * - a "verify fix" recheck queued after the close that finished with "still present", or
     * - for a device finding: device data received after the close (the sync time of that device, or the agent's last
     *   full scan) that the findings engine has processed since (last_seen at or after it), with the finding still open.
     * Anything else (other finding types, a recheck that couldn't tell) waits, up to UNCONFIRMED_DAYS.
     *
     * @param array<string,mixed> $r
     */
    private function stillThere(array $r): bool
    {
        $since = (string) $r['closed_seen_at'];
        if ($r['verify_result'] === 'still_present' && $r['vj_created_at'] !== null && (string) $r['vj_created_at'] >= $since
            && $r['vj_status'] === 'done' && (string) $r['verify_result_at'] >= (string) $r['vj_created_at']) {
            return true;
        }
        return $r['d_seen'] !== null && (string) $r['d_seen'] > $since && (string) $r['f_last_seen'] >= (string) $r['d_seen'];
    }

    /**
     * Queue a "verify fix" recheck for a finding whose ticket was closed in ITFlow, with the finding page's rules: the
     * finding can be rechecked on its own, the client isn't paused, the target is in scope and the port in the
     * client's profile, at most one per finding every 10 minutes, and the same caps on waiting rechecks. Unlike the
     * button (a person asking), it waits for the client's scan window.
     *
     * @param array<string,mixed> $r
     * @return string 'queued' (or one already on its way), 'later' (limits reached: try again next run), or 'no'
     *                (this finding can't be rechecked on its own; its next scan or device data decides)
     */
    private function requestVerify(array $r): string
    {
        $target = \Sentinel\Findings\VerifyTarget::fromKey((string) $r['finding_key']);
        $client = \Sentinel\Core\App::clients()->find((int) $r['client_id']);
        if ($target === null || $client === null || (int) $client['scanning_paused'] === 1 || (int) $client['is_demo'] === 1 || \Sentinel\Core\App::scope()->globallyPaused()
            || !\Sentinel\Core\App::scope()->isInScope((int) $client['id'], $target['kind'] === 'email' ? $target['domain'] : $target['ip'])
            || ($target['kind'] === 'endpoint' && !in_array($target['port'], \Sentinel\Scanning\PortProfile::forClient($client), true))) {
            return 'no';
        }
        $id = (int) $r['finding_id'];
        if (in_array($r['vj_status'], ['queued', 'running'], true)) {
            return 'queued'; // one is already on its way
        }
        if ($r['verify_requested_at'] !== null && strtotime($r['verify_requested_at'] . ' UTC') > time() - 600) {
            return 'later';
        }
        $waiting = $this->db->prepare("SELECT SUM(client_id = :c), COUNT(*) FROM scan_jobs WHERE job_type = 'verify' AND status IN ('queued','running')");
        $waiting->execute(['c' => $client['id']]);
        [$forClient, $total] = array_map('intval', $waiting->fetch(PDO::FETCH_NUM));
        if ($forClient >= self::VERIFY_MAX_QUEUED || $total >= self::VERIFY_MAX_QUEUED_TOTAL) {
            return 'later';
        }
        if ($target['kind'] === 'email') {
            $payload = ['finding_id' => $id, 'email_domain' => $target['domain']];
        } else {
            $stmt = $this->db->prepare('SELECT hostnames FROM assets WHERE client_id = :c AND ip = :ip');
            $stmt->execute(['c' => $client['id'], 'ip' => $target['ip']]);
            $names = array_values(array_filter(explode(',', (string) $stmt->fetchColumn())));
            $payload = ['finding_id' => $id, 'ips' => [$target['ip']], 'hostnames' => [], 'ports' => [$target['port']], 'names' => [$target['ip'] => array_slice($names, 0, 20)]];
        }
        try {
            $jobId = \Sentinel\Core\App::scans()->queue((int) $client['id'], 'manual', null, false, 'Verify fix: ITFlow ticket closed (finding #' . $id . ')', $payload, 'verify');
        } catch (\DomainException) {
            return 'no';
        }
        $this->db->prepare('UPDATE findings SET verify_requested_at = UTC_TIMESTAMP(), verify_job_id = :j WHERE id = :id')->execute(['j' => $jobId, 'id' => $id]);
        $this->db->prepare("INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, 'verify_requested', NULL, :n, UTC_TIMESTAMP())")
            ->execute(['f' => $id, 'n' => 'Requested because its ITFlow ticket was closed.']);
        return 'queued';
    }

    /** The "verified fixed" (or decided) note, at most once until the ticket is reopened. @param array<string,mixed> $r */
    private function fixedNoteOnce(array $r): void
    {
        if ($r['fixed_noted_at'] !== null) {
            return;
        }
        $this->itflow->addNote((int) $r['itflow_client_id'], (int) $r['itflow_ticket_id'], $this->fixedNote($r));
        $this->setRow((int) $r['row_id'], ['fixed_noted_at' => gmdate('Y-m-d H:i:s'), 'last_note_at' => gmdate('Y-m-d H:i:s')]);
    }

    /** The database's current UTC time. */
    private function dbNow(): string
    {
        return (string) $this->db->query('SELECT UTC_TIMESTAMP()')->fetchColumn();
    }

    /**
     * A new ticket for a finding whose old ticket was closed while the problem is still there. The old row keeps the
     * finding in history_finding_id.
     *
     * @param array<string,mixed> $r
     */
    private function replace(array $r, string $why): void
    {
        $f = $this->findingForTicket((int) $r['finding_id']);
        if ($f === null) {
            return;
        }
        $this->db->beginTransaction();
        try {
            $this->db->prepare("UPDATE itflow_tickets SET state = 'replaced', history_finding_id = finding_id, finding_id = NULL WHERE id = :id")->execute(['id' => $r['row_id']]);
            $newRow = $this->newRow((int) $r['client_id'], 'finding', (int) $r['finding_id'], (string) $f['severity'], (int) $f['in_kev'] === 1);
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
        $ticket = $this->openTicket($newRow, (int) $r['itflow_client_id'], $this->subject($f), '<p><strong>' . self::h($why) . '</strong></p>' . $this->findingHtml($f), $this->priority($f));
        if ($ticket === null) {
            return; // retried as a normal finding ticket
        }
        $this->event((int) $r['finding_id'], $why . ' New ITFlow ticket ' . ($ticket['reference'] !== '' ? $ticket['reference'] : '#' . $ticket['id']) . ' opened.');
        $this->audit->log('itflow.ticket_opened', null, 'itflow-tickets', 'finding', (int) $r['finding_id'], ['itflow_ticket_id' => $ticket['id'], 'replaces' => (int) $r['itflow_ticket_id']]);
        $this->n['replaced']++;
    }

    /** A finding with what its ticket needs (client name, KEV), or null. @return array<string,mixed>|null */
    private function findingForTicket(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT f.*, c.name AS client_name, (k.cve_id IS NOT NULL) AS in_kev, k.required_action AS kev_action, k.due_date AS kev_due
                                    FROM findings f JOIN clients c ON c.id = f.client_id LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id WHERE f.id = :id');
        $stmt->execute(['id' => $id]);
        $f = $stmt->fetch();
        return $f === false ? null : $f;
    }

    /** Insert a pending row (itflow_ticket_id 0 until ITFlow answers). Returns its ID. */
    private function newRow(int $clientId, string $kind, ?int $findingId, string $severity, bool $kev): int
    {
        $this->db->prepare("INSERT INTO itflow_tickets (client_id, kind, finding_id, itflow_ticket_id, severity_at_open, kev_noted, state, created_at)
                            VALUES (:c, :k, :f, 0, :s, :kev, 'pending', UTC_TIMESTAMP())")
            ->execute(['c' => $clientId, 'k' => $kind, 'f' => $findingId, 's' => in_array($severity, ['fail', 'warn'], true) ? $severity : null, 'kev' => $kev ? 1 : 0]);
        return (int) $this->db->lastInsertId();
    }

    /** @param array<string,mixed> $f */
    private function subject(array $f): string
    {
        $kev = (int) $f['in_kev'] === 1;
        return '[Sentinel] ' . ($kev ? 'Known exploited: ' : ($f['severity'] === 'fail' ? 'Fail: ' : 'Warning: '))
            . preg_replace('/^Known exploited: /', '', (string) $f['title']) . ' - ' . $f['target'];
    }

    /** @param array<string,mixed> $f */
    private function priority(array $f): string
    {
        return (int) $f['in_kev'] === 1 ? 'Urgent' : 'High';
    }

    /** The note when Sentinel no longer sees the problem, or it was decided in Sentinel. @param array<string,mixed> $r */
    private function fixedNote(array $r): string
    {
        $reason = (string) $r['triage_note'] !== '' ? '<p>Reason: ' . self::h($r['triage_note']) . '</p>' : '';
        return match ((string) $r['f_status']) {
            'resolved' => '<p><strong>Verified fixed by Sentinel.</strong> Its checks no longer see this problem (since ' . self::h($r['f_resolved_at']) . ' UTC).</p>',
            'accepted' => '<p><strong>Marked as an accepted risk in Sentinel.</strong></p>' . $reason,
            'false_positive' => '<p><strong>Marked as a false positive in Sentinel.</strong></p>' . $reason,
            default => '<p>Closed in Sentinel.</p>',
        };
    }

    /** What Sentinel sees, for a note (every value escaped). @param array<string,mixed> $r */
    private function evidenceHtml(array $r): string
    {
        $link = $this->publicUrl !== '' ? rtrim($this->publicUrl, '/') . '/findings/' . (int) $r['finding_id'] : '';
        return '<p>' . self::h($r['title']) . ' - ' . self::h($r['target']) . ((string) $r['evidence'] !== '' ? '<br>Evidence: ' . self::h($r['evidence']) : '')
            . '<br>Last seen: ' . self::h($r['f_last_seen']) . ' UTC</p>'
            . ($link !== '' ? '<p><a href="' . self::h($link) . '">' . self::h($link) . '</a></p>' : '');
    }

    /** @param array<string,mixed> $fields column => value; the column names are this class's own, never input */
    private function setRow(int $id, array $fields): void
    {
        $sets = implode(', ', array_map(static fn (string $k): string => "{$k} = :{$k}", array_keys($fields)));
        $this->db->prepare("UPDATE itflow_tickets SET {$sets} WHERE id = :id")->execute($fields + ['id' => $id]);
    }

    /** A line in the finding's history. */
    private function event(int $findingId, string $note): void
    {
        $this->db->prepare("INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, 'itflow_ticket', NULL, :n, UTC_TIMESTAMP())")
            ->execute(['f' => $findingId, 'n' => mb_substr($note, 0, 1000)]);
    }

    /**
     * Tickets for open Fail and known-exploited findings that have none yet (or whose ticket ITFlow refused and is
     * due a retry). Only findings opened since tickets were turned on, or added to the KEV list since then.
     */
    private function findingTickets(): void
    {
        if ($this->budget <= 0) {
            return;
        }
        $since = $this->settings->fresh('itflow_tickets_since');
        $since = $since !== '' ? $since : gmdate('Y-m-d H:i:s');
        $stmt = $this->db->prepare(
            "SELECT f.id, c.itflow_client_id, t.id AS row_id
             FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 AND c.is_demo = 0 AND c.itflow_client_id IS NOT NULL
             LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
             LEFT JOIN itflow_tickets t ON t.kind = 'finding' AND t.finding_id = f.id
             WHERE f.status = 'open' AND (t.id IS NULL OR t.state = 'gone' OR (t.state = 'failed' AND t.retry_at <= UTC_TIMESTAMP()))
               AND (f.severity = 'fail' OR k.cve_id IS NOT NULL OR t.state = 'failed')
               AND (t.id IS NOT NULL OR COALESCE(f.opened_at, f.first_seen) >= :since OR k.date_added >= DATE(:since2))
             ORDER BY (k.cve_id IS NOT NULL) DESC, f.id LIMIT " . $this->budget
        );
        $stmt->execute(['since' => $since, 'since2' => $since]);
        foreach ($stmt->fetchAll() as $row) {
            if ($this->budget <= 0) {
                return;
            }
            $f = $this->findingForTicket((int) $row['id']);
            if ($f === null) {
                continue;
            }
            $kev = (int) $f['in_kev'] === 1;
            $rowId = $row['row_id'] !== null ? (int) $row['row_id'] : null;
            if ($rowId !== null && $this->db->query('SELECT state FROM itflow_tickets WHERE id = ' . $rowId)->fetchColumn() === 'gone') {
                // The old ticket is gone from ITFlow: keep it in the history and open a new one.
                $this->db->prepare('UPDATE itflow_tickets SET history_finding_id = finding_id, finding_id = NULL WHERE id = :id')->execute(['id' => $rowId]);
                $rowId = null;
            }
            $rowId ??= $this->newRow((int) $f['client_id'], 'finding', (int) $f['id'], (string) $f['severity'], $kev);
            $this->setRow($rowId, ['kev_noted' => $kev ? 1 : 0, 'severity_at_open' => $f['severity']]);
            $ticket = $this->openTicket($rowId, (int) $row['itflow_client_id'], $this->subject($f), $this->findingHtml($f), $this->priority($f));
            if ($ticket === null) {
                continue;
            }
            $this->event((int) $f['id'], 'ITFlow ticket ' . ($ticket['reference'] !== '' ? $ticket['reference'] : '#' . $ticket['id']) . ' opened.');
            $this->audit->log('itflow.ticket_opened', null, 'itflow-tickets', 'finding', (int) $f['id'], ['itflow_ticket_id' => $ticket['id'], 'reference' => $ticket['reference']]);
            $this->n['tickets']++;
        }
    }

    /**
     * A note on open finding tickets whose finding has joined the KEV list since the ticket was opened. A ticket that
     * can't take the note (closed, gone) is marked kev_noted = 2 and not tried again.
     */
    private function kevNotes(): void
    {
        $rows = $this->db->query(
            "SELECT t.id AS row_id, t.itflow_ticket_id, c.itflow_client_id, k.required_action AS kev_action, k.due_date AS kev_due
             FROM itflow_tickets t JOIN findings f ON f.id = t.finding_id AND f.status = 'open'
             JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 AND c.is_demo = 0 AND c.itflow_client_id IS NOT NULL
             JOIN kev_catalog k ON k.cve_id = f.cve_id
             WHERE t.kind = 'finding' AND t.state = 'open' AND t.kev_noted = 0 LIMIT 50"
        )->fetchAll();
        foreach ($rows as $r) {
            $html = '<p><strong>Sentinel: this problem is now known to be exploited by attackers</strong> (CISA KEV list). Treat it as urgent.</p>'
                . ((string) $r['kev_action'] !== '' ? '<p>Required action: ' . self::h($r['kev_action']) . '</p>' : '')
                . ((string) $r['kev_due'] !== '' ? '<p>CISA due date: ' . self::h($r['kev_due']) . '</p>' : '');
            try {
                $this->itflow->addNote((int) $r['itflow_client_id'], (int) $r['itflow_ticket_id'], $html);
            } catch (ItflowException $ex) {
                $this->skip($ex);
                $this->setRow((int) $r['row_id'], ['kev_noted' => 2, 'last_error' => mb_substr($ex->getMessage(), 0, 255)]);
                continue;
            }
            $this->setRow((int) $r['row_id'], ['kev_noted' => 1, 'last_note_at' => gmdate('Y-m-d H:i:s')]);
            $this->n['notes']++;
        }
    }

    /**
     * One ticket per client for Warnings, at most weekly, when there are Warnings not in the last one. Weekly
     * tickets count from itflow_tickets_weekly_since (when tickets were turned on), which the "existing Fails"
     * button doesn't move.
     */
    private function weeklyTickets(): void
    {
        $since = $this->settings->fresh('itflow_tickets_weekly_since');
        if ($since === '') {
            $since = $this->settings->fresh('itflow_tickets_since');
            $since = $since !== '' && $since >= '2001' ? $since : gmdate('Y-m-d H:i:s');
            $this->settings->set('itflow_tickets_weekly_since', $since);
        }
        $clients = $this->db->query(
            "SELECT c.id, c.name, c.itflow_client_id,
                    (SELECT MAX(t.created_at) FROM itflow_tickets t WHERE t.client_id = c.id AND t.kind = 'weekly' AND t.state NOT IN ('pending', 'failed')) AS last_weekly,
                    (SELECT MAX(t.id) FROM itflow_tickets t WHERE t.client_id = c.id AND t.kind = 'weekly' AND t.state = 'failed' AND t.retry_at <= UTC_TIMESTAMP()) AS retry_row
             FROM clients c WHERE c.is_archived = 0 AND c.is_demo = 0 AND c.itflow_client_id IS NOT NULL
               AND EXISTS (SELECT 1 FROM findings f WHERE f.client_id = c.id AND f.status = 'open' AND f.severity = 'warn')
               AND NOT EXISTS (SELECT 1 FROM itflow_tickets t WHERE t.client_id = c.id AND t.kind = 'weekly'
                               AND (t.state = 'pending' OR (t.state = 'failed' AND t.retry_at > UTC_TIMESTAMP())))
             ORDER BY c.id"
        )->fetchAll();
        foreach ($clients as $c) {
            if ($this->budget <= 0) {
                return;
            }
            $last = $c['last_weekly'];
            if ($last !== null && strtotime($last . ' UTC') > time() - self::WEEKLY_DAYS * 86400) {
                continue;
            }
            $cut = $last ?? $since;
            // The new ones first, so the list (at most 100) always holds them.
            $stmt = $this->db->prepare("SELECT f.* FROM findings f LEFT JOIN itflow_tickets t ON t.kind = 'finding' AND t.finding_id = f.id
                                        WHERE f.client_id = :c AND f.status = 'open' AND f.severity = 'warn' AND t.id IS NULL
                                        ORDER BY COALESCE(f.opened_at, f.first_seen) >= :cut DESC, f.finding_type, f.id LIMIT 100");
            $stmt->execute(['c' => $c['id'], 'cut' => $cut]);
            $warnings = $stmt->fetchAll();
            $new = array_filter($warnings, static fn (array $f): bool => (string) ($f['opened_at'] ?? $f['first_seen']) >= $cut);
            if ($new === []) {
                continue; // nothing new since the last weekly ticket (or since tickets were turned on)
            }
            $rowId = $c['retry_row'] !== null ? (int) $c['retry_row'] : $this->newRow((int) $c['id'], 'weekly', null, 'warn', false);
            $ticket = $this->openTicket($rowId, (int) $c['itflow_client_id'], '[Sentinel] ' . count($new) . ' new security warning(s) this week - ' . $c['name'],
                $this->weeklyHtml((string) $c['name'], $warnings, $cut), 'Medium');
            if ($ticket === null) {
                continue;
            }
            $this->db->prepare('UPDATE itflow_tickets SET created_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['id' => $rowId]);
            $this->audit->log('itflow.ticket_opened', null, 'itflow-tickets', 'client', (int) $c['id'], ['itflow_ticket_id' => $ticket['id'], 'kind' => 'weekly', 'warnings' => count($warnings)]);
            $this->n['weekly']++;
        }
    }

    /** The ticket text for one finding (HTML; every value escaped). @param array<string,mixed> $f */
    private function findingHtml(array $f): string
    {
        $kev = (int) ($f['in_kev'] ?? 0) === 1;
        $g = Guidance::for($f, ['in_kev' => $kev ? 1 : 0, 'kev_action' => $f['kev_action'] ?? null]);
        $link = $this->publicUrl !== '' ? rtrim($this->publicUrl, '/') . '/findings/' . (int) $f['id'] : '';
        $rows = [
            'Client' => $f['client_name'], 'Severity' => $kev ? 'Fail - known exploited (CISA KEV)' : ($f['severity'] === 'fail' ? 'Fail' : 'Warning'),
            'Where' => $f['target'], 'Found' => $f['detail'], 'Evidence' => $f['evidence'], 'CVE' => $f['cve_id'],
            'First seen' => ($f['first_seen'] ?? '') !== '' ? $f['first_seen'] . ' UTC' : '', 'Fix by' => ($f['due_at'] ?? '') !== '' && $f['due_at'] !== null ? substr((string) $f['due_at'], 0, 10) : '',
        ];
        $html = '<p><strong>' . self::h($f['title']) . '</strong></p><table>';
        foreach ($rows as $label => $value) {
            if ((string) $value !== '') {
                $html .= '<tr><td><strong>' . self::h($label) . '</strong></td><td>' . self::h($value) . '</td></tr>';
            }
        }
        $html .= '</table>';
        $html .= '<p><strong>Why it matters</strong><br>' . self::h($g['meaning']) . '</p>';
        $html .= '<p><strong>How to fix it</strong><br>' . nl2br(self::h($g['fix'])) . '</p>';
        if ($kev && (string) ($f['kev_action'] ?? '') !== '') {
            $html .= '<p><strong>CISA required action</strong><br>' . self::h($f['kev_action']) . ((string) ($f['kev_due'] ?? '') !== '' ? ' (CISA due date ' . self::h($f['kev_due']) . ')' : '') . '</p>';
        }
        if ($link !== '') {
            $html .= '<p>Open in Sentinel: <a href="' . self::h($link) . '">' . self::h($link) . '</a></p>';
        }
        return $html . '<p><em>Opened by MSP Sentinel. Sentinel checks again when its next scan runs.</em></p>';
    }

    /**
     * The weekly Warnings ticket (HTML; every value escaped).
     *
     * @param list<array<string,mixed>> $warnings
     */
    private function weeklyHtml(string $client, array $warnings, string $cut): string
    {
        $base = $this->publicUrl !== '' ? rtrim($this->publicUrl, '/') : '';
        $html = '<p><strong>Open security warnings for ' . self::h($client) . '</strong> (' . count($warnings) . '). Warnings are less urgent than Fails; plan them in.</p><ul>';
        foreach ($warnings as $f) {
            $isNew = (string) ($f['opened_at'] ?? $f['first_seen']) >= $cut;
            $g = Guidance::for($f);
            $html .= '<li>' . ($isNew ? '<strong>NEW</strong> ' : '') . self::h($f['title']) . ' - ' . self::h($f['target'])
                . '<br><em>Fix:</em> ' . self::h(self::oneLine($g['fix'], 400))
                . ($base !== '' ? '<br><a href="' . self::h($base . '/findings/' . (int) $f['id']) . '">' . self::h($base . '/findings/' . (int) $f['id']) . '</a>' : '') . '</li>';
        }
        return $html . '</ul><p><em>Opened by MSP Sentinel: one ticket a week while there are new warnings.</em></p>';
    }

    /** HTML-escape a value from anywhere. */
    private static function h(mixed $v): string
    {
        return htmlspecialchars(is_scalar($v) ? (string) $v : '', ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** Text on one line (no control characters), shortened. */
    private static function oneLine(string $s, int $max): string
    {
        return mb_substr(trim((string) preg_replace('/[\p{Cc}\p{Cf}\s]+/u', ' ', $s)), 0, $max);
    }
}
