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
 * Tickets are internal (no ticket_notify), so ITFlow doesn't email the client. Closing them from ITFlow, and Sentinel
 * resolving them when a problem is fixed, are phase 3.
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

    /** Open what is due now. Returns a one-line summary; failures are recorded and returned, never thrown. */
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
            $n = ['tickets' => 0, 'weekly' => 0, 'notes' => 0];
            $error = '';
            try {
                $budget = self::MAX_PER_RUN;
                $n['notes'] = $this->kevNotes();
                $n['tickets'] = $this->findingTickets($budget);
                $budget -= $n['tickets'];
                $n['weekly'] = $budget > 0 ? $this->weeklyTickets($budget) : 0;
            } catch (ItflowException $ex) {
                $error = $ex->getMessage();
            } catch (\Throwable $ex) {
                error_log('[msp-sentinel] ITFlow tickets: ' . $ex->getMessage());
                $error = 'an unexpected error (see the PHP error log)';
            }
            $summary = sprintf('%d finding ticket(s), %d weekly Warnings ticket(s), %d note(s).', $n['tickets'], $n['weekly'], $n['notes'])
                . ($error !== '' ? ' Stopped: ' . $error : '');
            $this->settings->set('itflow_tickets_last_result', mb_substr($summary, 0, 500));
            $this->settings->set('itflow_tickets_last_ok', $error === '' ? '1' : '0');
            return $summary;
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /** Tickets for open Fail and known-exploited findings that have none yet. */
    private function findingTickets(int $budget): int
    {
        $since = $this->settings->fresh('itflow_tickets_since');
        $stmt = $this->db->prepare(
            "SELECT f.*, c.name AS client_name, c.itflow_client_id, (k.cve_id IS NOT NULL) AS in_kev, k.required_action AS kev_action, k.due_date AS kev_due
             FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 AND c.is_demo = 0 AND c.itflow_client_id IS NOT NULL
             LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
             LEFT JOIN itflow_tickets t ON t.kind = 'finding' AND t.finding_id = f.id
             WHERE f.status = 'open' AND t.id IS NULL AND (f.severity = 'fail' OR k.cve_id IS NOT NULL OR f.title LIKE 'Known exploited%')
               AND COALESCE(f.opened_at, f.first_seen) >= :since
             ORDER BY (k.cve_id IS NOT NULL) DESC, f.id LIMIT " . max(1, $budget)
        );
        $stmt->execute(['since' => $since !== '' ? $since : gmdate('Y-m-d H:i:s')]);
        $count = 0;
        foreach ($stmt->fetchAll() as $f) {
            $kev = (int) $f['in_kev'] === 1 || str_starts_with((string) $f['title'], 'Known exploited');
            $subject = '[Sentinel] ' . ($kev ? 'Known exploited: ' : 'Fail: ') . preg_replace('/^Known exploited: /', '', (string) $f['title']) . ' - ' . $f['target'];
            $ticket = $this->itflow->createTicket((int) $f['itflow_client_id'], self::oneLine($subject, 200), $this->findingHtml($f, $kev), $kev ? 'Urgent' : 'High');
            $this->db->prepare("INSERT INTO itflow_tickets (client_id, kind, finding_id, itflow_ticket_id, reference, url, severity_at_open, kev_noted, created_at)
                                VALUES (:c, 'finding', :f, :t, :r, :u, :s, :k, UTC_TIMESTAMP())")
                ->execute(['c' => $f['client_id'], 'f' => $f['id'], 't' => $ticket['id'], 'r' => $ticket['reference'], 'u' => $ticket['url'], 's' => $f['severity'], 'k' => $kev ? 1 : 0]);
            $this->db->prepare("INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, 'itflow_ticket', NULL, :n, UTC_TIMESTAMP())")
                ->execute(['f' => $f['id'], 'n' => 'ITFlow ticket ' . ($ticket['reference'] !== '' ? $ticket['reference'] : '#' . $ticket['id']) . ' opened.']);
            $this->audit->log('itflow.ticket_opened', null, 'itflow-tickets', 'finding', (int) $f['id'], ['itflow_ticket_id' => $ticket['id'], 'reference' => $ticket['reference']]);
            $count++;
        }
        return $count;
    }

    /** A note on finding tickets whose finding has become known-exploited since the ticket was opened. */
    private function kevNotes(): int
    {
        $rows = $this->db->query(
            "SELECT t.id AS row_id, t.itflow_ticket_id, f.*, c.itflow_client_id, k.required_action AS kev_action, k.due_date AS kev_due
             FROM itflow_tickets t JOIN findings f ON f.id = t.finding_id AND f.status = 'open'
             JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 AND c.is_demo = 0 AND c.itflow_client_id IS NOT NULL
             LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
             WHERE t.kind = 'finding' AND t.kev_noted = 0 AND (k.cve_id IS NOT NULL OR f.title LIKE 'Known exploited%') LIMIT 50"
        )->fetchAll();
        foreach ($rows as $r) {
            $html = '<p><strong>Sentinel: this problem is now known to be exploited by attackers</strong> (CISA KEV list). Treat it as urgent.</p>'
                . ((string) $r['kev_action'] !== '' ? '<p>Required action: ' . self::h($r['kev_action']) . '</p>' : '')
                . ((string) $r['kev_due'] !== '' ? '<p>CISA due date: ' . self::h($r['kev_due']) . '</p>' : '');
            $this->itflow->addNote((int) $r['itflow_client_id'], (int) $r['itflow_ticket_id'], $html);
            $this->db->prepare('UPDATE itflow_tickets SET kev_noted = 1, last_note_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['id' => $r['row_id']]);
        }
        return count($rows);
    }

    /** One ticket per client for Warnings, at most weekly, when there are Warnings not in the last one. */
    private function weeklyTickets(int $budget): int
    {
        $since = $this->settings->fresh('itflow_tickets_since');
        $clients = $this->db->query(
            "SELECT c.id, c.name, c.itflow_client_id, (SELECT MAX(t.created_at) FROM itflow_tickets t WHERE t.client_id = c.id AND t.kind = 'weekly') AS last_weekly
             FROM clients c WHERE c.is_archived = 0 AND c.is_demo = 0 AND c.itflow_client_id IS NOT NULL
               AND EXISTS (SELECT 1 FROM findings f WHERE f.client_id = c.id AND f.status = 'open' AND f.severity = 'warn')"
        )->fetchAll();
        $count = 0;
        foreach ($clients as $c) {
            if ($count >= $budget) {
                break;
            }
            $last = $c['last_weekly'];
            if ($last !== null && strtotime($last . ' UTC') > time() - self::WEEKLY_DAYS * 86400) {
                continue;
            }
            $stmt = $this->db->prepare("SELECT f.* FROM findings f LEFT JOIN itflow_tickets t ON t.kind = 'finding' AND t.finding_id = f.id
                                        WHERE f.client_id = :c AND f.status = 'open' AND f.severity = 'warn' AND t.id IS NULL ORDER BY f.finding_type, f.id LIMIT 100");
            $stmt->execute(['c' => $c['id']]);
            $warnings = $stmt->fetchAll();
            $cut = $last ?? ($since !== '' ? $since : gmdate('Y-m-d H:i:s'));
            $new = array_filter($warnings, static fn (array $f): bool => (string) ($f['opened_at'] ?? $f['first_seen']) >= $cut);
            if ($new === []) {
                continue; // nothing new since the last weekly ticket (or since tickets were turned on)
            }
            $ticket = $this->itflow->createTicket((int) $c['itflow_client_id'], self::oneLine('[Sentinel] ' . count($new) . ' new security warning(s) this week - ' . $c['name'], 200),
                $this->weeklyHtml((string) $c['name'], $warnings, $cut), 'Medium');
            $this->db->prepare("INSERT INTO itflow_tickets (client_id, kind, finding_id, itflow_ticket_id, reference, url, severity_at_open, created_at)
                                VALUES (:c, 'weekly', NULL, :t, :r, :u, 'warn', UTC_TIMESTAMP())")
                ->execute(['c' => $c['id'], 't' => $ticket['id'], 'r' => $ticket['reference'], 'u' => $ticket['url']]);
            $this->audit->log('itflow.ticket_opened', null, 'itflow-tickets', 'client', (int) $c['id'], ['itflow_ticket_id' => $ticket['id'], 'kind' => 'weekly', 'warnings' => count($warnings)]);
            $count++;
        }
        return $count;
    }

    /** The ticket text for one finding (HTML; every value escaped). @param array<string,mixed> $f */
    private function findingHtml(array $f, bool $kev): string
    {
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
