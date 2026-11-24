<?php

declare(strict_types=1);

namespace Sentinel\Findings;

use PDO;
use Sentinel\Core\Settings;

/**
 * The fix workflow: who owns a finding and when it should be fixed.
 *
 * Due dates follow a policy by severity, counted from when the finding last
 * became open: known-exploited vulnerabilities (CISA KEV) first, then other
 * Fail findings, then Warnings (defaults 7, 14 and 30 days, set by admins).
 * An admin can set a finding's own due date; it then no longer follows the
 * policy until reset. Only open findings are ever due or overdue: accepted
 * risks, false positives and resolved findings are not.
 *
 * Assignees must be active technicians or admins. Viewers can't own findings.
 *
 * Untrusted: user IDs, dates and notes from forms (validated by the
 * controller and again here where it matters).
 *
 * Security assumptions: every change is written to the finding's history;
 * the controller writes the audit log. All queries use bound parameters or
 * integers cast in PHP.
 */
final class FixWorkflow
{
    /** Allowed range for the days settings. */
    public const MIN_DAYS = 1;
    public const MAX_DAYS = 365;
    /** A finding is "due soon" this many days before its due date (reminder). */
    public const DUE_SOON_DAYS = 2;

    /** Works on the given connection and settings. */
    public function __construct(private readonly PDO $db, private readonly Settings $settings)
    {
    }

    /**
     * Days to fix for each class, from settings (clamped to a sane range).
     *
     * @return array{kev:int, fail:int, warn:int}
     */
    public function policy(): array
    {
        $out = [];
        foreach (['kev' => 7, 'fail' => 14, 'warn' => 30] as $k => $default) {
            $v = (int) $this->settings->get('due_days_' . $k);
            $out[$k] = $v >= self::MIN_DAYS && $v <= self::MAX_DAYS ? $v : $default;
        }
        return $out;
    }

    /**
     * Recompute the policy due dates (findings without an admin-set date), for one client or all.
     * Due at the end of the day (UTC), like admin-set dates, so the date shown is the last day to fix it.
     * Cheap: one UPDATE. Called after each findings refresh and when the policy changes.
     */
    public function recomputeDue(?int $clientId = null): void
    {
        $p = $this->policy();
        $sql = "UPDATE findings f LEFT JOIN kev_catalog k ON k.cve_id = f.cve_id
                SET f.due_at = TIMESTAMP(DATE(COALESCE(f.opened_at, f.first_seen)) + INTERVAL (CASE WHEN k.cve_id IS NOT NULL THEN :kev WHEN f.severity = 'fail' THEN :fail ELSE :warn END) DAY, '23:59:59')
                WHERE f.due_custom = 0" . ($clientId !== null ? ' AND f.client_id = :c' : '');
        $params = ['kev' => $p['kev'], 'fail' => $p['fail'], 'warn' => $p['warn']] + ($clientId !== null ? ['c' => $clientId] : []);
        $this->db->prepare($sql)->execute($params);
    }

    /**
     * Users who may own findings: active users whose role may triage findings (1.40; the built-in Technician and
     * Admin, as before).
     *
     * @return list<array{id:int, username:string, display_name:string}>
     */
    public function assignableUsers(): array
    {
        return (new \Sentinel\Auth\RoleRepository($this->db))->usersWith('findings.triage');
    }

    /** True if the user exists, is active and may own findings. */
    public function isAssignable(int $userId): bool
    {
        return in_array($userId, array_column($this->assignableUsers(), 'id'), true);
    }

    /**
     * Assign a finding (or unassign with null). Writes the history.
     *
     * @return array{from:?int, to:?int}|null Previous and new assignee, or null if nothing changed.
     */
    public function assign(int $findingId, ?int $assigneeId, int $byUserId, string $note = ''): ?array
    {
        if ($assigneeId !== null && !$this->isAssignable($assigneeId)) {
            throw new \InvalidArgumentException('This user cannot be assigned findings.');
        }
        $this->db->beginTransaction();
        try {
            $cur = $this->db->prepare('SELECT assigned_to FROM findings WHERE id = :id FOR UPDATE');
            $cur->execute(['id' => $findingId]);
            $from = $cur->fetchColumn();
            if ($from === false) {
                $this->db->rollBack();
                return null;
            }
            $from = $from === null ? null : (int) $from;
            if ($from === $assigneeId) {
                $this->db->rollBack();
                return null;
            }
            $this->db->prepare('UPDATE findings SET assigned_to = :a, assigned_by = :b, assigned_at = IF(:a2 IS NULL, NULL, UTC_TIMESTAMP()), updated_at = UTC_TIMESTAMP() WHERE id = :id')
                ->execute(['a' => $assigneeId, 'b' => $byUserId, 'a2' => $assigneeId, 'id' => $findingId]);
            $name = $assigneeId === null ? '' : (string) $this->db->query('SELECT username FROM users WHERE id = ' . (int) $assigneeId)->fetchColumn();
            $text = $assigneeId === null ? __('Unassigned.') : __('Assigned to {user}.', ['user' => $name]);
            $this->event($findingId, $assigneeId === null ? 'unassigned' : 'assigned', $byUserId, trim($text . ' ' . $note));
            $this->db->commit();
            return ['from' => $from, 'to' => $assigneeId];
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
    }

    /**
     * Set a finding's own due date (admins), or go back to the policy with null.
     *
     * @param string|null $date Y-m-d (validated by the caller); the finding is due at the end of that day (UTC).
     * @param bool $recompute on a reset, recompute the client's policy dates now (a bulk reset does it once afterwards)
     */
    public function setDue(int $findingId, ?string $date, int $byUserId, string $note, bool $recompute = true): void
    {
        if ($date !== null && !self::validDate($date)) {
            throw new \InvalidArgumentException('Invalid date.');
        }
        if ($date === null) {
            $this->db->prepare('UPDATE findings SET due_custom = 0, updated_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['id' => $findingId]);
            if ($recompute) { // a bulk reset recomputes once per client afterwards
                $client = (int) $this->db->query('SELECT client_id FROM findings WHERE id = ' . $findingId)->fetchColumn();
                $this->recomputeDue($client);
            }
            $this->event($findingId, 'due_changed', $byUserId, trim(__('Due date follows the policy again.') . ' ' . $note));
            return;
        }
        $this->db->prepare("UPDATE findings SET due_custom = 1, due_at = :d, updated_at = UTC_TIMESTAMP() WHERE id = :id")
            ->execute(['d' => $date . ' 23:59:59', 'id' => $findingId]);
        $this->event($findingId, 'due_changed', $byUserId, trim(__('Due date set to {date}.', ['date' => $date]) . ' ' . $note));
    }

    /** True for a real calendar date (Y-m-d) between today-1y and today+2y. */
    public static function validDate(string $date): bool
    {
        $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $date, new \DateTimeZone('UTC'));
        if ($d === false || $d->format('Y-m-d') !== $date) {
            return false;
        }
        $t = $d->getTimestamp();
        return $t > time() - 366 * 86400 && $t < time() + 2 * 366 * 86400;
    }

    /**
     * Open findings that are overdue or due soon, of active clients, with client and assignee.
     *
     * @return list<array<string,mixed>>
     */
    public function dueItems(): array
    {
        return $this->db->query(
            "SELECT f.id, f.client_id, f.title, f.target, f.severity, f.due_at, f.assigned_to, c.name AS client_name,
                    u.username, u.email, u.alert_email, u.is_active AS user_active, u.role AS user_role,
                    f.due_at < UTC_TIMESTAMP() AS overdue
             FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 AND c.is_demo = 0 LEFT JOIN users u ON u.id = f.assigned_to
             WHERE f.status = 'open' AND f.due_at IS NOT NULL AND f.due_at < UTC_TIMESTAMP() + INTERVAL " . self::DUE_SOON_DAYS . " DAY
             ORDER BY f.due_at, f.id LIMIT 5000"
        )->fetchAll();
    }

    /**
     * Counts of open findings per assignee state, for the findings page and dashboards.
     *
     * @return array{overdue:int, due_soon:int, mine:int, unassigned:int}
     */
    public function counts(int $userId): array
    {
        $stmt = $this->db->prepare(
            "SELECT SUM(f.due_at < UTC_TIMESTAMP()) AS overdue,
                    SUM(f.due_at >= UTC_TIMESTAMP() AND f.due_at < UTC_TIMESTAMP() + INTERVAL " . self::DUE_SOON_DAYS . " DAY) AS due_soon,
                    SUM(f.assigned_to = :u) AS mine, SUM(f.assigned_to IS NULL) AS unassigned
             FROM findings f JOIN clients c ON c.id = f.client_id AND c.is_archived = 0 WHERE f.status = 'open'"
        );
        $stmt->execute(['u' => $userId]);
        $r = $stmt->fetch() ?: [];
        return ['overdue' => (int) ($r['overdue'] ?? 0), 'due_soon' => (int) ($r['due_soon'] ?? 0), 'mine' => (int) ($r['mine'] ?? 0), 'unassigned' => (int) ($r['unassigned'] ?? 0)];
    }

    /** Hour (UTC) after which the daily reminders go out. */
    public const REMINDER_HOUR_UTC = 7;

    /**
     * True once per UTC day, from REMINDER_HOUR_UTC on: the caller then sends the daily reminders.
     * The day is recorded first, so a failure can't make the reminders repeat every minute.
     */
    public function claimDailyReminders(?\DateTimeImmutable $now = null): bool
    {
        $now ??= new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $today = $now->format('Y-m-d');
        if ((int) $now->format('G') < self::REMINDER_HOUR_UTC || $this->settings->fresh('fix_reminders_last_run') === $today) {
            return false;
        }
        $this->settings->set('fix_reminders_last_run', $today);
        return true;
    }

    /** Append a history event. */
    private function event(int $findingId, string $event, ?int $userId, ?string $note): void
    {
        $this->db->prepare('INSERT INTO finding_events (finding_id, event, user_id, note, created_at) VALUES (:f, :e, :u, :n, UTC_TIMESTAMP())')
            ->execute(['f' => $findingId, 'e' => $event, 'u' => $userId, 'n' => $note]);
    }
}
