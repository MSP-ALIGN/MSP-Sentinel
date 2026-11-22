<?php

declare(strict_types=1);

namespace Sentinel\Itflow;

use PDO;
use Sentinel\Core\Audit;
use Sentinel\Core\Settings;

/**
 * Keeps Sentinel's clients in step with ITFlow (phase 1 of docs/ROADMAP-itflow.md). ITFlow is the system of record:
 *
 * - A new ITFlow client becomes a Sentinel client with its ITFlow ID. It has no authorisation, so it is never
 *   scanned until someone records the client's written permission (that rule doesn't change for synced clients).
 * - An unlinked Sentinel client with the same name (ignoring case) is linked instead of duplicated.
 * - A name change in ITFlow is applied (when the new name isn't taken by another Sentinel client).
 * - Archived in ITFlow -> archived in Sentinel (marked as archived by the sync); unarchived in ITFlow -> restored,
 *   but only when the sync archived it (a client an admin archived in Sentinel stays archived).
 * - An ITFlow client that is already archived when first seen is not created.
 * - Clients missing from ITFlow's answer are left alone (the key may simply not see them).
 * - Demo clients are never touched.
 * - MSP Align is linked automatically when it is connected: a Sentinel client with an ITFlow ID and no MSP Align link
 *   gets the MSP Align client whose psa_id is that ITFlow ID.
 *
 * Runs from the worker every minute but only works every 15 minutes (or on "Sync now"), under a database lock.
 * Every change is written to the audit log as "itflow-sync".
 *
 * Untrusted input: names from ITFlow and MSP Align (cleaned: control characters removed, length capped; views escape).
 */
final class ItflowSync
{
    /** Minutes between syncs. */
    public const INTERVAL_MINUTES = 15;

    public function __construct(private readonly PDO $db, private readonly Settings $settings, private readonly Audit $audit,
        private readonly ?ItflowClient $itflow, private readonly ?\Sentinel\Compliance\AlignClient $align = null)
    {
    }

    /** Sync when due (worker). Returns the summary, or null when nothing ran. */
    public function syncIfDue(): ?string
    {
        if ($this->itflow === null || $this->settings->fresh('itflow_enabled') !== '1') {
            return null;
        }
        $last = $this->settings->fresh('itflow_last_sync');
        if ($last !== '' && strtotime($last . ' UTC') > time() - self::INTERVAL_MINUTES * 60) {
            return null;
        }
        return $this->sync();
    }

    /**
     * Sync now. Returns a one-line summary; failures are recorded and returned, never thrown.
     */
    public function sync(): string
    {
        if ($this->itflow === null) {
            return 'ITFlow is not connected.';
        }
        $lock = $this->db->quote('msp_sentinel_itflow_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16));
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
            return 'Another ITFlow sync is running.';
        }
        try {
            $this->settings->set('itflow_last_sync', gmdate('Y-m-d H:i:s'));
            try {
                $s = $this->syncClients($this->itflow->clients());
                $summary = sprintf('%d new, %d linked by name, %d renamed, %d archived, %d restored (%d ITFlow clients).',
                    $s['created'], $s['linked'], $s['renamed'], $s['archived'], $s['restored'], $s['seen']);
                if ($s['conflicts'] > 0) {
                    $summary .= ' ' . $s['conflicts'] . ' name(s) left as they were because another client has that name.';
                }
                $ok = true;
            } catch (ItflowException $ex) {
                $summary = 'Failed: ' . $ex->getMessage();
                $ok = false;
            }
            if ($ok && $this->align !== null) {
                $summary .= ' ' . $this->linkAlign();
            }
            $this->settings->set('itflow_last_result', mb_substr($summary, 0, 500));
            $this->settings->set('itflow_last_ok', $ok ? '1' : '0');
            return $summary;
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }

    /**
     * Apply ITFlow's client list.
     *
     * @param list<array{id:int, name:string, archived:bool}> $clients
     * @return array{seen:int, created:int, linked:int, renamed:int, archived:int, restored:int, conflicts:int}
     */
    public function syncClients(array $clients): array
    {
        $s = ['seen' => count($clients), 'created' => 0, 'linked' => 0, 'renamed' => 0, 'archived' => 0, 'restored' => 0, 'conflicts' => 0];
        $byItflow = $this->db->prepare('SELECT * FROM clients WHERE itflow_client_id = :i AND is_demo = 0 ORDER BY id LIMIT 1');
        $byName = $this->db->prepare('SELECT * FROM clients WHERE LOWER(name) = LOWER(:n) AND itflow_client_id IS NULL AND is_demo = 0 LIMIT 1');
        foreach ($clients as $c) {
            $name = self::clean($c['name']);
            if ($name === '') {
                continue;
            }
            $byItflow->execute(['i' => $c['id']]);
            $mine = $byItflow->fetch();
            if ($mine === false) {
                if ($c['archived']) {
                    continue; // not worth creating a client that is already archived in ITFlow
                }
                $byName->execute(['n' => $name]);
                $same = $byName->fetch();
                if ($same !== false) {
                    $this->db->prepare('UPDATE clients SET itflow_client_id = :i, updated_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['i' => $c['id'], 'id' => $same['id']]);
                    $this->log('client.itflow_linked', (int) $same['id'], ['itflow_client_id' => $c['id']]);
                    $s['linked']++;
                    $mine = $same + ['itflow_client_id' => $c['id']];
                } else {
                    $this->create($c['id'], $this->nameTaken($name) ? mb_substr($name, 0, 130) . ' (ITFlow #' . $c['id'] . ')' : $name);
                    $s['created']++;
                    continue;
                }
            }
            $id = (int) $mine['id'];
            if ($mine['name'] !== $name && !str_ends_with((string) $mine['name'], '(ITFlow #' . $c['id'] . ')')) {
                if ($this->nameTaken($name, $id)) {
                    $s['conflicts']++;
                } else {
                    $this->db->prepare('UPDATE clients SET name = :n, updated_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['n' => $name, 'id' => $id]);
                    $this->log('client.itflow_renamed', $id, ['from' => $mine['name'], 'to' => $name]);
                    $s['renamed']++;
                }
            }
            if ($c['archived'] && (int) $mine['is_archived'] === 0) {
                $this->db->prepare('UPDATE clients SET is_archived = 1, itflow_archived = 1, updated_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['id' => $id]);
                $this->log('client.archived', $id, ['reason' => 'archived in ITFlow']);
                $s['archived']++;
            } elseif (!$c['archived'] && (int) $mine['is_archived'] === 1 && (int) ($mine['itflow_archived'] ?? 0) === 1) {
                $this->db->prepare('UPDATE clients SET is_archived = 0, itflow_archived = 0, updated_at = UTC_TIMESTAMP() WHERE id = :id')->execute(['id' => $id]);
                $this->log('client.restored', $id, ['reason' => 'unarchived in ITFlow']);
                $s['restored']++;
            }
        }
        return $s;
    }

    /** Link unlinked Sentinel clients to MSP Align clients whose psa_id is their ITFlow ID. */
    private function linkAlign(): string
    {
        try {
            $byPsa = [];
            foreach ($this->align->clients() as $a) {
                if (($a['psa_id'] ?? '') !== '' && ctype_digit($a['psa_id'])) {
                    $byPsa[(int) $a['psa_id']] = $a;
                }
            }
        } catch (\Sentinel\Compliance\AlignException $ex) {
            return 'MSP Align not linked: ' . $ex->getMessage();
        }
        $n = 0;
        $rows = $this->db->query('SELECT id, itflow_client_id FROM clients WHERE itflow_client_id IS NOT NULL AND align_client_id IS NULL AND is_demo = 0 AND is_archived = 0')->fetchAll();
        foreach ($rows as $r) {
            $a = $byPsa[(int) $r['itflow_client_id']] ?? null;
            if ($a !== null) {
                $this->db->prepare('UPDATE clients SET align_client_id = :a, align_client_name = :n, updated_at = UTC_TIMESTAMP() WHERE id = :id')
                    ->execute(['a' => $a['id'], 'n' => mb_substr(self::clean($a['name']), 0, 190), 'id' => $r['id']]);
                $this->log('client.align_linked', (int) $r['id'], ['align_client_id' => $a['id'], 'matched_by' => 'ITFlow ID']);
                $n++;
            }
        }
        return $n > 0 ? $n . ' linked to MSP Align by ITFlow ID.' : '';
    }

    /** A new Sentinel client (and its default site), with Sentinel's usual defaults and no authorisation. */
    private function create(int $itflowId, string $name): void
    {
        $this->db->beginTransaction();
        try {
            $this->db->prepare(
                "INSERT INTO clients (name, itflow_client_id, timezone, scan_window_start, scan_window_end, notes, ports_extra, ports_excluded, created_by, created_at, updated_at)
                 VALUES (:n, :i, 'UTC', '22:00:00', '06:00:00', :notes, '', '', NULL, UTC_TIMESTAMP(), UTC_TIMESTAMP())"
            )->execute(['n' => $name, 'i' => $itflowId, 'notes' => 'Created from ITFlow (client #' . $itflowId . '). Not scanned until its authorisation is recorded.']);
            $id = (int) $this->db->lastInsertId();
            $this->db->prepare("INSERT INTO sites (client_id, name, is_default, created_at, updated_at) VALUES (:c, 'Main site', 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())")->execute(['c' => $id]);
            $this->db->commit();
        } catch (\Throwable $ex) {
            $this->db->rollBack();
            throw $ex;
        }
        $this->log('client.created', $id, ['source' => 'ITFlow', 'itflow_client_id' => $itflowId]);
    }

    private function nameTaken(string $name, ?int $exceptId = null): bool
    {
        $stmt = $this->db->prepare('SELECT COUNT(*) FROM clients WHERE LOWER(name) = LOWER(:n)' . ($exceptId === null ? '' : ' AND id <> ' . (int) $exceptId));
        $stmt->execute(['n' => $name]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** @param array<string,mixed> $details */
    private function log(string $action, int $clientId, array $details): void
    {
        $this->audit->log($action, null, 'itflow-sync', 'client', $clientId, $details);
    }

    /** A name from another system: no control or bidi characters, single spaces, at most 150 characters. */
    private static function clean(string $name): string
    {
        $name = (string) preg_replace('/[\p{Cc}\p{Cf}]/u', '', mb_scrub($name, 'UTF-8'));
        return mb_substr(trim((string) preg_replace('/\s+/u', ' ', $name)), 0, 150);
    }
}
