<?php

declare(strict_types=1);

namespace Sentinel\Inventory;

use PDO;
use Sentinel\Alerts\AlertService;
use Sentinel\Findings\FindingsEngine;
use Sentinel\Vulns\VulnMatcher;

/**
 * Syncs internal devices from inventory sources: for each linked client, read
 * the organisation's snapshot from the source, save it, match installed
 * software to known vulnerabilities, refresh the client's findings and send
 * the usual alerts. Read-only towards the source and never touches devices.
 *
 * Runs from the worker (every SYNC_HOURS per client, a few clients per tick)
 * and for "Sync now" (which only marks the link as due). One sync per client
 * at a time (named lock). Archived clients are skipped.
 *
 * Security assumptions: the source is only asked about the organisation an
 * admin linked to this client; everything it returns is untrusted and
 * cleaned by InventoryRepository. Error messages from sources contain no
 * secrets (InventoryException).
 */
final class InventorySync
{
    /** Hours between syncs of one client. */
    public const SYNC_HOURS = 6;
    /** Most clients synced in one worker tick. */
    public const PER_TICK = 3;

    /** @param array<string,InventorySource> $sources Configured sources by name. */
    public function __construct(
        private readonly PDO $db,
        private readonly InventoryRepository $repo,
        private readonly array $sources,
        private readonly ?VulnMatcher $matcher,
        private readonly ?FindingsEngine $findings,
        private readonly ?AlertService $alerts,
    ) {
    }

    /**
     * Sync the clients that are due (worker).
     *
     * @return int Clients synced (successfully or not).
     */
    public function syncDue(): int
    {
        $done = 0;
        foreach ($this->sources as $name => $source) {
            foreach ($this->repo->linksDue($name, self::SYNC_HOURS, self::PER_TICK - $done) as $link) {
                $this->syncClient((int) $link['client_id'], $name);
                $done++;
            }
            if ($done >= self::PER_TICK) {
                break;
            }
        }
        return $done;
    }

    /**
     * Sync one client from one source now.
     *
     * @return array{status:string, message:string}
     */
    public function syncClient(int $clientId, string $sourceName): array
    {
        $source = $this->sources[$sourceName] ?? null;
        $link = $this->repo->link($clientId, $sourceName);
        if ($source === null || $link === null) {
            return ['status' => 'error', 'message' => __('This source is not configured or the client is not linked.')];
        }
        $archived = $this->db->prepare('SELECT is_archived FROM clients WHERE id = :c');
        $archived->execute(['c' => $clientId]);
        if ((int) $archived->fetchColumn() === 1) {
            return ['status' => 'skipped', 'message' => __('The client is archived.')];
        }
        $lock = $this->db->quote('msp_sentinel_inventory_' . substr(hash('sha256', (string) $this->db->query('SELECT DATABASE()')->fetchColumn()), 0, 16) . '_' . $clientId);
        if ((int) $this->db->query("SELECT GET_LOCK({$lock}, 0)")->fetchColumn() !== 1) {
            return ['status' => 'skipped', 'message' => __('A sync for this client is already running.')];
        }
        try {
            try {
                $snapshot = $source->snapshot((string) $link['org_id']);
            } catch (InventoryException $ex) {
                $msg = __('{source} sync failed: {e}', ['source' => $source->label(), 'e' => mb_substr($ex->getMessage(), 0, 300)]);
                $this->repo->recordSync($clientId, $sourceName, 'error', $msg);
                return ['status' => 'error', 'message' => $msg];
            }
            $stats = $this->repo->saveSnapshot($clientId, $sourceName, $snapshot);
            $pending = 0;
            if ($this->matcher !== null) {
                try {
                    $pending = $this->matcher->matchSoftware($this->repo, $clientId, 3)['pending'];
                } catch (\Throwable $ex) {
                    error_log('[msp-sentinel] software matching failed for client ' . $clientId . ': ' . $ex->getMessage());
                }
            }
            if ($this->findings !== null) {
                try {
                    $result = $this->findings->refreshClient($clientId);
                    $this->alerts?->findingsChanged($clientId, $result, true);
                } catch (\Throwable $ex) {
                    error_log('[msp-sentinel] findings refresh after inventory sync failed for client ' . $clientId . ': ' . $ex->getMessage());
                }
            }
            $msg = __('{d} device(s), {s} program(s), {p} missing update(s)', ['d' => $stats['devices'], 's' => $stats['software'], 'p' => $stats['patches']])
                . ($stats['removed'] > 0 ? ' ' . __('{n} device(s) no longer reported.', ['n' => $stats['removed']]) : '')
                . (($snapshot['complete'] ?? false) === true ? '' : ' ' . __('The source returned partial data; devices not in it were kept.'))
                . ($pending > 0 ? ' ' . __('{n} product(s) are waiting for vulnerability data.', ['n' => $pending]) : '');
            $this->repo->recordSync($clientId, $sourceName, ($snapshot['complete'] ?? false) === true ? 'ok' : 'partial', $msg);
            return ['status' => 'ok', 'message' => $msg];
        } finally {
            $this->db->query("SELECT RELEASE_LOCK({$lock})");
        }
    }
}
