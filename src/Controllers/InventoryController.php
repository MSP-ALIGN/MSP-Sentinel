<?php

declare(strict_types=1);

namespace Sentinel\Controllers;

use Sentinel\Core\App;
use Sentinel\Core\HttpException;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Core\Session;
use Sentinel\Inventory\InventoryException;

/**
 * Internal devices from inventory sources (NinjaOne): linking a client to an
 * organisation in the source, "Sync now", and one device's details.
 *
 * Access (enforced by the routes): everyone signed in can view devices;
 * technicians and admins can ask for a sync; only admins link and unlink.
 *
 * Untrusted: {id}, {device}, the chosen organisation ID and the source name
 * (checked against the configured sources and the source's own list).
 *
 * Security assumptions: an organisation is linked only by an admin's explicit
 * choice from the source's own list (suggestions are never applied
 * automatically), and one organisation can belong to only one client.
 * Every change is in the audit log. Syncs are read-only towards the source.
 */
final class InventoryController extends Controller
{
    /** GET /clients/{id}/inventory/link (admins): pick the organisation, with a suggestion by name. */
    public function linkForm(Request $request, array $params): Response
    {
        $client = $this->client($params);
        if ((int) $client['is_archived'] === 1) {
            Session::flash('warning', __('This client is archived. Restore it before linking it.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/devices');
        }
        [$name, $source] = $this->source($request->query('source'));
        $orgs = [];
        $error = '';
        try {
            $orgs = $source->organisations();
        } catch (InventoryException $ex) {
            $error = __('{source} could not be reached: {e}', ['source' => $source->label(), 'e' => mb_substr($ex->getMessage(), 0, 300)]);
        }
        usort($orgs, static fn (array $a, array $b): int => strcasecmp($a['name'], $b['name']));
        return $this->page('inventory/link', __('Link {client} to {source}', ['client' => $client['name'], 'source' => $source->label()]), [
            'client' => $client, 'sourceName' => $name, 'sourceLabel' => $source->label(), 'orgs' => $orgs, 'error' => $error,
            'suggested' => self::suggest((string) $client['name'], $orgs), 'link' => App::inventory()->link((int) $client['id'], $name),
        ]);
    }

    /** POST /clients/{id}/inventory/link (admins). */
    public function link(Request $request, array $params): Response
    {
        $client = $this->client($params);
        if ((int) $client['is_archived'] === 1) {
            Session::flash('warning', __('This client is archived. Restore it before linking it.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/devices');
        }
        if ((int) ($client['is_demo'] ?? 0) === 1) {
            Session::flash('info', __('This is a demo client with made-up data: it can\'t be linked to a real inventory source.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/devices');
        }
        [$name, $source] = $this->source($request->input('source'));
        $orgId = $request->input('org_id');
        try {
            $orgs = $source->organisations();
        } catch (InventoryException $ex) {
            Session::flash('danger', __('{source} could not be reached: {e}', ['source' => $source->label(), 'e' => mb_substr($ex->getMessage(), 0, 300)]));
            return Response::redirect('/clients/' . (int) $client['id'] . '/devices');
        }
        $org = null;
        foreach ($orgs as $o) {
            if ($o['id'] === $orgId) {
                $org = $o; // only an organisation the source itself lists can be linked
            }
        }
        if ($org === null) {
            Session::flash('danger', __('Choose an organisation from the list.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/inventory/link?source=' . rawurlencode($name));
        }
        if (App::inventory()->orgLinkedElsewhere($name, $org['id'], (int) $client['id'])) {
            Session::flash('danger', __('This organisation is already linked to another client.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/inventory/link?source=' . rawurlencode($name));
        }
        // Another organisation than before (1.49): unlink the old one first, so its devices and their findings leave this
        // client (closed as "unlinked", not as fixed) instead of staying for good; the new one starts as a first import.
        $previous = App::inventory()->link((int) $client['id'], $name);
        if ($previous !== null && (string) $previous['org_id'] !== $org['id']) {
            App::inventorySync()->unlink((int) $client['id'], $name, (int) $this->user()['id']);
            $this->audit($request, 'inventory.unlinked', 'client', (int) $client['id'], ['source' => $name, 'org_id' => mb_substr((string) $previous['org_id'], 0, 64), 'reason' => 'relinked']);
        }
        try {
            App::inventory()->setLink((int) $client['id'], $name, $org['id'], $org['name'], (int) $this->user()['id']);
        } catch (\DomainException) {
            Session::flash('danger', __('This organisation is already linked to another client.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/inventory/link?source=' . rawurlencode($name));
        }
        $this->audit($request, 'inventory.linked', 'client', (int) $client['id'], ['source' => $name, 'org_id' => mb_substr($org['id'], 0, 64), 'org_name' => mb_substr($org['name'], 0, 200)]);
        Session::flash('success', __('Linked to {org}. Devices appear after the first sync (within a minute).', ['org' => $org['name']]));
        return Response::redirect('/clients/' . (int) $client['id'] . '/devices');
    }

    /** POST /clients/{id}/inventory/unlink (admins): devices are marked removed and their findings resolve. */
    public function unlink(Request $request, array $params): Response
    {
        $client = $this->client($params);
        [$name] = $this->source($request->input('source'));
        if (App::inventory()->link((int) $client['id'], $name) !== null) {
            App::inventorySync()->unlink((int) $client['id'], $name, (int) $this->user()['id']);
            $this->audit($request, 'inventory.unlinked', 'client', (int) $client['id'], ['source' => $name]);
        }
        Session::flash('success', __('Unlinked. Its devices are no longer shown and their findings were closed (noted as unlinked, not as fixed).'));
        return Response::redirect('/clients/' . (int) $client['id'] . '/devices');
    }

    /** POST /clients/{id}/inventory/sync (technicians and admins): sync within a minute (worker). */
    public function sync(Request $request, array $params): Response
    {
        $client = $this->client($params);
        [$name] = $this->source($request->input('source'));
        if ((int) $client['is_archived'] === 1) {
            Session::flash('warning', __('This client is archived.'));
        } elseif ((int) ($client['is_demo'] ?? 0) === 1) {
            Session::flash('info', __('This is a demo client with made-up data: it is never synced.'));
        } elseif (App::inventory()->link((int) $client['id'], $name) === null) {
            Session::flash('warning', __('This client is not linked yet.'));
        } else {
            App::db()->prepare('UPDATE source_links SET last_sync_at = NULL WHERE client_id = :c AND source = :s')->execute(['c' => (int) $client['id'], 's' => $name]);
            $this->audit($request, 'inventory.sync_requested', 'client', (int) $client['id'], ['source' => $name]);
            Session::flash('success', __('Sync requested. It runs within a minute (after any scan already running).'));
        }
        return Response::redirect('/clients/' . (int) $client['id'] . '/devices');
    }

    /** GET /clients/{id}/devices/{device}: one internal device with its software, vulnerabilities and missing updates. */
    public function device(Request $request, array $params): Response
    {
        $client = $this->client($params);
        $device = App::inventory()->device((int) $client['id'], (int) ($params['device'] ?? 0)) ?? throw new HttpException(404);
        // An agent device merged into an inventory device (1.38): its page is the combined one, while that device is
        // still current and this client's (else this page shows on its own).
        if (($device['merged_into'] ?? null) !== null) {
            $t = App::db()->prepare('SELECT COUNT(*) FROM devices WHERE id = :t AND client_id = :c AND removed_at IS NULL');
            $t->execute(['t' => (int) $device['merged_into'], 'c' => (int) $client['id']]);
            if ((int) $t->fetchColumn() === 1) {
                return Response::redirect('/clients/' . (int) $client['id'] . '/devices/' . (int) $device['merged_into']);
            }
        }
        // The combined device: this row and the agent devices merged into it (findings, open services, protocol issues).
        $merged = App::inventory()->mergedInto((int) $client['id'], (int) $device['id']);
        $ids = array_merge([(int) $device['id']], array_map(static fn (array $m): int => (int) $m['id'], $merged));
        $stmt = App::db()->prepare('SELECT id, severity, status, title FROM findings WHERE client_id = ? AND device_id IN (' . implode(',', array_fill(0, count($ids), '?')) . ")
                                    AND status <> 'resolved' ORDER BY severity = 'fail' DESC, id");
        $stmt->execute(array_merge([(int) $client['id']], $ids));
        // One row per port (two agents may have seen the same machine), and the device-level checks (e.g. SNMP) of the
        // merged agent devices with this device's own winning.
        $ports = [];
        foreach ($ids as $id) {
            foreach (App::inventory()->ports($id) as $p) {
                $ports[(string) ($p['protocol'] ?? 'tcp') . '/' . (int) $p['port']] ??= $p;
            }
        }
        ksort($ports, SORT_NATURAL);
        $ports = array_values($ports);
        $checks = [];
        foreach (array_reverse($merged) as $m) {
            $checks = array_replace($checks, json_decode((string) ($m['checks'] ?? ''), true) ?: []);
        }
        $ruleDevice = $device;
        if ($checks !== []) {
            $ruleDevice['checks'] = (string) json_encode(array_replace($checks, json_decode((string) ($device['checks'] ?? ''), true) ?: []));
        }
        // An unmerged agent device: inventory devices an admin may merge it into (same address first).
        $candidates = [];
        if ((string) $device['source'] === 'agent') {
            $c = App::db()->prepare("SELECT id, name, ip_addresses FROM devices WHERE client_id = :c AND source <> 'agent' AND removed_at IS NULL AND merged_into IS NULL ORDER BY name LIMIT 500");
            $c->execute(['c' => (int) $client['id']]);
            $mine = array_map('trim', explode(',', (string) $device['ip_addresses']));
            foreach ($c->fetchAll() as $row) {
                $row['same_ip'] = array_intersect($mine, array_map('trim', explode(',', (string) $row['ip_addresses']))) !== [];
                $candidates[] = $row;
            }
            usort($candidates, static fn (array $a, array $b): int => [$b['same_ip'], $a['name']] <=> [$a['same_ip'], $b['name']]);
        }
        return $this->page('inventory/device', (string) ($device['name'] !== '' ? $device['name'] : $device['source_id']), [
            'client' => $client, 'device' => $device, 'deviceFindings' => $stmt->fetchAll(), 'ports' => $ports, 'merged' => $merged, 'mergeCandidates' => $candidates,
            'issues' => array_merge(\Sentinel\Inventory\DeviceRules::issues($device, $device['patches']), \Sentinel\Agent\ProtocolRules::issues($ruleDevice, $ports)),
        ]);
    }

    /**
     * POST /clients/{id}/devices/{device}/merge (admins): an agent device is the same machine as an inventory device
     * (target), or (target empty: "split") a different one, which the matching rules then leave alone (1.38).
     * Untrusted: the device and target IDs (both must belong to this client; the target must be an inventory device).
     */
    public function merge(Request $request, array $params): Response
    {
        $client = $this->client($params);
        $deviceId = (int) ($params['device'] ?? 0);
        $raw = $request->input('target');
        $target = $raw === '' ? null : (ctype_digit($raw) && strlen($raw) < 10 ? (int) $raw : -1);
        $ok = $target !== -1 && App::inventory()->setMerge((int) $client['id'], $deviceId, $target);
        if (!$ok) {
            Session::flash('danger', __('That merge is not possible: choose a device from this client\'s inventory.'));
            return Response::redirect('/clients/' . (int) $client['id'] . '/devices/' . $deviceId);
        }
        $this->audit($request, $target === null ? 'device.split' : 'device.merged', 'device', $deviceId, ['client_id' => (int) $client['id'], 'into' => $target]);
        Session::flash('success', $target === null ? __('Shown as a separate device from now on.') : __('Merged: shown as one device.'));
        return Response::redirect('/clients/' . (int) $client['id'] . '/devices/' . ($target ?? $deviceId));
    }

    /**
     * The client from {id} (404 if missing).
     *
     * @return array<string,mixed>
     */
    private function client(array $params): array
    {
        return App::clients()->find((int) ($params['id'] ?? 0)) ?? throw new HttpException(404);
    }

    /**
     * A configured source by name (default: the first), or 404.
     *
     * @return array{0:string, 1:\Sentinel\Inventory\InventorySource}
     */
    private function source(string $name): array
    {
        $sources = App::inventorySources();
        $name = $name !== '' ? $name : (string) array_key_first($sources);
        if (!isset($sources[$name])) {
            throw new HttpException(404);
        }
        return [$name, $sources[$name]];
    }

    /**
     * The organisation whose name matches the client's (ignoring case, punctuation and company suffixes), or null.
     * Only a suggestion: the admin still chooses and confirms.
     *
     * @param list<array{id:string,name:string}> $orgs
     */
    public static function suggest(string $clientName, array $orgs): ?string
    {
        $norm = static fn (string $n): string => (string) preg_replace(['/\b(ltd|limited|inc|llc|gmbh|bv|plc|pty|co|corp|corporation|company)\b\.?/i', '/[^a-z0-9]+/'], ['', ''], strtolower($n));
        $want = $norm($clientName);
        if ($want === '') {
            return null;
        }
        foreach ($orgs as $o) {
            if ($norm($o['name']) === $want) {
                return $o['id'];
            }
        }
        return null;
    }
}
