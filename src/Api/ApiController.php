<?php

declare(strict_types=1);

namespace Sentinel\Api;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use Sentinel\Core\App;
use Sentinel\Core\Request;
use Sentinel\Core\Response;
use Sentinel\Reports\CsvExport;
use Sentinel\Scanning\NmapRunner;

/**
 * API endpoints (JSON). One instance per request, for one authenticated token.
 *
 * Untrusted: query parameters (page, per_page, client_id, status, severity,
 * type, updated_since: each checked against fixed lists or formats), path
 * IDs, and the JSON body of write calls.
 *
 * Security assumptions:
 * - Every query is limited to the token's clients ($this->clients: null =
 *   all). A record of another client answers 404, the same as a missing one,
 *   so a token can't probe for other clients' IDs.
 * - Writes (triage, queue scan) follow the same rules as the web UI (note
 *   required, archived clients refused, scope and scan window enforced by the
 *   worker, no outside-window override), are recorded in the audit log with
 *   the token, and act as the admin who created the token.
 * - Times are UTC, in ISO 8601 ("2026-11-22T10:00:00Z").
 */
final class ApiController
{
    private const MAX_PER_PAGE = 500;

    private readonly PDO $db;
    /** @var list<int>|null */
    private readonly ?array $clients;

    /** @param array<string,mixed> $token Authenticated token row (see TokenService::authenticate). */
    public function __construct(private readonly array $token, private readonly Request $request)
    {
        $this->db = App::db();
        $this->clients = $token['client_ids'];
    }

    /** GET /api/v1/openapi.json */
    public function openapi(array $p): Response
    {
        return ApiKernel::json(OpenApi::spec(App::version()));
    }

    /** GET /api/v1/me: what this token can do. */
    public function me(array $p): Response
    {
        return ApiKernel::json(['data' => [
            'name' => $this->token['name'],
            'permissions' => array_values(array_filter(['read', (int) $this->token['can_triage'] === 1 ? 'triage' : null, (int) $this->token['can_scan'] === 1 ? 'scan' : null])),
            'clients' => $this->clients ?? 'all',
            'expires_at' => self::iso($this->token['expires_at']),
            'version' => App::version(),
        ]]);
    }

    /** GET /api/v1/clients */
    public function clients(array $p): Response
    {
        [$where, $params] = $this->scope('c.id');
        if (($since = $this->since()) !== null) {
            $where[] = 'c.updated_at >= :since';
            $params['since'] = $since;
        }
        return $this->paged('SELECT c.id, c.name, c.itflow_client_id, c.timezone, c.is_archived, c.scanning_paused, c.created_at, c.updated_at FROM clients c',
            $where, $params, 'c.id', [self::class, 'clientOut']);
    }

    /** GET /api/v1/clients/{id} */
    public function client(array $p): Response
    {
        return ApiKernel::json(['data' => self::clientOut($this->clientRow((int) $p['id']))]);
    }

    /** GET /api/v1/clients/{id}/summary: totals and rating, like the report. */
    public function summary(array $p): Response
    {
        $c = $this->clientRow((int) $p['id']);
        $cid = (int) $c['id'];
        // Counted here (not FindingRepository::counts, which skips archived clients), so archived clients report their real state.
        $cnt = $this->db->prepare("SELECT SUM(status = 'open' AND severity = 'fail') AS fail, SUM(status = 'open' AND severity = 'warn') AS warn,
                                          SUM(status = 'accepted') AS accepted, SUM(status = 'false_positive') AS false_positive FROM findings WHERE client_id = :c");
        $cnt->execute(['c' => $cid]);
        $counts = array_map('intval', $cnt->fetch() ?: []) + ['fail' => 0, 'warn' => 0, 'accepted' => 0, 'false_positive' => 0];
        $scan = $this->db->prepare("SELECT id, status, finished_at FROM scan_jobs WHERE client_id = :c AND finished_at IS NOT NULL AND job_type <> 'verify' ORDER BY id DESC LIMIT 1");
        $scan->execute(['c' => $cid]);
        $last = $scan->fetch() ?: null;
        $types = $this->db->prepare("SELECT finding_type, severity, COUNT(*) AS n FROM findings WHERE client_id = :c AND status = 'open' GROUP BY finding_type, severity");
        $types->execute(['c' => $cid]);
        $byType = [];
        foreach ($types->fetchAll() as $t) {
            $byType[$t['finding_type']][$t['severity']] = (int) $t['n'];
        }
        $assets = (int) $this->db->query('SELECT COUNT(*) FROM assets WHERE client_id = ' . $cid)->fetchColumn();
        return ApiKernel::json(['data' => [
            'client_id' => $cid,
            'name' => $c['name'],
            'archived' => (int) $c['is_archived'] === 1,
            'rating' => $counts['fail'] > 0 ? 'at_risk' : ($counts['warn'] > 0 ? 'needs_attention' : 'good'),
            'open' => ['fail' => $counts['fail'], 'warn' => $counts['warn']],
            'accepted' => $counts['accepted'],
            'false_positive' => $counts['false_positive'],
            'open_by_type' => $byType,
            'assets' => $assets,
            'last_scan' => $last === null ? null : ['scan_id' => (int) $last['id'], 'status' => $last['status'], 'finished_at' => self::iso($last['finished_at'])],
        ]]);
    }

    /** POST /api/v1/clients/{id}/scans: queue a scan (runs in the client's scan window). */
    public function queueScan(array $p): Response
    {
        $c = $this->clientRow((int) $p['id']);
        $cid = (int) $c['id'];
        if ((int) ($c['is_demo'] ?? 0) === 1) {
            throw new ApiError(409, 'This is a demo client with made-up data: it is never scanned.');
        }
        if ((int) $c['is_archived'] === 1 || (int) $c['scanning_paused'] === 1 || App::scope()->globallyPaused()) {
            throw new ApiError(409, 'Scanning is paused or the client is archived.');
        }
        if (!NmapRunner::fromConfig(App::config())->available()) {
            throw new ApiError(503, 'nmap is not installed on the Sentinel server.');
        }
        $payload = App::scanWorker()->payloadFor($c);
        if ($payload === null) {
            throw new ApiError(409, 'Nothing to scan: the client has no active authorisation with IP addresses or exact hostnames.');
        }
        $this->db->beginTransaction();
        try {
            $this->db->prepare('SELECT id FROM clients WHERE id = :id FOR UPDATE')->execute(['id' => $cid]);
            App::scans()->cancelQueuedTlsJobs($cid);
            $open = App::scans()->openJob($cid);
            if ($open !== null) {
                $this->db->rollBack();
                return ApiKernel::json(['error' => ['status' => 409, 'message' => 'A scan for this client is already queued or running.'], 'scan_id' => (int) $open['id']], 409);
            }
            $jobId = App::scans()->queue($cid, 'manual', (int) $this->token['created_by'], false, null, $payload);
            $this->db->prepare('UPDATE scan_jobs SET api_token_id = :t WHERE id = :id')->execute(['t' => $this->token['id'], 'id' => $jobId]);
            $this->db->commit();
        } catch (\Throwable $ex) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $ex;
        }
        $this->audit('scan.queued', 'scan_job', $jobId, ['client_id' => $cid, 'targets' => count($payload['ips']) + count($payload['hostnames'])]);
        return ApiKernel::json(['data' => ['scan_id' => $jobId, 'status' => 'queued', 'message' => 'Queued. It runs in the client\'s scan window.']], 202);
    }

    /** GET /api/v1/assets: assets with their open services. */
    public function assets(array $p): Response
    {
        [$where, $params] = $this->scope('a.client_id');
        $this->clientFilter($where, $params, 'a.client_id');
        if (($since = $this->since()) !== null) {
            $where[] = 'a.updated_at >= :since';
            $params['since'] = $since;
        }
        return $this->paged('SELECT a.id, a.client_id, a.ip, a.hostnames, a.itflow_asset_id, a.first_seen, a.last_seen, a.last_scanned, a.updated_at FROM assets a',
            $where, $params, 'a.id', null, function (array $rows): array {
                $ids = array_map(static fn (array $r): int => (int) $r['id'], $rows);
                $services = [];
                if ($ids !== []) {
                    foreach ($this->db->query('SELECT asset_id, port, protocol, service_name, product, version, cpe, first_seen, last_seen FROM services WHERE is_open = 1 AND asset_id IN (' . implode(',', $ids) . ') ORDER BY port')->fetchAll() as $s) {
                        $services[(int) $s['asset_id']][] = ['port' => (int) $s['port'], 'protocol' => $s['protocol'], 'service' => $s['service_name'], 'product' => $s['product'],
                            'version' => $s['version'], 'cpe' => $s['cpe'], 'first_seen' => self::iso($s['first_seen']), 'last_seen' => self::iso($s['last_seen'])];
                    }
                }
                return array_map(static fn (array $r): array => [
                    'id' => (int) $r['id'], 'client_id' => (int) $r['client_id'], 'ip' => $r['ip'],
                    'hostnames' => $r['hostnames'] === '' ? [] : explode(',', (string) $r['hostnames']),
                    'itflow_asset_id' => $r['itflow_asset_id'] === null ? null : (int) $r['itflow_asset_id'],
                    'first_seen' => self::iso($r['first_seen']), 'last_seen' => self::iso($r['last_seen']), 'last_scanned' => self::iso($r['last_scanned']),
                    'updated_at' => self::iso($r['updated_at']), 'open_services' => $services[(int) $r['id']] ?? [],
                ], $rows);
            });
    }

    /** GET /api/v1/findings */
    public function findings(array $p): Response
    {
        [$where, $params] = $this->scope('f.client_id');
        $this->clientFilter($where, $params, 'f.client_id');
        foreach (['status' => ['open', 'resolved', 'accepted', 'false_positive'], 'severity' => ['fail', 'warn'], 'type' => ['port', 'tls', 'web', 'vuln', 'email', 'patch', 'device', 'directory', 'dns', 'breach', 'pentest']] as $key => $allowed) {
            $v = $this->request->query($key);
            if ($v === '') {
                continue;
            }
            if (!in_array($v, $allowed, true)) {
                throw new ApiError(400, $key . ' must be one of: ' . implode(', ', $allowed) . '.');
            }
            $where[] = 'f.' . ($key === 'type' ? 'finding_type' : $key) . ' = :' . $key;
            $params[$key] = $v;
        }
        if (($since = $this->since()) !== null) {
            $where[] = 'f.updated_at >= :since';
            $params['since'] = $since;
        }
        return $this->paged(self::FINDING_SELECT, $where, $params, 'f.id', fn (array $f): array => $this->findingFor($f));
    }

    /** GET /api/v1/findings/{id}: one finding with its history. */
    public function finding(array $p): Response
    {
        $f = $this->findingRow((int) $p['id']);
        $maskNotes = $f['finding_type'] === 'breach' && !$this->mayReadBreaches();
        $events = array_map(static fn (array $e): array => ['event' => $e['event'],
            'note' => $maskNotes && $e['note'] !== null ? \Sentinel\Breach\BreachMonitor::maskAll((string) $e['note']) : $e['note'],
            'by' => $e['username'] ?? null, 'at' => self::iso($e['created_at'])], App::findings()->events((int) $f['id']));
        return ApiKernel::json(['data' => $this->findingFor($f) + ['history' => $events]]);
    }

    /** POST /api/v1/findings/{id}/triage: {"status": "accepted|false_positive|open", "note": "..."} */
    public function triage(array $p): Response
    {
        $f = $this->findingRow((int) $p['id']);
        $body = $this->request->jsonBody() ?? throw new ApiError(400, 'Send a JSON object: {"status": "...", "note": "..."}.');
        $status = is_string($body['status'] ?? null) ? $body['status'] : '';
        $note = is_string($body['note'] ?? null) ? trim($body['note']) : '';
        if (!in_array($status, ['accepted', 'false_positive', 'open'], true)) {
            throw new ApiError(422, 'status must be accepted, false_positive or open.');
        }
        if ($note === '' || mb_strlen($note) > 1900 || !mb_check_encoding($note, 'UTF-8')) {
            throw new ApiError(422, 'A note is required (up to 1900 characters): explain why.');
        }
        if ($f['status'] === 'resolved') {
            throw new ApiError(409, 'This finding is resolved; there is nothing to triage.');
        }
        if ((int) $f['client_archived'] === 1) {
            throw new ApiError(409, 'This client is archived.');
        }
        $full = '[API: ' . $this->token['name'] . '] ' . $note;
        $previous = App::findings()->triage((int) $f['id'], $status, $full, (int) $this->token['created_by']);
        if ($previous === null) {
            return ApiKernel::json(['data' => $this->findingFor($this->findingRow((int) $f['id'])), 'changed' => false]);
        }
        $this->audit('finding.triaged', 'finding', (int) $f['id'], ['client_id' => (int) $f['client_id'], 'from' => $previous, 'to' => $status, 'note' => mb_substr($note, 0, 300)]);
        App::events()->publish('finding.triaged', (App::events()->finding((int) $f['id']) ?? []) + ['previous_status' => $previous]);
        return ApiKernel::json(['data' => $this->findingFor($this->findingRow((int) $f['id'])), 'changed' => true]);
    }

    /** GET /api/v1/scans */
    public function scans(array $p): Response
    {
        [$where, $params] = $this->scope('j.client_id');
        $this->clientFilter($where, $params, 'j.client_id');
        return $this->paged('SELECT j.id, j.client_id, j.job_type, j.trigger_type, j.status, j.outside_window, j.api_token_id, j.created_at, j.started_at, j.finished_at, j.summary FROM scan_jobs j',
            $where, $params, 'j.id DESC', [self::class, 'scanOut']);
    }

    /** GET /api/v1/scans/{id} */
    public function scan(array $p): Response
    {
        [$where, $params] = $this->scope('j.client_id');
        $where[] = 'j.id = :id';
        $params['id'] = (int) $p['id'];
        $stmt = $this->db->prepare('SELECT j.id, j.client_id, j.job_type, j.trigger_type, j.status, j.outside_window, j.api_token_id, j.created_at, j.started_at, j.finished_at, j.summary
                                    FROM scan_jobs j WHERE ' . implode(' AND ', $where));
        $stmt->execute($params);
        $row = $stmt->fetch() ?: throw new ApiError(404, 'Not found.');
        return ApiKernel::json(['data' => self::scanOut($row)]);
    }

    /** GET /api/v1/reports */
    public function reports(array $p): Response
    {
        [$where, $params] = $this->scope('r.client_id');
        $this->clientFilter($where, $params, 'r.client_id');
        return $this->paged('SELECT r.id, r.client_id, r.kind, r.source, r.title, r.period_start, r.period_end, r.generated_at, r.html_sha256 FROM reports r',
            $where, $params, 'r.id DESC', [self::class, 'reportOut']);
    }

    /** GET /api/v1/reports/{id}: metadata and totals. */
    public function report(array $p): Response
    {
        $r = $this->reportRow((int) $p['id']);
        $snap = json_decode((string) $r['snapshot'], true) ?: [];
        return ApiKernel::json(['data' => self::reportOut($r) + ['rating' => $snap['rating']['level'] ?? null, 'counts' => $snap['counts'] ?? null]]);
    }

    /** GET /api/v1/reports/{id}/html: the frozen document. */
    public function reportHtml(array $p): Response
    {
        $r = $this->reportRow((int) $p['id']);
        $res = (new Response($this->readable((string) $r['html'])))
            ->header('Content-Type', 'text/html; charset=UTF-8')
            ->header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; sandbox")
            ->header('Content-Disposition', 'attachment; filename="report-' . (int) $r['id'] . '.html"');
        // The frozen copy's hash only when it is sent unchanged (masked copies differ).
        return $this->mayReadBreaches() ? $res->header('X-Report-SHA256', (string) $r['html_sha256']) : $res;
    }

    /** GET /api/v1/reports/{id}/csv */
    public function reportCsv(array $p): Response
    {
        $r = $this->reportRow((int) $p['id']);
        $snap = json_decode((string) $r['snapshot'], true);
        if (!is_array($snap)) {
            throw new ApiError(404, 'Not found.');
        }
        return (new Response($this->readable(CsvExport::build($snap))))
            ->header('Content-Type', 'text/csv; charset=UTF-8')
            ->header('Content-Security-Policy', "default-src 'none'; sandbox")
            ->header('Content-Disposition', 'attachment; filename="report-' . (int) $r['id'] . '.csv"');
    }

    private const FINDING_SELECT = 'SELECT f.id, f.client_id, f.asset_id, f.finding_key, f.finding_type, f.severity, f.title, f.detail, f.target, f.evidence, f.cve_id, f.status,
        f.triage_note, f.triaged_at, f.reappeared, f.reopened_count, f.first_seen, f.last_seen, f.resolved_at, f.updated_at, c.is_archived AS client_archived,
        f.due_at, f.assigned_at, au.username AS assignee_username, f.source
        FROM findings f JOIN clients c ON c.id = f.client_id LEFT JOIN users au ON au.id = f.assigned_to';

    /**
     * WHERE parts limiting a query to the token's clients.
     *
     * @return array{0:list<string>, 1:array<string,mixed>}
     */
    private function scope(string $column): array
    {
        if ($this->clients === null) {
            return [[], []];
        }
        if ($this->clients === []) {
            return [['1 = 0'], []];
        }
        return [[$column . ' IN (' . implode(',', array_map('intval', $this->clients)) . ')'], []];
    }

    /**
     * Optional ?client_id= filter.
     *
     * @param list<string> $where
     * @param array<string,mixed> $params
     */
    private function clientFilter(array &$where, array &$params, string $column): void
    {
        $v = $this->request->query('client_id');
        if ($v === '') {
            return;
        }
        if (!ctype_digit($v) || strlen($v) > 10) {
            throw new ApiError(400, 'client_id must be a number.');
        }
        $where[] = $column . ' = :client_id';
        $params['client_id'] = (int) $v;
    }

    /** The ?updated_since= value as a UTC "Y-m-d H:i:s", or null. */
    private function since(): ?string
    {
        $v = $this->request->query('updated_since');
        if ($v === '') {
            return null;
        }
        if (!preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/', $v)) {
            throw new ApiError(400, 'updated_since must be an ISO 8601 time with a time zone, e.g. 2026-11-01T00:00:00Z.');
        }
        try {
            return (new DateTimeImmutable($v))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
        } catch (\Exception) {
            throw new ApiError(400, 'updated_since is not a valid time.');
        }
    }

    /**
     * Run a paginated query and wrap it in {data, meta}.
     *
     * @param list<string> $where
     * @param array<string,mixed> $params
     * @param callable|null $map  Per-row output mapper.
     * @param callable|null $mapAll Whole-page mapper (used instead of $map).
     */
    private function paged(string $select, array $where, array $params, string $order, ?callable $map, ?callable $mapAll = null): Response
    {
        $page = $this->request->query('page');
        $per = $this->request->query('per_page');
        if (($page !== '' && (!ctype_digit($page) || (int) $page < 1 || strlen($page) > 7)) || ($per !== '' && (!ctype_digit($per) || (int) $per < 1 || (int) $per > self::MAX_PER_PAGE))) {
            throw new ApiError(400, 'page must be 1 or more; per_page from 1 to ' . self::MAX_PER_PAGE . '.');
        }
        $page = $page === '' ? 1 : (int) $page;
        $per = $per === '' ? 100 : (int) $per;
        $sqlWhere = $where === [] ? '' : ' WHERE ' . implode(' AND ', $where);
        $count = $this->db->prepare('SELECT COUNT(*) FROM (' . $select . $sqlWhere . ') x');
        $count->execute($params);
        $total = (int) $count->fetchColumn();
        $stmt = $this->db->prepare($select . $sqlWhere . ' ORDER BY ' . $order . ' LIMIT ' . $per . ' OFFSET ' . (($page - 1) * $per));
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
        $data = $mapAll !== null ? $mapAll($rows) : array_map($map, $rows);
        return ApiKernel::json(['data' => $data, 'meta' => ['page' => $page, 'per_page' => $per, 'total' => $total, 'next_page' => $page * $per < $total ? $page + 1 : null]]);
    }

    /** A client the token may see, or 404. */
    private function clientRow(int $id): array
    {
        if ($this->clients !== null && !in_array($id, $this->clients, true)) {
            throw new ApiError(404, 'Not found.');
        }
        return App::clients()->find($id) ?? throw new ApiError(404, 'Not found.');
    }

    /** A finding the token may see, or 404. */
    private function findingRow(int $id): array
    {
        [$where, $params] = $this->scope('f.client_id');
        $where[] = 'f.id = :id';
        $params['id'] = $id;
        $stmt = $this->db->prepare(self::FINDING_SELECT . ' WHERE ' . implode(' AND ', $where));
        $stmt->execute($params);
        return $stmt->fetch() ?: throw new ApiError(404, 'Not found.');
    }

    /** A report the token may see, or 404. */
    private function reportRow(int $id): array
    {
        $r = App::reports()->find($id);
        if ($r === null || ($this->clients !== null && !in_array((int) $r['client_id'], $this->clients, true))) {
            throw new ApiError(404, 'Not found.');
        }
        return $r;
    }

    /** Audit an API write, as the token's creator, with the token named. */
    private function audit(string $action, string $type, int $id, array $details): void
    {
        App::audit()->log($action, (int) $this->token['created_by'], (string) $this->token['creator_username'], $type, $id,
            $details + ['via' => 'api', 'token_id' => (int) $this->token['id'], 'token' => $this->token['name']], $this->request->ip());
    }

    /** "Y-m-d H:i:s" (UTC) to ISO 8601, or null. */
    public static function iso(mixed $v): ?string
    {
        return $v === null || $v === '' ? null : str_replace(' ', 'T', substr((string) $v, 0, 19)) . 'Z';
    }

    /** @param array<string,mixed> $c */
    public static function clientOut(array $c): array
    {
        return ['id' => (int) $c['id'], 'name' => $c['name'], 'itflow_client_id' => $c['itflow_client_id'] === null ? null : (int) $c['itflow_client_id'],
                'timezone' => $c['timezone'], 'archived' => (int) $c['is_archived'] === 1, 'scanning_paused' => (int) $c['scanning_paused'] === 1,
                'created_at' => self::iso($c['created_at']), 'updated_at' => self::iso($c['updated_at'])];
    }

    /** @param array<string,mixed> $f */
    /**
     * A finding as this token may see it (1.42): a breached address is masked (in the key and detail) unless the
     * token's creator may see breached addresses in full, as in the web interface.
     *
     * @param array<string,mixed> $f
     * @return array<string,mixed>
     */
    private function findingFor(array $f): array
    {
        $out = self::findingOut($f);
        if ($out['type'] === 'breach' && !$this->mayReadBreaches()) {
            // The key keeps a short hash so two addresses that mask alike stay apart (1.42.2); notes are masked too.
            $out['key'] = 'breach:' . \Sentinel\Breach\BreachMonitor::masked(substr((string) $out['key'], 7)) . '#' . substr(hash('sha256', (string) $out['key']), 0, 12);
            $out['detail'] = \Sentinel\Breach\BreachMonitor::maskAll((string) $out['detail']);
            $out['triage_note'] = $out['triage_note'] === null ? null : \Sentinel\Breach\BreachMonitor::maskAll((string) $out['triage_note']);
        }
        return $out;
    }

    /** True when the token's creator may see breached addresses in full. */
    private function mayReadBreaches(): bool
    {
        return in_array('breach.addresses', (array) ($this->token['creator_permissions'] ?? []), true);
    }

    /** A report's text as this token may read it (1.42.2): email addresses masked unless its creator may see them. */
    private function readable(string $text): string
    {
        return $this->mayReadBreaches() ? $text : \Sentinel\Breach\BreachMonitor::maskAll($text);
    }

    public static function findingOut(array $f): array
    {
        return ['id' => (int) $f['id'], 'client_id' => (int) $f['client_id'], 'asset_id' => $f['asset_id'] === null ? null : (int) $f['asset_id'], 'key' => $f['finding_key'],
                'type' => $f['finding_type'], 'severity' => $f['severity'], 'status' => $f['status'], 'title' => $f['title'], 'detail' => $f['detail'],
                'target' => $f['target'], 'evidence' => $f['evidence'], 'cve_id' => $f['cve_id'], 'triage_note' => $f['triage_note'], 'triaged_at' => self::iso($f['triaged_at']),
                'reappeared' => (int) $f['reappeared'] === 1, 'reopened_count' => (int) $f['reopened_count'], 'first_seen' => self::iso($f['first_seen']),
                'last_seen' => self::iso($f['last_seen']), 'resolved_at' => self::iso($f['resolved_at']), 'updated_at' => self::iso($f['updated_at']),
                // Fix workflow (read-only here): only open findings are due.
                'source' => $f['source'] ?? 'external',
                'assignee' => $f['assignee_username'] ?? null, 'assigned_at' => self::iso($f['assigned_at'] ?? null),
                'due_at' => ($f['status'] ?? '') === 'open' ? self::iso($f['due_at'] ?? null) : null];
    }

    /** @param array<string,mixed> $j */
    public static function scanOut(array $j): array
    {
        $summary = json_decode((string) ($j['summary'] ?? ''), true);
        return ['id' => (int) $j['id'], 'client_id' => (int) $j['client_id'], 'type' => $j['job_type'], 'trigger' => $j['trigger_type'], 'status' => $j['status'],
                'outside_window' => (int) $j['outside_window'] === 1, 'via_api' => $j['api_token_id'] !== null, 'created_at' => self::iso($j['created_at']),
                'started_at' => self::iso($j['started_at']), 'finished_at' => self::iso($j['finished_at']),
                'messages' => is_array($summary) ? array_values(array_map('strval', array_slice((array) ($summary['messages'] ?? []), 0, 20))) : []];
    }

    /** @param array<string,mixed> $r */
    public static function reportOut(array $r): array
    {
        return ['id' => (int) $r['id'], 'client_id' => (int) $r['client_id'], 'kind' => $r['kind'], 'source' => $r['source'], 'title' => $r['title'],
                'period_start' => $r['period_start'], 'period_end' => $r['period_end'], 'generated_at' => self::iso($r['generated_at']), 'sha256' => $r['html_sha256']];
    }
}
