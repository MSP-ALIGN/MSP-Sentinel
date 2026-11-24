<?php

declare(strict_types=1);

namespace Sentinel\Itflow;

/**
 * Talks to ITFlow's API (v1): reads clients (phase 1), opens tickets and adds internal notes (phase 2); see
 * docs/ROADMAP-itflow.md.
 *
 * API facts used (ITFlow's own source: api/v1/validate_api_key.php, clients/read.php, read_output.php,
 * functions/api_keys.php):
 * - The key goes in the X-API-Key header (ITFlow keeps it out of web server logs that way). Keys are tied to an ITFlow
 *   user and follow that user's role and client access.
 * - GET /api/v1/clients/read.php?limit=&offset=  ->  {"success":"True","count":n,"data":[{client_id, client_name,
 *   client_archived_at, client_updated_at, ...}]}. Archived clients are included. No match answers
 *   {"success":"False","message":"No resource ..."} with HTTP 200, which is an empty page, not an error.
 * - A wrong or expired key answers HTTP 401.
 * - POST /api/v1/tickets/create.php (JSON body: client_id, ticket_subject, ticket_details HTML, ticket_priority one of
 *   Low|Medium|High|Urgent, ticket_vendor_ticket_number) -> {"success":"True","data":[{"insert_id":N}],
 *   "ticket_reference":"...","ticket_url":"..."}; a refused request answers 400 {"success":"False","message":"..."}.
 *   Without ticket_notify nobody is emailed. ticket_url is the client's guest link (it carries the ticket's secret
 *   url_key): Sentinel never stores or shows it, and links to the agent view (agent/ticket.php) instead.
 * - GET /api/v1/tickets/read.php?client_id=N&limit=&offset= lists a client's tickets oldest first (ORDER BY ticket_id,
 *   SELECT * so with ticket_vendor_ticket_number and ticket_created_at; no limit cap, no total; an empty page is
 *   "No resource"), used to find a ticket whose create call timed out.
 * - POST /api/v1/ticket_replies/create.php (client_id, ticket_id, ticket_reply HTML, ticket_reply_type "Internal")
 *   -> {"success":"True","data":[{"insert_id":N}]}; an Internal reply is not emailed to the client. A closed ticket
 *   takes no replies.
 * - GET /api/v1/tickets/read.php?ticket_id=N -> one row with ticket_status (1 New, 2 Open, 3 On Hold, 4 Resolved,
 *   5 Closed, or a custom open status), ticket_resolved_at, ticket_closed_at; "No resource" when it is gone.
 * - POST /api/v1/tickets/resolve.php and reopen.php (client_id, ticket_id) -> {"success":"True","count":1}.
 *   A closed ticket can't be reopened ("start a new one instead").
 *
 * Security assumptions:
 * - The address is ITFlow's, entered by an admin (it may be an internal host: both are self-hosted). Only https,
 *   verified certificates and no redirects, so the key is only ever sent to that address; plain http only in the
 *   test suite.
 * - Every answer is untrusted: sizes and pages are capped, values are cast; Sentinel cleans names before storing.
 * - The key is never logged or put in an exception message.
 */
final class ItflowClient
{
    private const PAGE = 200;
    private const MAX_PAGES = 500;
    private const MAX_BYTES = 16777216;
    private const MARKER_PAGES = 25;

    /** @param bool $allowHttp Test suite only. */
    public function __construct(private readonly string $baseUrl, private readonly string $apiKey, private readonly bool $allowHttp = false)
    {
    }

    /** Whether an address is acceptable: https://host[:port][/path], no credentials, query or fragment. */
    public static function validUrl(string $url, bool $allowHttp = false): bool
    {
        $p = parse_url($url);
        return is_array($p) && in_array($p['scheme'] ?? '', $allowHttp ? ['https', 'http'] : ['https'], true) && ($p['host'] ?? '') !== ''
            && !isset($p['user']) && !isset($p['pass']) && !isset($p['query']) && !isset($p['fragment'])
            && preg_match('/^[A-Za-z0-9.-]{1,253}$|^\[[0-9A-Fa-f:.]+\]$/', (string) $p['host']) === 1;
    }

    /** Whether a string can be an ITFlow API key (printable, no spaces; ITFlow's own format may change). */
    public static function validKey(string $key): bool
    {
        return preg_match('/^[A-Za-z0-9._~+\/=-]{16,200}$/', $key) === 1;
    }

    /**
     * Every client the key can see, archived ones included.
     *
     * @return list<array{id:int, name:string, archived:bool}>
     */
    public function clients(): array
    {
        $out = [];
        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            $rows = $this->read('/api/v1/clients/read.php', ['limit' => self::PAGE, 'offset' => $page * self::PAGE]);
            $before = count($out);
            foreach ($rows as $r) {
                if (is_array($r) && is_numeric($r['client_id'] ?? null) && (int) $r['client_id'] > 0) {
                    $out[(int) $r['client_id']] = ['id' => (int) $r['client_id'], 'name' => is_scalar($r['client_name'] ?? null) ? trim((string) $r['client_name']) : '',
                        'archived' => is_string($r['client_archived_at'] ?? null) && $r['client_archived_at'] !== '' && !str_starts_with($r['client_archived_at'], '0000')];
                }
            }
            if (count($rows) < self::PAGE) {
                return array_values($out);
            }
            if (count($out) === $before) {
                throw new ItflowException('ITFlow returned the same clients again for the next page; the sync was stopped.');
            }
        }
        throw new ItflowException('ITFlow returned more clients than Sentinel reads in one sync.');
    }

    /**
     * Open a ticket for a client. ITFlow stores the details as HTML: the caller must have escaped every value in it.
     * $marker goes into the ticket's vendor ticket number, so a ticket whose create call timed out can be found again
     * (findByMarker) instead of opened twice.
     *
     * @return array{id:int, reference:string}
     */
    public function createTicket(int $clientId, string $subject, string $detailsHtml, string $priority, string $marker = ''): array
    {
        if (!in_array($priority, ['Low', 'Medium', 'High', 'Urgent'], true)) {
            throw new \InvalidArgumentException('Unknown ITFlow priority.');
        }
        $fields = ['client_id' => $clientId, 'ticket_subject' => mb_substr($subject, 0, 200), 'ticket_details' => $detailsHtml, 'ticket_priority' => $priority];
        if ($marker !== '') {
            $fields['ticket_vendor_ticket_number'] = $marker;
        }
        $data = $this->post('/api/v1/tickets/create.php', $fields);
        $id = $data['data'][0]['insert_id'] ?? null;
        if (!is_numeric($id) || (int) $id <= 0) {
            throw new ItflowException('ITFlow did not return the new ticket\'s number.');
        }
        $ref = is_string($data['ticket_reference'] ?? null) ? mb_substr($data['ticket_reference'], 0, 40) : '';
        return ['id' => (int) $id, 'reference' => (string) preg_replace('/[^A-Za-z0-9#._-]/', '', $ref)];
    }

    /**
     * IDs of the ITFlow clients that carry a tag (1.45), through ITFlow's tags API: GET /api/v1/tags/read.php with
     * kind=client and tag_name (any case) finds the tag(s), then tag_id=... lists tag_record_ids (the clients the key
     * may see). Null when no client tag has that name (a typo must not look like "nobody is tagged"). Throws when this
     * ITFlow has no tags API or refuses it, so the caller never mistakes "can't tell" for "no clients tagged".
     *
     * Untrusted: everything ITFlow answers (only numeric IDs are kept).
     *
     * @return list<int>|null
     */
    public function taggedClientIds(string $tagName): ?array
    {
        $tags = $this->tagsRead(['kind' => 'client', 'tag_name' => $tagName, 'limit' => 1000]);
        $ids = [];
        $found = false;
        foreach ($tags as $t) {
            if (!is_array($t) || !is_numeric($t['tag_id'] ?? null) || strcasecmp(trim((string) ($t['tag_name'] ?? '')), trim($tagName)) !== 0) {
                continue;
            }
            $found = true;
            foreach ($this->tagsRead(['tag_id' => (int) $t['tag_id']]) as $one) {
                $records = is_array($one) ? ($one['tag_record_ids'] ?? []) : [];
                if (is_string($records)) {
                    $records = explode(',', $records); // tolerated: a comma-separated list
                }
                foreach (is_array($records) ? $records : [] as $rid) {
                    if (is_numeric($rid) && (int) $rid > 0) {
                        $ids[(int) $rid] = true;
                    }
                }
            }
        }
        return $found ? array_keys($ids) : null;
    }

    /**
     * One call to ITFlow's tags API. A 404 means this ITFlow has none: an error, never "no tags".
     *
     * @param array<string,int|string> $query
     * @return list<mixed>
     */
    private function tagsRead(array $query): array
    {
        [$status, $body] = $this->request('/api/v1/tags/read.php', $query, null);
        $data = json_decode($body, true);
        if ($status === 404 && !is_array($data)) {
            throw new ItflowException('This ITFlow has no tags API (tags/read.php), so clients can\'t be filtered by tag.', ItflowException::KIND_REFUSED);
        }
        if ($status === 401) {
            throw new ItflowException('ITFlow refused the API key (wrong or expired).', ItflowException::KIND_AUTH);
        }
        if ($status === 403) {
            throw self::denied(is_array($data) && is_string($data['message'] ?? null) ? mb_substr((string) preg_replace('/[^\P{C}]/u', '', $data['message']), 0, 200) : '');
        }
        if (!is_array($data)) {
            throw new ItflowException('ITFlow answered HTTP ' . $status . ' for its tags.', ItflowException::KIND_REFUSED);
        }
        if (($data['success'] ?? '') === 'True') {
            return is_array($data['data'] ?? null) && array_is_list($data['data']) ? $data['data'] : [];
        }
        $msg = is_string($data['message'] ?? null) ? $data['message'] : '';
        if (str_starts_with($msg, 'No resource')) {
            return []; // nothing with that name
        }
        throw new ItflowException('ITFlow refused the tag lookup: ' . mb_substr((string) preg_replace('/[^\P{C}]/u', '', $msg), 0, 200), ItflowException::KIND_REFUSED);
    }

    /**
     * The service boards of an ITFlow build with board support (1.44: the MountaineerIT build's
     * GET /api/v1/mit_boards/read.php), or null when this ITFlow has none (stock ITFlow answers 404 there).
     *
     * @return list<array{id:int, name:string, is_default:bool}>|null
     */
    public function boards(): ?array
    {
        [$status, $body] = $this->request('/api/v1/mit_boards/read.php', ['limit' => 1000], null);
        if ($status === 404 || $status === 503) {
            return null; // no board support here (stock ITFlow), or switched off
        }
        if ($status === 401) {
            throw new ItflowException('ITFlow refused the API key (wrong or expired).', ItflowException::KIND_AUTH);
        }
        $data = json_decode($body, true);
        if ($status === 403) {
            throw self::denied(is_array($data) && is_string($data['message'] ?? null) ? mb_substr((string) preg_replace('/[^\P{C}]/u', '', $data['message']), 0, 200) : '');
        }
        if ($status !== 200 || !is_array($data) || ($data['success'] ?? '') !== 'True') {
            throw new ItflowException('ITFlow did not list its boards (HTTP ' . $status . ').', ItflowException::KIND_REFUSED);
        }
        $out = [];
        foreach ((array) ($data['data'] ?? []) as $b) {
            if (is_array($b) && is_numeric($b['board_id'] ?? null) && (int) $b['board_id'] > 0) {
                $out[] = ['id' => (int) $b['board_id'], 'name' => trim(mb_substr((string) preg_replace('/[^\P{C}]/u', '', (string) ($b['board_name'] ?? '')), 0, 100)),
                          'is_default' => in_array($b['board_is_default'] ?? 0, [1, '1', true], true)];
            }
        }
        usort($out, static fn (array $a, array $b): int => $a['id'] <=> $b['id']); // lowest ID first: "Alerts" picks the first
        return $out;
    }

    /** The board named "Alerts" (ignoring case and spaces; the lowest ID if several), or null. @param list<array{id:int,name:string,is_default:bool}> $boards */
    public static function alertsBoard(array $boards): ?array
    {
        foreach ($boards as $b) {
            if (strcasecmp(trim($b['name']), 'Alerts') === 0) {
                return $b;
            }
        }
        return null;
    }

    /**
     * Read the boards and keep them in the settings for the Integrations page (1.44.1). Returns them (null: none).
     * Errors are kept out of the cache: the last good list stays.
     *
     * @return list<array{id:int, name:string, is_default:bool}>|null
     */
    public function refreshBoards(\Sentinel\Core\Settings $settings): ?array
    {
        $boards = $this->boards();
        $settings->set('itflow_boards_cache', (string) json_encode($boards));
        return $boards;
    }

    /**
     * Move a ticket to a service board (1.44: POST /api/v1/mit_boards/move.php), left unassigned so the board's own
     * rules (auto-assign, member notifications) pick it up.
     */
    public function moveTicket(int $clientId, int $ticketId, int $boardId, bool $unassign = true): void
    {
        $fields = ['client_id' => $clientId, 'ticket_id' => $ticketId, 'board_id' => $boardId];
        if ($unassign) {
            $fields['unassign'] = 1;
        }
        $this->post('/api/v1/mit_boards/move.php', $fields);
    }

    /**
     * The ticket of a client whose vendor ticket number is $marker, or null when there is none.
     *
     * ITFlow lists a client's tickets oldest first (ORDER BY ticket_id) with limit/offset and no total, and the ticket
     * looked for is among the newest. So: count the client's tickets with one-ticket probes (doubling the offset,
     * then halving the gap: about 2·log2(n) small reads), then read pages backwards from the newest. $notBefore (UTC)
     * is when Sentinel was about to open it: once a page reaches tickets created more than an hour before that, the
     * ticket isn't there (the hour allows for the two servers' clocks). More than MARKER_PAGES pages without an
     * answer throws (unknown, not "none").
     *
     * @return array{id:int, reference:string}|null
     */
    public function findByMarker(int $clientId, string $marker, string $notBefore = ''): ?array
    {
        $count = $this->countTickets($clientId);
        $cutoff = $notBefore !== '' ? (int) strtotime($notBefore . ' UTC') - 3600 : null;
        for ($page = 0, $end = $count; $page < self::MARKER_PAGES && $end > 0; $page++, $end -= self::PAGE) {
            $start = max(0, $end - self::PAGE);
            $rows = $this->read('/api/v1/tickets/read.php', ['client_id' => $clientId, 'limit' => $end - $start, 'offset' => $start]);
            $older = false;
            foreach ($rows as $r) {
                if (!is_array($r)) {
                    continue;
                }
                if (($r['ticket_vendor_ticket_number'] ?? null) === $marker && is_numeric($r['ticket_id'] ?? null) && (int) ($r['ticket_client_id'] ?? 0) === $clientId) {
                    $ref = is_scalar($r['ticket_prefix'] ?? null) && is_scalar($r['ticket_number'] ?? null) ? $r['ticket_prefix'] . $r['ticket_number'] : '';
                    return ['id' => (int) $r['ticket_id'], 'reference' => (string) preg_replace('/[^A-Za-z0-9#._-]/', '', mb_substr($ref, 0, 40))];
                }
                $created = is_string($r['ticket_created_at'] ?? null) ? strtotime($r['ticket_created_at'] . ' UTC') : false;
                $older = $older || ($cutoff !== null && $created !== false && $created < $cutoff);
            }
            if ($older) {
                return null; // reached tickets from before it would have been opened
            }
        }
        if ($count <= self::MARKER_PAGES * self::PAGE) {
            return null; // every ticket read
        }
        throw new ItflowException('The client has too many recent ITFlow tickets to look through.', ItflowException::KIND_REFUSED);
    }

    /** How many tickets a client has in ITFlow (the API gives no total): one-ticket probes, doubling then bisecting. */
    private function countTickets(int $clientId): int
    {
        $exists = fn (int $offset): bool => $this->read('/api/v1/tickets/read.php', ['client_id' => $clientId, 'limit' => 1, 'offset' => $offset]) !== [];
        if (!$exists(0)) {
            return 0;
        }
        $lo = 0; // an offset that exists
        $hi = 1;
        while ($exists($hi)) {
            $lo = $hi;
            $hi *= 2;
            if ($hi > 1 << 24) {
                throw new ItflowException('ITFlow returned more tickets than Sentinel can count.', ItflowException::KIND_REFUSED);
            }
        }
        while ($hi - $lo > 1) { // $lo exists, $hi doesn't
            $mid = intdiv($lo + $hi, 2);
            if ($exists($mid)) {
                $lo = $mid;
            } else {
                $hi = $mid;
            }
        }
        return $lo + 1;
    }

    /** The agent's view of a ticket in ITFlow (no secret in it), or '' when the address isn't valid. */
    public static function ticketUrl(string $baseUrl, int $clientId, int $ticketId, bool $allowHttp = false): string
    {
        return self::validUrl($baseUrl, $allowHttp) ? rtrim($baseUrl, '/') . '/agent/ticket.php?' . http_build_query(['client_id' => $clientId, 'ticket_id' => $ticketId]) : '';
    }

    /** Add an internal note (not emailed to the client) to a ticket. The caller must have escaped the HTML. */
    public function addNote(int $clientId, int $ticketId, string $html): void
    {
        $this->post('/api/v1/ticket_replies/create.php', ['client_id' => $clientId, 'ticket_id' => $ticketId, 'ticket_reply' => $html, 'ticket_reply_type' => 'Internal']);
    }

    /** A ticket's state in ITFlow: open (any working status), resolved, closed, or gone (deleted or out of reach). */
    public function ticketStatus(int $ticketId): string
    {
        $rows = $this->read('/api/v1/tickets/read.php', ['ticket_id' => $ticketId]);
        $t = $rows[0] ?? null;
        if (!is_array($t)) {
            return 'gone';
        }
        $status = (int) ($t['ticket_status'] ?? 0);
        $closed = is_string($t['ticket_closed_at'] ?? null) && $t['ticket_closed_at'] !== '' && !str_starts_with($t['ticket_closed_at'], '0000');
        $resolved = is_string($t['ticket_resolved_at'] ?? null) && $t['ticket_resolved_at'] !== '' && !str_starts_with($t['ticket_resolved_at'], '0000');
        return $closed || $status === 5 ? 'closed' : ($resolved || $status === 4 ? 'resolved' : 'open');
    }

    /** Resolve a ticket. */
    public function resolveTicket(int $clientId, int $ticketId): void
    {
        $this->post('/api/v1/tickets/resolve.php', ['client_id' => $clientId, 'ticket_id' => $ticketId]);
    }

    /** Reopen a resolved ticket (ITFlow refuses closed ones). */
    public function reopenTicket(int $clientId, int $ticketId): void
    {
        $this->post('/api/v1/tickets/reopen.php', ['client_id' => $clientId, 'ticket_id' => $ticketId]);
    }

    /**
     * ITFlow's 403 (apiDeny). Only "no access to the target client" is about one item; everything else (the key's user
     * inactive or archived, a key without a user, a role without the Support module) is about the key, so every
     * later call fails too and the run stops.
     */
    private static function denied(string $msg): ItflowException
    {
        $perClient = str_contains($msg, 'does not have access to the target client');
        return new ItflowException(($perClient ? 'The ITFlow API key\'s user has no access to this client: '
            : 'ITFlow refused the API key\'s user (check that user is active and its role has the Support module at write level): ') . $msg,
            $perClient ? ItflowException::KIND_REFUSED : ItflowException::KIND_AUTH);
    }

    /**
     * A write endpoint (JSON body). Returns the decoded answer of a successful call.
     *
     * @param array<string,int|string> $fields
     * @return array<string,mixed>
     */
    private function post(string $path, array $fields): array
    {
        [$status, $body] = $this->request($path, null, (string) json_encode($fields, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE));
        $data = json_decode($body, true);
        if ($status === 200 && is_array($data) && ($data['success'] ?? '') === 'True') {
            return $data;
        }
        $msg = is_array($data) && is_string($data['message'] ?? null) ? mb_substr((string) preg_replace('/[^\P{C}]/u', '', $data['message']), 0, 200) : 'HTTP ' . $status;
        if ($status === 401) {
            throw new ItflowException('ITFlow refused the API key (wrong or expired).', ItflowException::KIND_AUTH);
        }
        if ($status === 403) {
            throw self::denied($msg);
        }
        if (($status === 200 && is_array($data)) || in_array($status, [400, 404, 409, 422], true)) {
            throw new ItflowException('ITFlow refused: ' . $msg, ItflowException::KIND_REFUSED);
        }
        throw new ItflowException('ITFlow answered HTTP ' . $status . ' for ' . $path . '.'); // unknown whether it was done
    }

    /**
     * A read endpoint's rows ([] for ITFlow's "No resource" answer).
     *
     * @param array<string,int|string> $query
     * @return list<mixed>
     */
    private function read(string $path, array $query): array
    {
        [$status, $body] = $this->request($path, $query, null);
        if ($status === 401) {
            throw new ItflowException('ITFlow refused the API key (wrong or expired).', ItflowException::KIND_AUTH);
        }
        if ($status === 403) {
            $data = json_decode($body, true);
            throw self::denied(is_array($data) && is_string($data['message'] ?? null) ? mb_substr((string) preg_replace('/[^\P{C}]/u', '', $data['message']), 0, 200) : '');
        }
        $data = json_decode($body, true);
        if ($status !== 200 || !is_array($data)) {
            throw new ItflowException('ITFlow answered HTTP ' . $status . ' for ' . $path . ' (is this the ITFlow address?).');
        }
        if (($data['success'] ?? '') === 'True') {
            return is_array($data['data'] ?? null) && array_is_list($data['data']) ? $data['data'] : [];
        }
        $msg = is_string($data['message'] ?? null) ? $data['message'] : '';
        if (str_starts_with($msg, 'No resource')) {
            return []; // ITFlow's way of saying "nothing (more) here"
        }
        throw new ItflowException('ITFlow refused the request: ' . mb_substr((string) preg_replace('/[^\P{C}]/u', '', $msg), 0, 200), ItflowException::KIND_REFUSED);
    }

    /**
     * One HTTPS call: GET with a query, or POST with a JSON body.
     *
     * @param array<string,int|string>|null $query
     * @return array{0:int,1:string} status and body
     */
    private function request(string $path, ?array $query, ?string $json): array
    {
        if (!self::validUrl($this->baseUrl, $this->allowHttp)) {
            throw new ItflowException('The ITFlow address must be an https:// address (Administration, Integrations).');
        }
        $body = '';
        $ch = curl_init(rtrim($this->baseUrl, '/') . $path . ($query === null || $query === [] ? '' : '?' . http_build_query($query)));
        $headers = ['Accept: application/json', 'X-API-Key: ' . $this->apiKey];
        $opts = [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_PROTOCOLS => $this->allowHttp ? (CURLPROTO_HTTP | CURLPROTO_HTTPS) : CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'MSP-Sentinel',
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$body): int {
                $body .= $chunk;
                return strlen($body) > self::MAX_BYTES ? 0 : strlen($chunk);
            },
        ];
        if ($json !== null) {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $json;
            $headers[] = 'Content-Type: application/json';
        }
        $opts[CURLOPT_HTTPHEADER] = $headers;
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($ok === false) {
            throw new ItflowException('Could not reach ITFlow: ' . mb_substr($err, 0, 200));
        }
        return [$status, $body];
    }
}
