<?php

declare(strict_types=1);

namespace Sentinel\Api;

/**
 * The OpenAPI 3.1 description of the API (served at /api/v1/openapi.json).
 *
 * Security assumptions: static text written here; contains no data.
 */
final class OpenApi
{
    /** @return array<string,mixed> */
    public static function spec(string $version): array
    {
        $id = ['name' => 'id', 'in' => 'path', 'required' => true, 'schema' => ['type' => 'integer', 'minimum' => 1]];
        $page = [
            ['name' => 'page', 'in' => 'query', 'schema' => ['type' => 'integer', 'minimum' => 1, 'default' => 1]],
            ['name' => 'per_page', 'in' => 'query', 'schema' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 500, 'default' => 100]],
        ];
        $client = ['name' => 'client_id', 'in' => 'query', 'schema' => ['type' => 'integer']];
        $since = ['name' => 'updated_since', 'in' => 'query', 'description' => 'ISO 8601 time with zone, e.g. 2026-11-01T00:00:00Z', 'schema' => ['type' => 'string', 'format' => 'date-time']];
        $ok = static fn (string $d): array => ['200' => ['description' => $d, 'content' => ['application/json' => ['schema' => ['type' => 'object']]]]];
        $errors = ['401' => ['description' => 'Missing, invalid, expired or revoked token'], '403' => ['description' => 'Permission or IP not allowed'],
                   '404' => ['description' => 'Not found (or not visible to this token)'], '429' => ['description' => 'Rate limit (120 requests per minute per token)']];
        $get = static fn (string $summary, array $params, string $resp) => ['get' => ['summary' => $summary, 'parameters' => $params, 'responses' => $ok($resp) + $errors]];
        return [
            'openapi' => '3.1.0',
            'info' => [
                'title' => 'MSP Sentinel API',
                'version' => $version,
                'description' => "Read clients, assets, findings, scans and reports; triage findings and queue scans (if the token has those permissions).\n"
                    . "Authenticate with \"Authorization: Bearer snt_...\". Lists are paginated: {data, meta: {page, per_page, total, next_page}}. Times are UTC (ISO 8601). updated_since on findings and assets matches real changes (status, grade, evidence, triage, open services), not every re-scan.\n"
                    . "Newest-first lists (scans, reports) use offset paging: items created while you page can shift pages, so dedupe by id.\n"
                    . "Outbound events (if configured) are POSTed as JSON with X-Sentinel-Event and X-Sentinel-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, t.body)>. Events are retried for about two days and may arrive late or out of order: dedupe by the event id.",
            ],
            'servers' => [['url' => '/api/v1']],
            'security' => [['bearer' => []]],
            'components' => ['securitySchemes' => ['bearer' => ['type' => 'http', 'scheme' => 'bearer']]],
            'paths' => [
                '/me' => $get('This token: name, permissions, clients, expiry', [], 'Token details'),
                '/clients' => $get('List clients', array_merge($page, [$since]), 'Clients'),
                '/clients/{id}' => $get('One client', [$id], 'Client'),
                '/clients/{id}/summary' => $get('Rating and risk score (as on the dashboard), open totals, last scan', [$id], 'Summary'),
                '/clients/{id}/scans' => ['post' => ['summary' => 'Queue a scan (needs the "scan" permission; runs in the client\'s scan window)', 'parameters' => [$id],
                    'responses' => ['202' => ['description' => 'Queued'], '409' => ['description' => 'Already queued, paused, archived or nothing to scan']] + $errors]],
                '/assets' => $get('List assets with open services', array_merge($page, [$client, $since]), 'Assets'),
                '/findings' => $get('List findings', array_merge($page, [$client, $since,
                    ['name' => 'status', 'in' => 'query', 'schema' => ['enum' => ['open', 'resolved', 'accepted', 'false_positive']]],
                    ['name' => 'severity', 'in' => 'query', 'schema' => ['enum' => ['fail', 'warn']]],
                    ['name' => 'type', 'in' => 'query', 'schema' => ['enum' => ['port', 'tls', 'web', 'vuln', 'email', 'patch', 'device', 'directory', 'dns', 'breach', 'pentest']]]]), 'Findings'),
                '/findings/{id}' => $get('One finding with its history', [$id], 'Finding'),
                '/findings/{id}/triage' => ['post' => ['summary' => 'Triage a finding (needs the "triage" permission)', 'parameters' => [$id],
                    'requestBody' => ['required' => true, 'content' => ['application/json' => ['schema' => ['type' => 'object', 'required' => ['status', 'note'],
                        'properties' => ['status' => ['enum' => ['accepted', 'false_positive', 'open']], 'note' => ['type' => 'string', 'maxLength' => 1900]]]]]],
                    'responses' => $ok('The finding after the change') + ['409' => ['description' => 'Resolved finding or archived client'], '422' => ['description' => 'Invalid status or missing note']] + $errors]],
                '/scans' => $get('List scans, newest first', array_merge($page, [$client]), 'Scans'),
                '/scans/{id}' => $get('One scan', [$id], 'Scan'),
                '/reports' => $get('List reports, newest first', array_merge($page, [$client]), 'Reports'),
                '/reports/{id}' => $get('Report details and totals', [$id], 'Report'),
                '/reports/{id}/html' => ['get' => ['summary' => 'The frozen report document (HTML); header X-Report-SHA256', 'parameters' => [$id], 'responses' => ['200' => ['description' => 'HTML', 'content' => ['text/html' => new \stdClass()]]] + $errors]],
                '/reports/{id}/csv' => ['get' => ['summary' => 'The report\'s findings as CSV', 'parameters' => [$id], 'responses' => ['200' => ['description' => 'CSV', 'content' => ['text/csv' => new \stdClass()]]] + $errors]],
                '/openapi.json' => $get('This description', [], 'OpenAPI document'),
            ],
        ];
    }
}
