# API guide

Sentinel has a JSON API at `/api/v1` for MSP Align and other tools. The full machine-readable description is at
`/api/v1/openapi.json` (OpenAPI 3.1).

## Tokens

Admins create tokens under **Administration → API**. A token:
- is shown once;
- covers all clients or chosen ones;
- expires after 30 to 365 days;
- can be limited to IP addresses or networks;
- can always read, and can **triage** and **queue scans** only if those boxes are ticked.

It acts as the admin who created it and stops working when revoked, expired, or when that admin is deactivated or
is no longer an admin.

```sh
curl -H "Authorization: Bearer snt_xxxxxxxxxxxx_..." https://sentinel.msp.example/api/v1/me
```

## Endpoints

| Method and path | Needs | What |
|---|---|---|
| `GET /me` | read | This token: name, permissions, clients, expiry |
| `GET /clients`, `GET /clients/{id}` | read | Clients |
| `GET /clients/{id}/summary` | read | Rating (`at_risk`, `needs_attention`, `good`) and `score` (0 to 100), the same as the dashboard since 1.58.2; open Fail/Warning, accepted, by type, last scan |
| `GET /assets` | read | Assets with their open services |
| `GET /findings`, `GET /findings/{id}` | read | Findings (filters: `client_id`, `status`, `severity`, `type`, `updated_since`); one finding includes its history. Each finding has `assignee` (username or null), `assigned_at` and `due_at` (open findings only) |
| `POST /findings/{id}/triage` | triage | `{"status": "accepted"\|"false_positive"\|"open", "note": "..."}` |
| `GET /scans`, `GET /scans/{id}` | read | Scans, newest first |
| `POST /clients/{id}/scans` | scan | Queue a scan; it runs in the client's scan window, only in scope (202, or 409 if already queued or paused) |
| `GET /reports`, `GET /reports/{id}` | read | Reports and their totals |
| `GET /reports/{id}/html`, `GET /reports/{id}/csv` | read | The frozen document (header `X-Report-SHA256`) and its findings as CSV |

## Conventions

- Lists: `?page=1&per_page=100` (up to 500); the answer is `{"data": [...], "meta": {"page", "per_page", "total", "next_page"}}`.
- Times are UTC, ISO 8601: `2026-11-22T10:00:00Z`. `updated_since` accepts any ISO 8601 time with a zone.
- `updated_since` on findings and assets matches real changes (status, grade, evidence, triage, resolution, open
  services), not every re-scan, so incremental syncs stay small.
- Records of clients the token can't see answer **404**, exactly like missing ones.
- Errors: `{"error": {"status": 403, "message": "..."}}`. 401 for a missing, wrong, expired, revoked or
  IP-refused token; 403 for a missing permission; 429 above 120 requests a minute (per token) or after repeated
  failures from one address.
- Triage notes made through the API start with `[API: <token name>]`; every API change is in the audit log.

## Outbound events

Under **Administration → API → Outbound events**, Sentinel can POST to an https address when:
- findings open, reopen, escalate to Fail, resolve or are triaged (`finding.*`);
- a scan finishes (`scan.finished`);
- a report is created (`report.created`);
- you press the test button (`ping`).

```json
{"id": "evt_…", "type": "finding.opened", "created_at": "2026-11-22T10:00:00Z",
 "data": {"finding_id": 12, "client_id": 3, "type": "port", "severity": "fail", "status": "open", "title": "…", "target": "…", "cve_id": null}}
```

Headers: `X-Sentinel-Event`, `X-Sentinel-Delivery` and `X-Sentinel-Signature: t=<unix time>,v1=<hex>`, where the
hex is HMAC-SHA256 of `"<t>.<raw body>"` with the signing secret (shown once). To check it:

```php
[$t, $v1] = sscanf($_SERVER['HTTP_X_SENTINEL_SIGNATURE'], 't=%d,v1=%64s');
$ok = abs(time() - $t) < 300 && hash_equals(hash_hmac('sha256', $t . '.' . file_get_contents('php://input'), $secret), $v1);
```

Undelivered events are retried for about two days, so they can arrive late or out of order: skip duplicate `id`s
and use the API to fetch the current state.
