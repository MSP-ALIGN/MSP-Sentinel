# MSP Sentinel: design (v1.0)

Status: **draft, agreed in principle**. Changes to this document are made before code.

MSP Sentinel is a self-hosted security product for MSPs. It **detects** external exposure and vulnerabilities,
monitors them and alerts on them. It sits alongside MSP Align, which **plans, reports and proves**. Align reads
Sentinel's findings through a read-only API.

**Feature rule:** if it helps the MSP plan, report or prove, it belongs in Align. If it detects or responds, it belongs in Sentinel.

## 1. Decisions

| Area | Decision |
|---|---|
| Stack | Plain PHP 8.4, MariaDB, Bootstrap 5.3 + AdminLTE 4. No framework, no Composer. |
| Scanning | PHP command-line workers call **nmap**, which the MSP installs (not bundled), and PHP's own TLS/HTTP functions. Nuclei comes later. |
| Targets | Typed in, plus suggestions from DNS (A/MX records) and Certificate Transparency (crt.sh). **A suggestion is never scanned until an admin approves it into the client's scope.** |
| Schedule | Scans run from Sentinel's own server: a port check weekly and certificate checks daily, inside each client's scan window. A remote scanner node can be added later. |
| Ports | About 40 risky ports by default, editable per client (see section 6). |
| Roles | Admin, Technician, Viewer. Local accounts with TOTP 2FA. |
| Alerts | In-app notifications, email (a digest per scan plus an immediate email for each new FAIL) and a webhook. ITFlow tickets come in v1.x. |
| ITFlow | Optional ITFlow client and asset ID fields only. No ITFlow API calls in v1. |
| Align | Read-only REST API at `/api/v1`, using hashed bearer tokens that can be revoked. Align polls it. |
| License | AGPL-3.0 |

## 2. Components

1. **Web UI** (`public/index.php` front controller): clients, scope register, targets, findings, scans,
   settings, users, API tokens.
   - Every route checks login and role first.
   - Every POST is CSRF-checked.
   - Every value in a view is escaped.
2. **Scheduler** (`bin/scheduler.php`, run by cron every minute): turns each due schedule into a queued job. It only
   does this for targets in an active, approved scope, and only inside the client's scan window.
3. **Worker** (`bin/worker.php`): takes one job at a time and **rechecks the scope just before scanning**.
   - Ports: runs nmap with `-sV`, a slow timing template and a rate cap. Arguments come from a whitelist and are
     passed as an argument array. A shell string is never used.
   - Certificates and TLS: checks expiry, chain, weak protocols and hostname match.
   - Admin pages: an HTTP GET of `/` on the web ports. It matches the title and headers against a small list of
     signatures, using generic product names only.
4. **Threat feeds** (`bin/feeds.php`, daily):
   - downloads the CISA KEV catalog and EPSS scores;
   - makes rate-limited NVD CVE lookups by CPE (Common Platform Enumeration, a standard product ID), with an
     optional NVD API key.

   All of this is cached locally.
5. **Matcher:** maps each detected product and version to a CPE, then to CVEs. The result is **confirmed** when the
   version is known, or **product found, version unknown** when it isn't. It never guesses a version.
6. **Diff and alerts:** compares each scan with the previous one. It raises "new port", "port closed", "new KEV CVE"
   and "certificate expires in 14 days or less".
7. **API** (`/api/v1/clients`, `/assets`, `/findings`, `/clients/{id}/summary`): read-only, paginated, with an
   `updated_since` filter.

## 3. Data model (sketch)

- `users`, `sessions`, `api_tokens` (hash, scope, last used, revoked)
- `clients` (name, itflow_client_id, scan window, timezone, port profile)
- `scan_authorisations`: the "authorised to scan" record (client, approved_by, approved_at, valid_from/to, document
  reference, notes)
- `scope_entries` (authorisation, type ip/cidr/domain, value). **Nothing is ever scanned unless it matches an entry here.**
- `target_suggestions` (client, value, source dns/crtsh, status pending/approved/rejected)
- `assets` (client, ip/hostname, itflow_asset_id, first/last seen)
- `services` (asset, port, protocol, product, version, cpe, banner hash, first/last seen)
- `certificates` (asset, hostname, subject, issuer, not_after, protocols, weaknesses)
- `scans` and `scan_jobs` (type, status, start/end, who started it, error)
- `scan_log`: an append-only log of every active scan
- `findings`:
  - links: client, asset
  - classification: type, severity FAIL/WARN/INFO, confidence confirmed/possible
  - CVE data: cve_id, KEV flag, EPSS score
  - status: open/resolved/accepted/false_positive, plus the triage note and who made it
  - dates: first/last seen, last checked
- `cve_cache`, `kev_catalog`, `epss_scores`
- `notifications`, `settings`, `audit_log`

## 4. Severity

- **FAIL:**
  - a confirmed KEV CVE or a confirmed critical CVE;
  - any of these open to the internet: RDP 3389, SMB 445, Telnet 23, VNC 5900, databases (1433, 1521, 3306, 5432,
    6379, 9200, 27017);
  - a reachable firewall or VPN admin page;
  - an expired certificate.
- **WARN:**
  - a confirmed high CVE;
  - "product found, version unknown" on a product that has KEV entries;
  - FTP open;
  - a certificate expiring within 14 days;
  - weak TLS.
- **INFO:** everything else.
- Accepted and false-positive findings stay visible, with their notes, but they don't count toward FAIL or WARN totals.

## 5. How Align and ITFlow fit

- **Align:**
  - The connector reads `/summary` and `/findings` per client. Clients are matched on `itflow_client_id`.
  - FAIL and WARN counts feed Align's health score and compliance controls ("external exposure reviewed", "no known
    exploited vulnerabilities").
  - Findings carry their `last checked` date, so they serve as evidence.
  - Some findings become roadmap seeds, for example "Replace firewall: 2 KEV CVEs".
- **ITFlow:** in v1 the IDs are stored so the data lines up later. Tickets and automatic asset matching come in v1.x.

## 6. Default port profile

TCP: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 1723, 2049,
3306, 3389, 4443, 5060, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9200, 10443, 27017, plus common firewall
and VPN admin ports. UDP: 161, 500.

## 7. Out of scope for v1

- internal collector or agent
- nuclei
- ITFlow tickets and sync
- monthly top-1000 port sweep
- remote scanner node
- default-credential checks
- anything that looks like pen testing

Until real pen testing exists, call this product "vulnerability scanning". Sentinel is **not** a PCI ASV scan.

## 8. Tests

- An end-to-end suite runs with a fake `nmap` binary that replays recorded XML, and with mock HTTP servers for NVD,
  KEV, EPSS, crt.sh, DNS, SMTP and the webhook.
- TLS checks run against a local TLS server with made-up certificates.
- Fixtures use only `*.example` names and documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- No real host is ever scanned in tests.

## 9. Risks and how we handle them

1. **Scanning something outside the scope**, which has legal risk. Scope is checked twice, when the job is scheduled
   and right before the scan, and every active scan is logged.
2. **Setting off clients' intrusion alerts.** Scans are slow, use a short port list, and run only in each client's window.
3. **Wrong CVE matches.** Banners can be faked or unclear. The confirmed/possible split, triage notes and "never
   guess" keep findings honest.
4. **NVD rate limits and outages.** Data is cached and the API key is optional. If NVD is down, the last known data
   is shown with its date.
5. **nmap's license** (NPSL, not plain GPL). Sentinel calls nmap as a separate program and never bundles it. The
   license gets checked again before any packaging.
6. **API token leaks.** Tokens are stored hashed, read-only and revocable, and their last use is logged.
7. **Command injection through targets.** Values are strictly validated as IP, CIDR or domain, and passed as an
   argument array, never through a shell. The worker refuses private address ranges unless the scope explicitly
   allows them.

## 10. Build order

1. Repository skeleton: VERSION, LICENSE, README, idempotent migrations, the front controller, auth (2FA, roles),
   CSRF, the test harness
2. Clients and the scope register
3. Targets and discovery
4. Port scan worker
5. Certificates and TLS
6. Threat feeds and CVE matching
7. Findings and triage
8. Alerts
9. API

Each feature gets tests, then an independent security review, then fixes and a re-test.

## 11. Open items (for the owner)

- Check that the name "MSP Sentinel" is free: trademark, domain and GitHub org.
