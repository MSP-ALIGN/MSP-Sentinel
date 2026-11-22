# Changelog

All notable changes, newest first. Versions follow semantic versioning: `x.Y.0` adds features, `x.y.Z` only fixes.

### 1.3.0 (2026-11-22): Administration as its own section

- The left menu now holds only day-to-day work: Dashboard, Clients, Findings, Reports and Help.
- **Administration** moved to the user drop-down (top right) for admins: Overview, Users, Settings, API, System and
  Audit log. Admin pages have their own left menu, clearly marked, with a "Back to Sentinel" link.
- A new **Administration overview** shows each area with its key status: active users, email and webhook,
  API tokens and events, system health and updates, and recent audit activity.

### 1.2.0 (2026-11-22): command-view dashboards

- The **dashboard** is now a command view: a threat-level gauge (the highest client risk), totals, a 90-day trend,
  every client ranked by risk, the worst open findings, a live activity feed, the attack surface by type of service,
  certificates expiring in the next 30 days, and an operations strip (scanning armed or paused, worker, threat
  feeds, scans running, scan windows, authorisations).
- Every **client page** opens with its own overview console: risk gauge, totals, a scan-window countdown, trend,
  attack surface, recent activity and expiring certificates.
- A simple **risk score** (0-100, higher is worse): 20 per open known-exploited Fail, 10 per other Fail, 2 per
  Warning, capped at 100. The formula is in Help.
- Dashboards **refresh every minute** while visible, from Sentinel's own server only.
- Charts are drawn on the server as SVG with text labels; severity still comes with icons and words.

### 1.1.0 (2026-11-22): console look and new logo

- A new **dark "operations console" look** for the web interface: near-black panels with ember accents, angular
  cards, a subtle grid, uppercase headings in Chakra Petch and data in JetBrains Mono (both bundled locally under
  the SIL Open Font License, so nothing loads from other sites).
- A new **logo**: an original "radar iris" eye in a hexagon, used in the menu, on the sign-in page and as the
  browser icon. Its radar sweep is still for anyone who prefers reduced motion.
- **Dark by default, light per user:** choose under My profile → Appearance.
- Severity still never relies on colour alone, and client reports keep their clean, printable, MSP-branded style.

### 1.0.0 (2026-11-22): first stable release

- **Ready for other MSPs to install:** a release archive with checksums, and an installer for Ubuntu 24.04 and
  Debian 12 (Nginx, PHP-FPM 8.4, MariaDB, Let's Encrypt or self-signed HTTPS, cron, log rotation) with `--upgrade`
  and `--dry-run`.
- **Health check:** Administration → System and `bin/doctor.php` check PHP, the database, migrations, nmap, the
  worker, the feeds, storage, HTTPS, email and updates.
- **Backup and restore:** `bin/backup.php` (database, config and logo; optional passphrase encryption; keeps the
  newest N) and `bin/restore.php` (checks every file against its manifest first; dry run unless `--yes`). The installer sets up daily
  backups.
- **Update check:** once a day the worker asks the releases feed for the latest version; admins can turn it off.
- **Data retention:** choose how many months to keep scan history, resolved findings and reports. The audit log is
  always kept.
- **Documentation** in `docs/`: install, upgrade, configuration, security, backup, operations, API and a user guide.

### 0.10.0 (2026-11-22): API

- A JSON **API** at `/api/v1` for MSP Align and other tools: clients, summaries, assets with open services,
  findings (with history), scans and reports (including the frozen HTML and CSV). Lists are paginated and accept
  `updated_since`. The OpenAPI description is at `/api/v1/openapi.json`.
- **Tokens** are created by admins under Administration → API and shown once. Each token:
  - covers all clients or a chosen list;
  - expires (30 to 365 days) and can be limited to IP addresses or networks;
  - can always read; **triage** and **queue scans** are separate permissions, off unless ticked;
  - stops working if revoked, or if the admin who created it is deactivated or is no longer an admin.
- API scans follow the same rules as the web: scope, pauses and the client's scan window (no override).
  Triage needs a note and is marked with the token's name. Every API change is in the audit log.
- 120 requests a minute per token; repeated failed attempts from one address are blocked for a while.
- **Outbound events**: Sentinel can POST signed JSON when findings open, reopen, escalate, resolve or are triaged,
  when a scan finishes and when a report is created (`X-Sentinel-Signature: t=…,v1=HMAC-SHA256`).

### 0.9.0 (2026-11-22): reports

- Two reports per client, in your branding:
  - **Executive summary** for the client's management: an overall rating (Good, Needs attention or At risk), the
    top 5 risks in plain English ("what it means for you" and "what we're doing"), totals, a trend chart and what
    was checked;
  - **Technical findings** for IT: every open finding grouped by severity and host, with its evidence, CVE, KEV and
    EPSS data, why it matters and how to fix it, plus what was fixed this period and an appendix with scope, scans
    and methods.
- **Accepted risks and false positives** are listed in their own section with their notes, never hidden, and they
  don't count towards the totals.
- **Frozen**: each report is saved exactly as it was created, with a SHA-256, so you can show what a client was
  sent. Technicians and admins create reports; everyone can read them; admins can delete them.
- **Print to PDF** from the browser (A4 or Letter), download a self-contained HTML file, or download the findings as
  **CSV** (formulas are neutralised).
- **Monthly schedule** per client: both reports are created after each month and emailed, attached, to the MSP
  staff you choose for review before forwarding.
- **Branding** under Settings → Report branding: company name, logo (checked and re-encoded), accent colour, footer
  text, paper size, and an optional "Generated by MSP Sentinel" line.
- Severity is never shown by colour alone, and every report states its limits: external checks only, not a PCI ASV
  scan.

### 0.8.0 (2026-11-22): alerts

- **Immediate alerts** when a **Fail** finding is new or comes back. Accepted risks and false positives never alert.
- A **scan summary** (digest) after each scan, and **admin alerts** when a scan or a threat feed fails.
- Three ways to be told:
  - **in-app**: a bell in the header with an unread count, and a Notifications page;
  - **email** over SMTP (STARTTLS or TLS, certificate checked). Each user picks immediate, digest, both or none
    on their profile; up to 5 team addresses get everything;
  - a **webhook** for Teams, Slack or plain JSON. It carries a short summary and a link, never evidence.
- Admins set this up under Settings → Alerts, with test buttons. The SMTP password and webhook address are stored
  encrypted and never shown again.
- Messages go through an outbox with up to 3 tries. The worker and the feeds job send them, so no new cron job is
  needed. Set `app.public_url` in the config so alerts link back to Sentinel.

### 0.7.0 (2026-11-22): findings and triage

- One **findings list** per client, built from everything graded so far: exposed high-risk services,
  certificate problems, exposed admin pages and portals, and vulnerabilities. Only **Fail** and **Warning** items
  become findings; Info items stay in the client panels.
- **Lifecycle**:
  - a finding is **resolved** automatically when a check really sees the problem gone;
  - if the problem comes back, the same finding **reopens** and is marked "reappeared", with its history kept. An
    earlier accepted or false-positive decision is kept when the evidence is unchanged.
- **Triage** (technicians and admins, a note is always required):
  - **accepted risk** stays until the problem goes away;
  - **false positive** reopens by itself if the evidence changes (for example a different version is reported);
  - each finding has a full history, and every decision is in the audit log.
- A **Findings** page across all clients, with filters (client, status, grade, type). There is also a findings card
  at the top of each client page and open Fail/Warning counts on the dashboard.

### 0.6.0 (2026-11-22): vulnerability matching

- Services are matched to CVEs from the product and version they report:
  - when the version is known, NVD decides which CVEs affect that exact version (**confirmed**);
  - when only the product is known, only CISA known-exploited CVEs are shown, marked **product found, version
    unknown**. Never guessed;
  - a Linux distribution build (Ubuntu, Debian, RHEL...) is marked "fix may be backported", never confirmed;
  - only CVEs where NVD marks the product itself as vulnerable are counted.
- **Known exploited (KEV) first**, then critical and high. Each CVE shows its CVSS score, EPSS exploit
  likelihood and ransomware use. Lower severities are counted and can be expanded.
- Grading as agreed: confirmed KEV or critical fails; confirmed high or possible KEV gets a warning.
- **Daily feeds job** (`bin/feeds.php`): CISA KEV catalog, NVD answers (cached 7 days, rate-limited) and FIRST
  EPSS scores. Matching also runs right after each scan. Feed status is on the Settings page. An optional NVD
  API key goes in the config file. NVD's rate limits are respected across processes, and a 403/429 stops
  requests until Retry-After.
- Dashboard tile for confirmed and possible known-exploited vulnerabilities.

### 0.5.0 (2026-11-22): certificates and exposed admin pages

- **TLS certificate checks** after every port scan and once a day (in the scan window): expiry, issuer, self-signed
  or untrusted chain, name match (using in-scope hostnames as SNI), key size, signature algorithm, the negotiated
  protocol, and whether old **TLS 1.0/1.1** is still accepted.
- **Web page detection**: one request for the start page of each open web port (no logins, no path guessing),
  matched against generic signatures:
  - firewall or device admin pages (**Fail**);
  - VPN portals and remote desktop web access (**Warning**);
  - other login pages (**Info**).
- Grading follows the agreed rules: an expired certificate fails; one expiring within 14 days or with weak TLS
  gets a warning. The dashboard counts certificates expired or expiring within 14 days.
- Same safety as port scans: scope, kill switches and window are checked before every connection. Each result
  is logged in the scan log.

### 0.4.0 (2026-11-21): port scanning

- **Scan now** (technicians and admins) and **weekly scans** for every client with an active authorisation.
  Scans run only inside the client's scan window. Admins can run one outside the window by giving a reason,
  which is audited.
- **Gentle by default**: TCP connect scan as an unprivileged user, polite timing, at most 50 packets per second,
  one host at a time, light service/version detection. About 40 default ports, with per-client extras and
  exclusions.
- **Scope is checked before every host.** Hostnames are scanned by their addresses, and only addresses that are
  themselves in an active authorisation. Anything else is skipped and logged.
- Cancel a scan, or pause scanning (client or global), and nmap stops within seconds.
- **Open ports** per client: high-risk services (RDP, SMB, databases, Telnet, VNC...) are marked. There is also
  a **scan log** of every host touched or skipped.
- A queue plus a cron worker (`bin/worker.php`). A web request never runs nmap itself.

### 0.3.0 (2026-11-21): passive target discovery

- **Discover now** on a client (technicians and admins), plus a weekly CLI job (`bin/discover.php`):
  - looks up DNS records (A/AAAA/MX/NS/CNAME) of the domains in scope and a list of common names (www, mail, vpn,
    remote...);
  - checks public certificate logs (crt.sh) and reverse DNS of in-scope addresses.
- It's **passive**: DNS lookups and one public website. Nothing connects to the client's systems. It still
  respects the kill switches and needs an active authorisation.
- **Suggestions, not scope:**
  - only names under the client's own domains are suggested;
  - names at other providers (hosted mail, DNS, CDNs) are listed for information only;
  - addresses reached through an alias at another provider are flagged and left unticked.
- **Approving**: an admin ticks suggestions, and the authorisation form opens with the current scope plus the
  selection. Saving it records the client's approval and replaces the old authorisation.
- Dismissed suggestions stay dismissed. A **Change scope / renew** shortcut pre-fills a replacement authorisation.
- Tests run against a local fake DNS server and a fake crt.sh: no real lookups.

### 0.2.0 (2026-11-21): clients and the "authorised to scan" register

- **Clients** with timezone, scan window, notes and an optional ITFlow client ID. Each client gets a default
  **site**, and admins can add more (with optional ITFlow location IDs). Clients are archived, never deleted.
- **"Authorised to scan" register** (admins only):
  - each record holds who at the client approved scanning (name, role, date), the valid-from and valid-until
    dates (2 years at most), a document reference and the exact scope;
  - scope entries are public IPs, ranges up to /24 (IPv6 /120) and domains (`*.` for subdomains). Private,
    reserved and internal targets are refused;
  - authorisations can't be edited, only revoked with a reason, so the register stays trustworthy as evidence;
  - you're warned when a new entry is already in another client's scope, to catch typos.
- **Kill switches**: pause scanning for one client or for everything. Technicians and admins can pause;
  only admins can resume.
- A **scope check** that every future scan must pass: active authorisation (in the client's timezone), target in
  scope, client not archived or paused, global switch off. It fails closed.
- Dashboard shows clients, active authorisations and authorisations ending within 30 days.

### 0.1.0 (2026-11-21): foundation

- Sign-in with **mandatory two-factor authentication** (any TOTP authenticator app) and one-time recovery codes.
- Roles: **Admin**, **Technician**, **Viewer**.
- User management: add users with temporary passwords, change roles, disable users, reset passwords, reset 2FA.
- **Audit log** of sign-ins, failed sign-ins, user changes and settings changes.
- Settings: product name (white-label) and the source-code link required by the AGPL.
- Security basics on every page:
  - CSRF protection, strict Content Security Policy and no-cache headers
  - session timeouts (30 minutes idle, 12 hours absolute)
  - login throttling
  - 2FA seeds encrypted at rest
- Idempotent database migrations, CLI tools and an end-to-end test suite.
