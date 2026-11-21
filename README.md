# MSP Sentinel

Self-hosted security monitoring for MSPs (managed service providers). Sentinel **detects**: it finds external
exposure and vulnerabilities across your clients, monitors them and alerts on them. Its companion product,
MSP Align, plans, reports and proves, using Sentinel's findings.

> **Status: early development (0.3.0).** Sign-in, users, clients, the "authorised to scan" register and passive
> target discovery are in place. **It does not scan anything yet.** See [`docs/DESIGN.md`](docs/DESIGN.md) for the v1.0 design and
> [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full plan (external scanning, internal agent, pen testing).

Sentinel is free software under the [GNU AGPL-3.0](LICENSE). Each MSP runs its own copy and owns its data.

## What's new

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

## Requirements

- PHP 8.4 (8.3 works), with the extensions `pdo_mysql`, `sodium`, `mbstring`, `openssl` and `curl`
- MariaDB 10.6 or newer
- A web server that sends requests to `public/index.php` (Apache with the included `.htaccess`, nginx, or similar)
- HTTPS in production

## Install (manual, for now)

A Docker Compose setup and a setup wizard come in a later release.

```sh
# 1. Configuration (outside the web root; keep it private)
cp config/config.example.php config/config.php
php bin/generate-key.php           # paste the output into 'app_key'
# edit config/config.php: database details

# 2. Database
php bin/migrate.php                # safe to run any time, including after every upgrade

# 3. First admin (the password is read from the terminal, hidden)
php bin/create-admin.php --username=jdoe --name="Jane Doe" --email=jdoe@msp.example
```

Weekly discovery (optional, recommended): add a cron job such as
`17 3 * * 0  php /path/to/msp-sentinel/bin/discover.php`.

Point the web server's document root at `public/`. Sign in, and you'll be asked to set up two-factor
authentication.

**Back up `config/config.php`.** Its `app_key` encrypts the 2FA seeds. If the key is lost, every user has to set
up 2FA again.

## Tests

The end-to-end suite creates a throwaway database, starts PHP's built-in web server on `127.0.0.1` and drives the
real application. It never contacts any other host, and it uses only made-up data.

```sh
php tests/run.php            # all tests
php tests/run.php users      # only tests whose name contains "users"
```

The database admin used to create and drop the test database is set with `SENTINEL_TEST_DB_ADMIN_DSN`,
`SENTINEL_TEST_DB_ADMIN_USER` and `SENTINEL_TEST_DB_ADMIN_PASS`. By default it uses `root` over the local socket.

## Project layout

| Path | What |
|---|---|
| `public/` | Web root: front controller and static assets (Bootstrap 5.3, AdminLTE 4 and Bootstrap Icons, all served locally) |
| `src/` | Application code (`Core`, `Auth`, `Controllers`, `Migrations`) |
| `views/` | PHP templates (every value is escaped with `e()`) |
| `migrations/` | Idempotent database migrations |
| `bin/` | CLI tools |
| `lang/` | Interface translations (English is the source language) |
| `help/` | In-app help and "What's new" entries |
| `tests/` | End-to-end and unit tests |
| `docs/` | Design and roadmap |

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Third-party components

Served from `public/assets/vendor/`, each with its licence file: Bootstrap 5.3.8 (MIT), AdminLTE 4.10.0 (MIT),
Bootstrap Icons 1.13.1 (MIT), qrcode-generator 2.0.4 (MIT, licence notice in the file header).
