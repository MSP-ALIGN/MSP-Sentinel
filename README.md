<div align="center">

<img src="public/assets/img/logo.svg" alt="MSP Sentinel logo" width="96" height="96">

# MSP Sentinel

**Self-hosted security monitoring for MSPs.** Find what attackers can see and reach, across every client,
inside and outside the network, and get it fixed on time.

![Version 1.41.0](https://img.shields.io/badge/version-1.41.0-ff5a1f?style=flat-square)
![Licence AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0-blue?style=flat-square)
![PHP 8.4](https://img.shields.io/badge/PHP-8.4-777bb4?style=flat-square&logo=php&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-10.6%2B-003545?style=flat-square&logo=mariadb&logoColor=white)
![Self-hosted](https://img.shields.io/badge/self--hosted-your%20data%20stays%20yours-2ea44f?style=flat-square)

[Features](#features) · [Screenshots](#screenshots) · [How it stays safe](#how-it-stays-safe) · [Install](#install) ·
[Documentation](#documentation) · [What's new](#whats-new)

</div>

<p align="center"><img src="docs/images/dashboard.webp" alt="The MSP Sentinel dashboard: threat level, open findings, client risk grid, top exposures and live activity" width="900"></p>

## What it is

MSP Sentinel is a security product an MSP runs on its own server and brands as its own. It finds what attackers can
see and reach at each client, from the internet and inside the network, alerts on it, and tracks the fixes until a
check proves them. Its companion product, **MSP Align**, plans, reports and proves, using Sentinel's findings.

## Features

- **External exposure:** forgotten hostnames (DNS, certificate logs), gentle port scans, exposed admin pages, VPN
  portals and remote access, TLS certificates.
- **Website and email:** HTTPS and security headers, cookies, exposed `.git`/`.env`/backups, CMS versions, SPF, DMARC
  and DKIM, DNS zone transfers and subdomain takeover.
- **Vulnerabilities:** matched with NVD, CISA's known-exploited list (KEV) and EPSS; "confirmed" and "possible" kept
  apart, versions never guessed.
- **Inside the network:** an outbound-only on-premises agent finds devices, services, certificates, risky protocols
  and Active Directory weaknesses; NinjaOne adds installed software, updates, antivirus and encryption.
- **Breached accounts:** weekly check of your clients' domains against known data breaches.
- **Fix workflow:** triage, owners, due dates, daily reminders and *verify fix* rechecks of one finding.
- **Pen-test engagements:** time-boxed deeper tests, approved by a second admin, with a report and a retest letter.
- **Alerts and reports:** bell, email and Teams/Slack; branded executive and technical reports, frozen with a SHA-256.
- **Integrations:** ITFlow (clients and tickets), MSP Align (compliance), NinjaOne (devices), API and signed events.
- **Operations:** one-command installer, Update now, encrypted backups, health checks, audit log.

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="docs/images/client.webp" alt="A client's overview: risk gauge, open findings and attack surface (light theme)"><br><sub><b>Client overview</b> (light theme): risk score, findings, attack surface.</sub></td>
    <td width="50%"><img src="docs/images/findings.webp" alt="All findings with owner and due-date filters"><br><sub><b>Findings</b>: owners, due dates, overdue and due-soon quick links.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/finding.webp" alt="One finding with its fix card and history"><br><sub><b>A finding</b>: owner, due date, <i>verify fix</i> and full history.</sub></td>
    <td><img src="docs/images/website-email.webp" alt="Website and email security results"><br><sub><b>Website and email</b>: headers, exposed files, CMS versions, SPF/DMARC/DKIM.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/agents.webp" alt="On-premises agents for a client site"><br><sub><b>On-premises agents</b>: signed internal authorisation, check-ins, kill switch.</sub></td>
    <td><img src="docs/images/device.webp" alt="An internal device with its services and findings"><br><sub><b>Internal device</b>: open services, certificates, software and findings.</sub></td>
  </tr>
  <tr>
    <td><img src="docs/images/report.webp" alt="Executive summary report"><br><sub><b>Executive report</b>: branded, plain English, frozen with a SHA-256.</sub></td>
    <td><img src="docs/images/login.webp" alt="Sign-in page"><br><sub><b>Sign-in</b>: two-factor authentication is mandatory.</sub></td>
  </tr>
</table>

All screenshots use made-up clients and documentation addresses only.

## How it stays safe

- **Authorised targets only.** Nothing is scanned unless the client approved it in writing and you recorded it.
  Scope is checked again at the moment of scanning, and every active scan is logged.
- **Gentle by default.** Slow, rate-limited scans inside each client's scan window, with a global kill switch and a
  pause per client and per site.
- **Signed agent jobs.** Agents scan only the networks approved for their site, checked against a signature that the
  database alone can't forge.
- **Locked-down sign-in.** Mandatory two-factor authentication, three roles, your own password for powerful actions,
  secrets encrypted at rest.

More in [docs/security.md](docs/security.md) and [docs/responsible-use.md](docs/responsible-use.md). Sentinel is
**not a PCI ASV scan** and not a substitute for an independent penetration test.

## Install

One line on a fresh **Debian 13** VM (Debian 12 and Ubuntu 24.04 also work):

```sh
curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install.sh | sudo -E bash
```

A guided install asks seven questions (host name, HTTPS, firewall, fail2ban, automatic updates, backup passphrase,
first admin), shows a summary, then sets up Nginx, PHP 8.4, MariaDB, nmap, cron jobs and HTTPS. Upgrade later with
**Update now** under Administration → System, or `sudo msp-sentinel-update`.

Requirements, a development server, unattended installs and signed release archives: see
[docs/install.md](docs/install.md). Agents for client sites: see [docs/guides/agents.md](docs/guides/agents.md).

## Documentation

**New here? [Start here](docs/README.md)**: your first day, step by step.

| Guide | |
|---|---|
| [Your first client](docs/guides/first-client.md) | Add a client, record the authorisation, run the first scan |
| [Findings](docs/guides/findings.md) | Read, triage and fix findings; owners, due dates, verify fix |
| [Search](docs/guides/search.md) | The top-bar search and the filters |
| [Reports](docs/guides/reports.md) | Executive and technical reports, monthly reports, PDF and CSV |
| [Pen-test engagements](docs/guides/engagements.md) | Create, approve, run and report a deeper test |
| [On-premises agents](docs/guides/agents.md) | Scan inside a client's network; Active Directory checks |
| [Agent in Docker](docs/guides/docker-agent.md) / [on Proxmox](docs/guides/proxmox-agent.md) | Run the agent as a container or in an LXC |
| [Integrations](docs/guides/integrations.md) | ITFlow, MSP Align, NinjaOne, breach monitoring, API |
| [Alerts](docs/guides/alerts.md) | Email, Teams/Slack, notifications, fix reminders |
| [Users and security](docs/guides/users-and-security.md) | Roles, two-factor sign-in, users, API tokens, audit log |
| [Running the server](docs/guides/admin-system.md) | System page, updates, backups, retention, demo data |

Reference: [install](docs/install.md), [configuration](docs/configuration.md), [upgrade](docs/upgrade.md),
[backup](docs/backup.md), [operations](docs/operations.md), [API](docs/api.md) and more in
[docs/README.md](docs/README.md#reference). The same help is built into the app (**Help** in the menu).

## What's new

### 1.41.0 (2026-11-24): limit users to their clients

- **Per-user client lists.** Each user sees every client (the default, so nothing changes on upgrade) or only a
  chosen list: **Administration → Users →** the user **→ Clients** (migration 0047).
- **Nothing of other clients.** For a limited user, other clients' pages and records (findings, reports, scans,
  engagements, authorisations, sites) answer "not found", checked once in the request kernel before any page code
  runs, and lists, counts, search, the dashboard, reports, engagements, notifications and alert emails leave them out.
  A test fails if any page with an ID lacks a client check.
- **Never more than you see.** You can only give clients you see yourself, and only manage users whose clients you
  all see. Findings can only be given to someone who sees the client; a client a limited user adds becomes theirs.
  The last active Admin who sees every client can't be limited, demoted or disabled.

### 1.40.1 (2026-11-24): roles and permissions fixes from review

- **API tokens never do more than their creator.** Only someone who may triage findings or start scans can give a
  token those rights, and a token loses them when its creator does (read access stays).
- **One active Admin always stays.** The lock-out guard now counts only the built-in Admin, which also gets every
  permission a later release adds; a custom role with every permission today would fall short then.
- **Checked again when saving.** Who may change a user or a role, and which role may be given, is checked again
  with the rows locked, so a role changed meanwhile by someone more powerful can't slip through or be saved over; a
  role deleted meanwhile gives a form error.
- **Pages show only what you may use:** the Administration overview shows only your areas, and the System page shows
  a release signer only the release key.
- **Breached addresses** on a finding's page are masked unless you may see them in full.
- Permissions that reach the whole system are marked **Near full control** on the Roles page. The demo data command
  picks an Admin by role.

### 1.40.0 (2026-11-24): roles and permissions

- **Permissions.** Every action now needs a permission: 29 of them in 7 groups (clients and scope, scanning,
  findings, reports, engagements, agents and devices, administration). Seeing clients and their findings needs none.
- **Built-in roles unchanged.** Viewer, Technician and Admin keep exactly the rights they had (a test checks every
  page and action against 1.39). Existing users keep their role (migration 0046).
- **Your own roles.** **Administration → Roles** creates roles from the permission list (or copies a built-in one),
  for example a "Lead technician" who may also set due dates and approve engagements, without full Admin. The
  **Who can do what** table shows every permission and which role holds it.
- **Never more than you hold.** You can only give permissions and roles you hold yourself, and can't change, reset
  the password or two-factor of, or disable a more powerful user. Nobody changes their own role, built-in roles never
  change, and at least one active user always holds every permission. Role changes are confirmed with your password,
  audited with what was added and removed, and sign the role's users out so they apply at once.
- **Alerts, owners and approvals follow permissions:** system, backup and feed alerts go to those who manage the
  system or settings; findings can be given to anyone who may triage; any second person who may approve engagements
  can approve; API tokens keep working while their creator may manage the API.

Older releases: [release history](docs/whats-new.md). Every change: [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Commits carry a DCO sign-off (`git commit -s`).

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
| `src/` | Application code (`Core`, `Auth`, `Scope`, `Discovery`, `Scanning`, `Web`, `Vulns`, `Findings`, `Inventory`, `Agent`, `AgentClient`, `Alerts`, `Reports`, `Dashboard`, `Api`, `System`, `Controllers`) |
| `views/` | PHP templates (every value is escaped with `e()`) |
| `migrations/` | Idempotent database migrations |
| `bin/` | CLI tools, including the on-premises agent (`sentinel-agent.php`) and demo data (`demo.php`) |
| `lang/` | Interface translations (English is the source language) |
| `help/` | In-app help and "What's new" entries |
| `tests/` | End-to-end and unit tests |
| `docs/` | Guides, design, roadmap and README screenshots (`docs/images/`) |
| `install/` | Server and agent installers, and config templates |

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Third-party components

Served from `public/assets/vendor/`, each with its licence file: Bootstrap 5.3.8 (MIT), AdminLTE 4.10.0 (MIT),
Bootstrap Icons 1.13.1 (MIT), qrcode-generator 2.0.4 (MIT, licence notice in the file header), and the fonts
Chakra Petch and JetBrains Mono (SIL Open Font License 1.1, licence files in `public/assets/vendor/fonts/`).
