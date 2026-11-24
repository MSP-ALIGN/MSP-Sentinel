# Start here

New to MSP Sentinel? Follow these steps on your first day. Each one links to a short guide.

## Your first day

1. **Install Sentinel.** Run the one-line installer on a fresh Debian 13 VM and answer its seven questions. See
   [Install](install.md).
2. **Sign in and set up two-factor authentication.** Scan the QR code with an authenticator app, then keep your 10
   recovery codes somewhere safe. See [Users and security](guides/users-and-security.md#sign-in-and-two-factor-authentication).
3. **Add a second admin.** Two admins mean nobody is locked out, and pen-test engagements need a second admin to
   approve them (unless you turn two-person approval off under Settings). See [Users and security](guides/users-and-security.md#add-a-user).
4. **Set your time zone** under **Administration → Settings → General**, so times are shown in your time and new
   clients start in it (each user can pick their own under **My profile**).
5. **Add a client.** Give it a name, its time zone and a scan window (when scans may run). See
   [Your first client](guides/first-client.md#add-the-client).
6. **Record the client's authorisation.** Enter who approved scanning, the dates and exactly which addresses and
   domains. Nothing is scanned without it. See [Your first client](guides/first-client.md#record-the-authorisation)
   and the [authorisation form](authorisation-form.md) template.
7. **Scan.** Press **Scan now**, or let the weekly scan run in the client's window. See
   [Your first client](guides/first-client.md#scan).
8. **Read and triage the findings.** Fix what matters first; accept a risk or mark a false positive with a note. See
   [Findings](guides/findings.md).
9. **Create a report.** An executive summary for management and a technical report for IT, printed to PDF from the
   browser. See [Reports](guides/reports.md).

## Guides by task

| Guide | What it covers |
|---|---|
| [Your first client](guides/first-client.md) | Add a client, scan window, authorisation, discovery, first scan |
| [Findings](guides/findings.md) | Fail and Warning, triage, owners and due dates, verify fix, grades |
| [Search](guides/search.md) | The top-bar search and the filters on each list |
| [Reports](guides/reports.md) | Executive and technical reports, monthly reports, PDF and CSV |
| [Pen-test engagements](guides/engagements.md) | Create, approve, run, stop, report and retest |
| [On-premises agents](guides/agents.md) | Internal scans, enrolment, updates, Active Directory checks |
| [Agent in Docker](guides/docker-agent.md) | Run the agent as a container on a Linux Docker host |
| [Agent on Proxmox](guides/proxmox-agent.md) | Run the agent in a Proxmox LXC container |
| [Integrations](guides/integrations.md) | ITFlow, MSP Align, NinjaOne, breach monitoring, API and events |
| [Alerts](guides/alerts.md) | Email, Teams/Slack, notifications and daily fix reminders |
| [Users and security](guides/users-and-security.md) | Roles, two-factor sign-in, users, API tokens, confirmations, audit log |
| [Running the server](guides/admin-system.md) | System page, updates, backups and restores, retention, demo data, pausing |

The same help is built into the app: **Help** in the menu, with a "What's new" page for every release.

## Reference

| Document | What's in it |
|---|---|
| [Install](install.md) | The installer step by step, what it sets up, manual install on other systems |
| [Configuration](configuration.md) | Every `config/config.php` option and environment variable |
| [Upgrade](upgrade.md) | Update now, `msp-sentinel-update`, the installer, rolling back |
| [Backup and restore](backup.md) | Encrypted backups, restore, moving servers |
| [Operations](operations.md) | Scheduled jobs, health checks, logs, retention, troubleshooting |
| [On-premises agent](agent.md) | The agent in depth: safety model, schedule, updates, release key, grading |
| [Windows agent](windows-agent.md) | The Windows agent (preview) |
| [Pen-test engagements](engagements.md) | Every engagement test, rule and finding in detail |
| [API](api.md) | Tokens, endpoints, signed outbound events |
| [Authorisation form](authorisation-form.md) | A template for the client's written approval (external, internal, engagements) |
| [Security](security.md) | What Sentinel protects, and your hardening checklist |
| [Responsible use](responsible-use.md) | Authorisation, gentle scanning, honest reporting |
| [Design](DESIGN.md) | How Sentinel is built |
| [Roadmap](ROADMAP.md), [security roadmap](ROADMAP-security.md), [ITFlow roadmap](ROADMAP-itflow.md) | What comes next |
| [Contributing](../CONTRIBUTING.md) and [security policy](../SECURITY.md) | How to contribute, how to report a vulnerability |

## Release history

The newest releases are under [What's new](../README.md#whats-new) in the README. Older ones are in the
[release history](whats-new.md), every change is in the [changelog](../CHANGELOG.md), and major releases have
[release notes](releases/1.0.0.md).

Screenshots in this repository use made-up clients and documentation addresses only.
