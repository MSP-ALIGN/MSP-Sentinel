# Running Sentinel day to day

## Scheduled jobs

| Job | When (installer default) | What it does |
|---|---|---|
| `bin/worker.php` | every minute | Runs queued and weekly scans, daily certificate, website and email checks and *verify fix* rechecks; queues on-premises agent jobs (weekly full scan, daily light sweep); syncs inventory sources; sends alerts, daily fix reminders and events; creates monthly reports; records trend counts; checks for updates and applies data retention (daily). Runs as `sentinel`, never root. One worker at a time; scans continue in the next window if the window closes. |
| (worker) ITFlow client sync | every 15 minutes, when turned on | Adds new ITFlow clients, applies renames and archives, links MSP Align by ITFlow ID. |
| (worker) ITFlow tickets | every 5 minutes, when turned on | Opens tickets for new Fail and known-exploited findings (up to 20 a run), the weekly Warnings ticket, and known-exploited notes. |
| `bin/feeds.php --if-due` | checked every 5 minutes | Refreshes CISA KEV, NVD and EPSS data and re-grades findings when due: about once a day (every 23 hours), within minutes of installing, an hour after a run with a problem, or after **Refresh now** (Administration → Settings → Vulnerability data). One run at a time. |
| `bin/discover.php` | weekly, Sunday 03:17 | Passive discovery (DNS, certificate logs) for every client. Suggestions need an admin's approval. |
| `bin/backup.php` | daily 02:23 | Backup, keeps 14. See [backup.md](backup.md). |

## Health

- **Administration → System** and `php bin/doctor.php` (exit code 1 if something fails; `--json` for monitoring)
  check PHP, extensions, the database, migrations, the clock, config permissions, nmap, the worker heartbeat, the
  feeds, storage, disk space, HTTPS, email and updates.
- Point your monitoring at `bin/doctor.php --json`, or at the System page, or at the worker log.

## Logs

| Log | What |
|---|---|
| `/var/log/msp-sentinel/worker.log` | Worker output (one line per run) |
| `/var/log/msp-sentinel/feeds.log`, `discover.log`, `backup.log` | The other jobs |
| `/var/log/msp-sentinel/php-error.log` | PHP errors from the web interface (details users never see) |
| `/var/log/nginx/msp-sentinel.*.log` | Web access and errors |
| Audit log (in the app) | Who did what: sign-ins, changes, triage, scans, API writes |

## Data retention

Under **Administration → System → Data retention** admins choose how many months to keep finished scan history,
resolved findings and reports (0 keeps them forever, the default). The worker removes older data once a day and
writes the counts to the audit log. The audit log itself is never removed. A resolved finding that was removed and
later comes back is treated as new.

## Demo data

Made-up clients for trying Sentinel out, testing a development server or training technicians. Admins load and
remove it under **Administration → System → Demo data**, or on the server:

```sh
sudo -u sentinel php /opt/msp-sentinel/bin/demo.php --load     # --user=USERNAME picks the admin findings are assigned to
sudo -u sentinel php /opt/msp-sentinel/bin/demo.php --status
sudo -u sentinel php /opt/msp-sentinel/bin/demo.php --remove
```

What it adds:

| Client | Shows |
|---|---|
| Riverside Example Ltd | Lots to fix: known exploited vulnerabilities, an exposed firewall admin page and VPN portal, expired and weak certificates, website and email problems. Also an on-premises agent site (SMBv1, Telnet, SNMP "private", RDP without NLA, a login page over HTTP) and inventory devices (unsupported Windows, antivirus off, encryption off, missing and failed patches, vulnerable Chrome and 7-Zip). |
| Lakeshore Example Inc | An Exchange server with a possible known exploited vulnerability, a remote desktop web portal, TLS 1.0, weak SPF and DMARC. |
| Hillcrest Example Clinic | A well-run client: no open problems, only fixed history. |
| Bayview Example Co | MySQL open to the internet, a certificate name mismatch, and an authorisation that ends in 12 days. |

Findings are built by the normal findings engine, then some are assigned to the admin who loaded the data, accepted,
marked false positive, given a due date, or left overdue. There are also scan history, discovery suggestions,
90 days of trend history and two reports.

Safety:
- Demo clients use `*.example` names and documentation-only addresses (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, plus `10.20.0.0/24` for the made-up office network).
- They carry a **Demo** badge and are **never scanned**. Scheduled and manual scans, verify fix, discovery, agent
  scans, inventory sync and vulnerability look-ups all refuse or skip them. The demo agent's token is thrown away
  when it is created, so nothing can ever sign in as it.
- No user accounts are created. Demo clients never send notifications, alert emails, webhooks, outbound events,
  fix reminders or monthly reports.
- Removing deletes only demo clients and what belongs to them. The public CVE and KEV entries the demo refers to
  stay, because they are real reference data that the daily feeds keep up to date. The audit log keeps its records
  of loading and removing.

## Pausing scans

- **Pause all scanning** (header button, technicians and admins) stops everything at once, including running scans.
- A single client can be paused on its page. Only admins resume.
- Agent scans at one site can be paused under **On-premises agents** on the client page (running agent scans stop
  within a minute). The agents themselves are covered in [agent.md](agent.md).

## Troubleshooting

| Symptom | Check |
|---|---|
| "Scan worker has never run" | Is the cron file in `/etc/cron.d/` and is cron running? Look at `worker.log`. |
| Scans stay "queued" | Is the client's scan window open now (client time zone)? Is scanning paused? Is there an active authorisation? |
| No vulnerability matches | Has `feeds.php` run (System page)? NVD without an API key is slow: big first runs finish over several days. |
| Emails not arriving | Settings → Alerts → recent deliveries shows the last error. Use "Send test email". |
| API always answers 401 | Does the web server pass the `Authorization` header (see [install.md](install.md))? Is the token expired or revoked? |
| "Your form expired" | The session ended or the page was open too long: reload and try again. |
| Wrong client addresses in logs | Add your reverse proxy to `app.trusted_proxies`. |
