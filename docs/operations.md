# Running Sentinel day to day

## Scheduled jobs

| Job | When (installer default) | What it does |
|---|---|---|
| `bin/worker.php` | every minute | Runs queued and weekly scans, daily certificate, website and email checks and *verify fix* rechecks; queues on-premises agent jobs (weekly full scan, daily light sweep); syncs inventory sources; sends alerts, daily fix reminders and events; creates monthly reports; records trend counts; checks for updates and applies data retention (daily). Runs as `sentinel`, never root. One worker at a time; scans continue in the next window if the window closes. |
| `bin/feeds.php` | daily 04:41 | Refreshes CISA KEV, NVD and EPSS data and re-grades findings. |
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
