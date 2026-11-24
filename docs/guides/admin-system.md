# Running the server

Keep Sentinel healthy and up to date, back it up, and control what it keeps. For **admins**; the server commands need
`sudo` on the Sentinel server. The reference pages are [Upgrade](../upgrade.md), [Backup and restore](../backup.md)
and [Operations](../operations.md).

## Check its health

1. Go to **Administration → System**.
2. Look at the health checks: PHP, the database, migrations, the clock, nmap, the scan worker, the vulnerability feeds,
   storage and disk space, HTTPS, email and updates. Fix anything marked as a problem first.
3. On the server, `php bin/doctor.php` runs the same checks (`--json` for your monitoring).

## Update Sentinel

1. Under **Administration → System → Version and updates**, Sentinel shows when a newer version exists.
2. On a server installed with the one-line command, click **Update now** and confirm. It runs the same update as
   `sudo msp-sentinel-update`: backup first, fetch the code, database changes, health check. Sentinel may be
   unavailable for a minute; refresh the page to see the progress.
3. **Branch code is not signed.** A server that follows a branch installs whatever the branch holds when the update
   runs. The card shows the **installed commit** and the **newest commit** seen at the last check: if in doubt, look
   that commit up before you click.
4. A server installed from a **signed release download** has no Update now button. Download the new release and run
   its installer on the server: see [Upgrade](../upgrade.md#with-the-installer).

After updating, sign the new version for your agents: see [On-premises agents](agents.md#update-agents).

## Back up

1. The installer sets up a daily backup at 02:23 that keeps the newest 14 in `/var/backups/msp-sentinel/`. Each
   backup holds the database, the config file (with the app key) and the report logo.
2. To encrypt them, create `/etc/msp-sentinel/backup.env`, owned by `sentinel:sentinel` with mode `0600` (owner only,
   so the web server can't read it):

   ```sh
   export SENTINEL_BACKUP_ENCRYPT=1
   export SENTINEL_BACKUP_PASSPHRASE='a long passphrase kept in your password vault'
   ```

3. Copy the backups off the server on your own schedule. Encrypt every copy that leaves the server.
4. **Check them** under **Administration → System → Backups**: each run with its time, result, size and whether it was
   encrypted. The health check turns red, and admins get an alert (in-app and email, at most once a day), when the last
   backup failed or the last good one is more than 2 days old.

## Restore

1. Check the backup first (changes nothing): `sudo -u sentinel php bin/restore.php --file=...`
2. Restore with `--yes`, adding `--with-storage` and (as root) `--with-config` on a new server. The full steps are in
   [Backup and restore](../backup.md#restore).

How a restore stays safe:

- Every file is checked against the backup's manifest before anything changes.
- The database client runs with its own commands turned off (`--binary-mode`), and with `--sandbox` where the client
  supports it, so a changed backup can only run SQL against Sentinel's own database.
- Settings that name programs, folders or trust on this server are **kept from the server, never taken from a
  backup**: `scanner.nmap_path`, the update state folder, the CA file, the update URLs and `app.trusted_proxies`. So
  is the database connection.

## Choose how long data is kept

1. Under **Administration → System → Data retention**, choose how many months to keep finished scan history,
   resolved findings and reports. 0 keeps them forever (the default).
2. Save and confirm. Older data is removed once a day, and the counts go to the audit log. The audit log itself is
   always kept.

## Try it with demo data

1. Under **Administration → System → Demo data**, load four made-up clients with findings in every state, an agent
   site, devices, scan history and reports.
2. Remove them again with the same card. Removing deletes only demo clients and what belongs to them.

Demo clients use `*.example` names and documentation addresses, show a **Demo** badge, and are never scanned and
never send alerts.

## Pause all scanning

1. **Pause all scanning** on the dashboard (technicians and admins) stops everything at once, including running scans
   and pen-test engagements.
2. A single client can be paused on its page, and one site's agent scans on the client's Agents page.
3. Only admins resume.

## Good to know

- Logs are in `/var/log/msp-sentinel/`; the troubleshooting table is in [Operations](../operations.md#troubleshooting).
- Moving to a new server: install the same or a newer release, restore the latest backup, then point the DNS name at
  it. See [Backup and restore](../backup.md#moving-to-a-new-server).
- Turn the daily update check off, or Update now off on the server: see [Upgrade](../upgrade.md).
