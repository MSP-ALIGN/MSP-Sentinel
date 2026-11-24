# Upgrading

Sentinel follows semantic versioning: `x.Y.0` releases add features, `x.y.Z` releases only fix things. Read the
release notes ([CHANGELOG.md](../CHANGELOG.md)) before upgrading.

## With the one-line install

If you installed with the one-line command, run:

```sh
sudo msp-sentinel-update
```

It fetches the branch the server follows (see `/etc/msp-sentinel/update.env`) and runs the upgrade below.

### From the web interface

On servers installed with the one-line command, admins can also click **Update now** under
**Administration → System → Version and updates** (admins only; it asks "Are you sure?"). It runs exactly the
same `msp-sentinel-update` on the server: backup first, fetch the branch, database changes, health check. Sentinel
may be unavailable for a minute while it restarts. Refresh the page to see the progress and the output.

How it works, and why it is safe:
- The web app runs without privileges and cannot update itself. It only creates an empty file,
  `/opt/msp-sentinel/storage/update-request`.
- A systemd path unit (`msp-sentinel-web-update.path`) notices the file and starts
  `/usr/local/sbin/msp-sentinel-update-runner` as root. The runner deletes the file without reading it, and always
  runs the same fixed command. Nothing typed in the browser reaches it.
- Progress is written to `/var/lib/msp-sentinel-update/` (`status.json`, `update.log`), which the web app can read but
  not change.
- Only admins see the button, and every request (and every refusal) is in the audit log.
- The runner itself starts at most once every 15 minutes, one update at a time, and can only run the normal update
  (which backs up first). So even someone with a stolen admin session, or who could run code as the web server's
  user, could at worst start an unplanned update no more than four times an hour; they could not run anything
  else as root.

**What gets installed.** A server that follows a branch installs whatever that branch holds when the update runs:
branch code is not signed. The **Update now** card shows the installed commit and the newest commit seen at the last
check; if in doubt, look that commit up on GitHub before you click. For client work, a server installed from a signed
release download (below) is the more conservative choice.

Servers installed before 1.12.0 get it with their next `sudo msp-sentinel-update`. Servers installed from a release
download (below) don't have it: update those on the server.

To turn it off on a server (it stays off across upgrades):

```sh
sudo systemctl disable --now msp-sentinel-web-update.path
sudo rm -f /var/lib/msp-sentinel-update/enabled
```

Re-running the installer or the one-liner keeps it off. To turn it back on, recreate the marker and update:
`sudo install -m 0644 /dev/null /var/lib/msp-sentinel-update/enabled && sudo msp-sentinel-update`. Install without it
from the start with `SENTINEL_WEB_UPDATE=n` (one-line install) or `--no-web-update` (installer).

## With the installer

1. Download and verify the new release (see [install.md](install.md), step 1) and unpack it.
2. From the **new** release folder:

   ```sh
   sudo ./install/install.sh --upgrade
   ```

The upgrade:
1. makes a backup in `/var/backups/msp-sentinel/`;
2. replaces the code, keeping `config/config.php` and `storage/`;
3. runs the database migrations;
4. reloads PHP-FPM;
5. runs the health check.

It refuses to downgrade. While the code changes, the scheduled jobs are switched off; if a job such as a scan is
running, the upgrade waits for it to finish (up to an hour; pause scanning in the web interface to stop it sooner).
The jobs are switched back on at the end, even if the upgrade fails. The PHP-FPM pool, cron and log-rotation files
are rewritten from the new release; the Nginx site is left as it is.

## Manual upgrade

```sh
sudo -u sentinel php bin/backup.php --dir=/var/backups/msp-sentinel   # 1. back up
# 2. replace the code, keeping config/config.php and storage/
php bin/migrate.php                                                   # 3. migrations (safe to run twice)
sudo systemctl reload php8.4-fpm                                      # 4. clear PHP's code cache
php bin/doctor.php                                                    # 5. check
```

## Rolling back

The installer never downgrades, so a rollback is done by hand with the previous release and the backup the upgrade
made first (the newest file in `/var/backups/msp-sentinel/` from before the upgrade):

```sh
sudo mv /etc/cron.d/msp-sentinel /etc/msp-sentinel/cron.paused          # stop the jobs
tar xzf msp-sentinel-<old version>.tar.gz                               # the release you had before
sudo rsync -a --delete --exclude '/config/config.php*' --exclude /storage/ msp-sentinel-<old version>/ /opt/msp-sentinel/
sudo find /opt/msp-sentinel -path /opt/msp-sentinel/storage -prune -o -exec chown root:sentinel {} +
sudo chmod o+x /opt/msp-sentinel /opt/msp-sentinel/public && sudo chmod -R o+rX /opt/msp-sentinel/public/assets
sudo -u sentinel php8.4 /opt/msp-sentinel/bin/restore.php --file=/var/backups/msp-sentinel/<pre-upgrade backup> --yes
sudo systemctl reload php8.4-fpm
sudo mv /etc/msp-sentinel/cron.paused /etc/cron.d/msp-sentinel          # jobs back on
```

The restore puts the database back as it was before the upgrade's migrations. See [backup.md](backup.md).

## Knowing when there is an update

Once a day the worker asks the releases feed for the latest version (nothing else is sent). Admins see newer
versions under **Administration → System** and in the health check. Turn the check off there if you prefer.

Servers installed with the one-line command also know the branch and commit they run. The same daily check asks
GitHub how many commits that branch has moved on since, so a development server following `develop` (or production
following `main`) shows **Update available: the develop branch has N new commit(s)**. **Check now** asks straight away.
