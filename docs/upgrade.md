# Upgrading

Sentinel follows semantic versioning: `x.Y.0` releases add features, `x.y.Z` releases only fix things. Read the
release notes ([CHANGELOG.md](../CHANGELOG.md)) before upgrading.

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

It refuses to downgrade. Scans running during the upgrade continue; the next worker run uses the new code.

## Manual upgrade

```sh
sudo -u sentinel php bin/backup.php --dir=/var/backups/msp-sentinel   # 1. back up
# 2. replace the code, keeping config/config.php and storage/
php bin/migrate.php                                                   # 3. migrations (safe to run twice)
sudo systemctl reload php8.4-fpm                                      # 4. clear PHP's code cache
php bin/doctor.php                                                    # 5. check
```

## If something goes wrong

Restore the backup made before the upgrade (with the old release's code back in place):

```sh
sudo -u sentinel php bin/restore.php --file=/var/backups/msp-sentinel/<file> --yes
```

See [backup.md](backup.md).

## Knowing when there is an update

Once a day the worker asks the releases feed for the latest version (nothing else is sent). Admins see newer
versions under **Administration → System** and in the health check. Turn the check off there if you prefer.
