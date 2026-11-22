# Backup and restore

`bin/backup.php` saves the **database**, the **config file** and the **storage folder** (report logo) into one
`.tar.gz`, with a manifest of SHA-256 checksums. With `--encrypt` the archive is encrypted with a passphrase
(Argon2id key derivation, XChaCha20-Poly1305): any change to the file makes it fail to decrypt.

A backup contains the app key, the database password and all client data. Files are created 0600 in a 0700 folder.
**Encrypt every copy that leaves the server.**

## Daily backups (installer)

The installer adds a daily cron job that keeps the newest 14 backups in `/var/backups/msp-sentinel/`. To encrypt
them, create `/etc/msp-sentinel/backup.env` (mode 0640, `root:sentinel`):

```sh
export SENTINEL_BACKUP_ENCRYPT=1
export SENTINEL_BACKUP_PASSPHRASE='a long passphrase kept in your password vault'
```

Then copy the backups off the server (rsync, your backup tool, object storage) on your own schedule.

## By hand

```sh
sudo -u sentinel php bin/backup.php --dir=/var/backups/msp-sentinel --keep=14            # plain
sudo -u sentinel php bin/backup.php --dir=/var/backups/msp-sentinel --encrypt            # asks for a passphrase
```

Without `--dir`, backups go to `storage/backups/`. Later backups never include earlier ones.

## Restore

```sh
# 1. Check the backup (changes nothing):
sudo -u sentinel php bin/restore.php --file=/var/backups/msp-sentinel/msp-sentinel-backup-....tar.gz.enc
# 2. Restore the database:
sudo -u sentinel php bin/restore.php --file=... --yes
# On a new server, also restore the config (app key) and the logo:
sudo php bin/restore.php --file=... --yes --with-config --with-storage
```

- Every file is checked against the manifest before anything changes.
- The tables in the configured database are **replaced**.
- Pending migrations run afterwards.
- `--with-config` restores the backup's config (above all its app key) but keeps **this** server's database
  connection settings. The current config is kept as `config.php.before-restore-<time>`.
- If the backup's app key differs from the current one and you don't use `--with-config`, you are warned: two-factor
  sign-in, saved secrets and API tokens only work with the original app key.
- A backup from a newer version is refused: upgrade the code first.

## Moving to a new server

1. Install the same (or newer) release with the installer.
2. Copy the latest backup across and restore it with `--yes --with-config --with-storage`.
3. Point the DNS name at the new server and check **Administration → System**.
