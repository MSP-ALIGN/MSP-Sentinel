# Installing MSP Sentinel

This guide installs Sentinel on a fresh **Ubuntu 24.04 LTS** or **Debian 12** server with Nginx, PHP-FPM 8.4 and
MariaDB. The installer does everything; the manual steps at the end are for other setups.

## Before you start

- A small server or VM: 2 vCPU, 4 GB RAM and 20 GB of disk is plenty for a few hundred client addresses.
- A host name for Sentinel (for example `sentinel.msp.example`) pointing at the server, if you want a trusted
  certificate from Let's Encrypt. Ports 80 and 443 must be reachable for that.
- Outbound access from the server to:
  - the client addresses you will scan;
  - `crt.sh` (discovery), `services.nvd.nist.gov`, `www.cisa.gov` and `api.first.org` (vulnerability data);
  - your mail server, and your webhook receivers if you use them;
  - `api.github.com` for the daily update check (optional, can be turned off).
- Written permission from each client to scan the addresses you will add. Sentinel records these approvals, but
  getting them is your job.

## Install with the installer

1. Download the release and check it:

   ```sh
   V=1.7.0   # the release you are installing (see the Releases page)
   curl -LO https://github.com/msp-align/msp-sentinel/releases/download/v$V/msp-sentinel-$V.tar.gz
   curl -LO https://github.com/msp-align/msp-sentinel/releases/download/v$V/SHA256SUMS
   curl -LO https://github.com/msp-align/msp-sentinel/releases/download/v$V/SHA256SUMS.asc
   gpg --verify SHA256SUMS.asc SHA256SUMS      # check the key fingerprint against SECURITY.md
   sha256sum -c SHA256SUMS
   tar xzf msp-sentinel-$V.tar.gz
   cd msp-sentinel-$V
   ```

2. See what the installer would do (changes nothing):

   ```sh
   ./install/install.sh --dry-run --domain sentinel.msp.example
   ```

3. Install. With a Let's Encrypt certificate:

   ```sh
   sudo ./install/install.sh --domain sentinel.msp.example --certbot --email admin@msp.example
   ```

   Or with a self-signed certificate, for a test or when you will install your own certificate:

   ```sh
   sudo ./install/install.sh --domain sentinel.msp.example
   ```

4. The installer asks for the first admin's user name, name, email and password. Then open
   `https://sentinel.msp.example`, sign in, and set up two-factor authentication.

5. Copy `/opt/msp-sentinel/config/config.php` somewhere safe (a password manager or vault). Its `app_key` is needed
   to restore a backup.

### What the installer sets up

| Item | Where |
|---|---|
| Application (owned by root, readable by the app only) | `/opt/msp-sentinel` |
| Configuration (app key, database password) | `/opt/msp-sentinel/config/config.php`, mode 0640 |
| Writable data (report logo, CA cache) | `/opt/msp-sentinel/storage` |
| System user that runs the worker and cron jobs | `sentinel` (no login shell) |
| Database and user, with a random password | `msp_sentinel` on the local MariaDB |
| PHP-FPM pool (www-data, group sentinel) | `/etc/php/8.4/fpm/pool.d/msp-sentinel.conf` |
| Nginx site (HTTP redirects to HTTPS) | `/etc/nginx/sites-available/msp-sentinel` |
| Cron jobs: worker every minute, feeds daily, discovery weekly, backup daily | `/etc/cron.d/msp-sentinel` |
| Logs (rotated weekly) | `/var/log/msp-sentinel/` |
| Daily backups (keep 14) | `/var/backups/msp-sentinel/` |

Re-running the installer with the same version is safe: it keeps the config and database and re-applies the
rest (for example to switch to `--certbot` later). On hosts with IPv6 turned off, the Nginx site listens on IPv4 only.

Then check everything with `sudo -u sentinel php8.4 /opt/msp-sentinel/bin/doctor.php`, or under
**Administration → System**.

## After installing

1. **Settings → Alerts:** set up email (SMTP) and, if you like, a Teams or Slack webhook. Use the test buttons.
2. **Settings → Report branding:** your company name, logo, colour and contact details.
3. **Users:** add your technicians (role *technician*) and anyone who only needs to read (role *viewer*).
4. **Clients:** add a client, record the scan authorisation with the approved addresses, and run a first scan.
5. Optionally, get a free **NVD API key** and set `nvd.api_key` in the config: vulnerability lookups get about ten
   times faster.
6. Optionally, encrypt the daily backups: see [backup.md](backup.md).

## Manual install (other systems)

Requirements: PHP 8.4 (8.3 works) with `pdo_mysql`, `sodium`, `mbstring`, `openssl`, `curl`, `simplexml` and `gd`;
MariaDB 10.6+; nmap 7.x; a web server; HTTPS.

```sh
# 1. Put the release in place, e.g. /opt/msp-sentinel. The web root is public/.
# 2. Configuration (database password on stdin, never on the command line):
printf '%s\n' 'the-database-password' | php bin/setup-config.php --public-url=https://sentinel.msp.example
# 3. Database:
php bin/migrate.php
# 4. First admin (password asked on the terminal):
php bin/create-admin.php --username=jdoe --name="Jane Doe" --email=jdoe@msp.example
# 5. Health check:
php bin/doctor.php
```

Cron jobs, as an **unprivileged** user (the worker refuses to run as root):

```
* * * * *  php /opt/msp-sentinel/bin/worker.php
41 4 * * * php /opt/msp-sentinel/bin/feeds.php
17 3 * * 0 php /opt/msp-sentinel/bin/discover.php
23 2 * * * php /opt/msp-sentinel/bin/backup.php --dir=/var/backups/msp-sentinel --keep=14
```

Web server:
- Send every request that is not a file under `public/` to `public/index.php`. `public/.htaccess` does this for
  Apache; `install/templates/nginx.conf` is the Nginx version.
- Pass the `Authorization` header to PHP, or the API refuses every call. With Apache and PHP-FPM, use
  `CGIPassAuth On`.
- `storage/` must be writable by both the web server and the worker user. Put both in one group and make the
  folder group-writable with setgid (`chmod 2770`).

If Sentinel sits behind a reverse proxy, list the proxy's address under `app.trusted_proxies`.
