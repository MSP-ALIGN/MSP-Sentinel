# Installing MSP Sentinel

This guide installs Sentinel on a fresh **Debian 13** server (Debian 12 and Ubuntu 24.04 LTS also work) with Nginx,
PHP-FPM 8.4 and MariaDB. The installer does everything; the manual steps at the end are for other setups.

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

## One-line install (recommended)

On a fresh Debian 13 VM (a minimal Debian may need `apt install -y curl sudo` first, as root):

```sh
curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install.sh | sudo -E bash
```

It installs `git`, `curl` and `rsync` and fetches Sentinel from GitHub into `/opt/msp-sentinel-src`. It then walks you
through seven steps and shows a summary, and only installs Sentinel once you answer `y`. It also adds the command `sudo msp-sentinel-update` for later upgrades. Run it
again on an installed server and it upgrades instead.

### The guided install, step by step

**Step 1 — Host name.** The name users type in the browser, for example `sentinel.msp.example`. For Let's Encrypt it
must be in public DNS and point at this server.

**Step 2 — HTTPS.** Pick one of three:

| Choice | Use it when | What you need |
|---|---|---|
| **1) Let's Encrypt** | The server is reachable from the internet | Public DNS for the host name; ports 80 and 443 open to the internet; an email for expiry notices. Renewal is automatic. |
| **2) Self-signed** (default) | A test server, or an internal-only server | Nothing. Browsers warn until you trust the certificate or replace it with your own in `/etc/nginx/sites-available/msp-sentinel`. |
| **3) Behind a reverse proxy** | Your proxy or load balancer already ends HTTPS | The proxy's IP address. Sentinel listens on plain HTTP port 80 and accepts connections **from that IP only**. |

For a reverse proxy, set it up to:
- terminate HTTPS with a trusted certificate for the host name;
- forward to `http://<sentinel-server>:80` and keep the original `Host` header;
- send `X-Forwarded-For` (the user's address, used for sign-in rate limits and the audit log) and
  `X-Forwarded-Proto: https`;
- pass the `Authorization` header through (the API needs it).

Sentinel trusts the forwarded headers only from the proxy IP you gave, so a user cannot fake their address.

**Step 3 — Firewall (ufw).** Default yes. Allows SSH (rate-limited, on every port sshd listens on), and HTTP and HTTPS — or,
behind a proxy, port 80 from the proxy only. Everything else inbound is blocked. Say no if your cloud provider or
another tool already manages the firewall.

**Step 4 — fail2ban.** Default yes. Blocks addresses after repeated failed SSH logins. (Sentinel's own sign-in has
its own lockout and rate limits.)

**Step 5 — Automatic security updates.** Default yes. Turns on Debian's unattended-upgrades for security fixes.
Sentinel itself is not auto-updated: run `sudo msp-sentinel-update` when you choose.

**Step 6 — Backup encryption.** A passphrase of at least 12 characters, typed twice (hidden). The daily backups are
then encrypted. Leave it empty to keep backups unencrypted. Store the passphrase in your password manager: a lost
passphrase means the backups cannot be restored. You can set or change it later: see [backup.md](backup.md).

**Step 7 — First admin.** User name, full name and email. The password is asked next, on the terminal.

**Summary.** Every answer is shown again. Answer `y` to install, anything else to stop without changing anything.

When it finishes, open `https://<host name>`, sign in, set up two-factor authentication, and copy
`/opt/msp-sentinel/config/config.php` somewhere safe: its `app_key` is needed to restore a backup.

### Development server (follows `develop`)

To try changes before they reach production, run a separate development server that follows the `develop` branch:

```sh
curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/develop/install-dev.sh | sudo -E bash
```

It is the same guided install. The difference is where the code comes from:

| | Production | Development |
|---|---|---|
| Command | `.../main/install.sh` | `.../develop/install-dev.sh` |
| Follows | `main` (merged, released changes) | `develop` (newest changes, before they are released) |
| `sudo msp-sentinel-update` | fetches the newest `main` | fetches the newest `develop` |
| Web interface | the branch and commit under Administration → System | the same, plus a yellow **Development build** badge on every page |

A suggested flow: changes land on `develop`, run `sudo msp-sentinel-update` on the development server and test them,
then merge `develop` into `main` and update production.

Keep the two apart:
- Use a separate server or VM and a separate host name, for example `sentinel-dev.msp.example`.
- Use made-up test clients, or only addresses you would scan from production too: the same written authorisation
  rules apply.
- A development server has its own database and app key. Don't restore a production backup onto it unless you mean
  to copy client data there.

Any branch other than `main` counts as a development build (a fork whose production branch has another name shows
the badge too). Running the other branch's command on an installed server does not switch it quietly: it asks you to
type the new branch name, or needs `SENTINEL_SWITCH_BRANCH=1` when unattended. To stay on the current branch, use
`sudo msp-sentinel-update`.

`SENTINEL_BRANCH` picks another branch, for example a feature branch to test before it is merged. An on-premises agent
can follow `develop` the same way: `curl ... | sudo -E SENTINEL_BRANCH=develop bash` with `.../develop/install-agent.sh`.

### Unattended install

For cloud-init or scripts, give the answers as environment variables; any step with a variable set is not asked:

```sh
curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install.sh | sudo -E \
  SENTINEL_DOMAIN=sentinel.msp.example SENTINEL_TLS=letsencrypt SENTINEL_LE_EMAIL=ops@msp.example \
  SENTINEL_ADMIN_USER=jdoe SENTINEL_ADMIN_NAME="Jane Doe" SENTINEL_ADMIN_EMAIL=jdoe@msp.example bash
```

| Variable | Meaning |
|---|---|
| `SENTINEL_DOMAIN` | Host name users browse to |
| `SENTINEL_TLS` | `letsencrypt`, `selfsigned` (default) or `proxy` |
| `SENTINEL_LE_EMAIL` | Let's Encrypt expiry notices (with `letsencrypt`) |
| `SENTINEL_PROXY_IP` | The reverse proxy's IP address (with `proxy`) |
| `SENTINEL_FIREWALL` | `y` (default) or `n` |
| `SENTINEL_FAIL2BAN` | `y` (default) or `n` |
| `SENTINEL_AUTO_UPDATES` | `y` (default) or `n` |
| `SENTINEL_WEB_UPDATE` | `y` (default) or `n`: **Update now** in Administration → System (see [upgrade.md](upgrade.md#from-the-web-interface)) |
| `SENTINEL_BACKUP_PASSPHRASE` | Backup encryption passphrase, at least 12 characters (empty: unencrypted) |
| `SENTINEL_ADMIN_USER`, `SENTINEL_ADMIN_NAME`, `SENTINEL_ADMIN_EMAIL` | First admin; without a terminal a random password is printed once |
| `SENTINEL_BRANCH` | Branch to install and update from (default `main`; `install-dev.sh` defaults to `develop`) |
| `SENTINEL_REPO` | `owner/name` of a fork |
| `SENTINEL_SWITCH_BRANCH=1` | Allow switching an installed server to another branch without asking |
| `SENTINEL_FORCE=1` | Skip the operating system check |
| `SENTINEL_DRY_RUN=1` | Show every step without changing anything |

Pass the backup passphrase from a secret store, not typed on a shared command line, so it does not end up in shell
history.

The one-line install follows the branch, not a signed release. For signed releases, use the steps below.

## Install with the installer

1. Download the release and check it:

   ```sh
   V=1.9.0   # the release you are installing (see the Releases page)
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

   Or behind a reverse proxy that ends HTTPS (see step 2 above for the proxy settings):

   ```sh
   sudo ./install/install.sh --domain sentinel.msp.example --tls proxy --proxy-ip 192.0.2.10
   ```

   Other options: `--no-firewall`, `--no-fail2ban`, `--no-auto-updates`, `--no-web-update`. For encrypted backups, set
   `SENTINEL_BACKUP_PASSPHRASE` in the environment (`sudo -E`). `./install/install.sh --help` lists them all.

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
| Nginx site (HTTP redirects to HTTPS; proxy mode: HTTP from the proxy only) | `/etc/nginx/sites-available/msp-sentinel` |
| Cron jobs: worker every minute, feeds daily, discovery weekly, backup daily | `/etc/cron.d/msp-sentinel` |
| Logs (rotated weekly) | `/var/log/msp-sentinel/` |
| Daily backups (keep 14; encrypted if a passphrase was set) | `/var/backups/msp-sentinel/`, settings in `/etc/msp-sentinel/backup.env` |
| Update now from the web interface (one-line installs; unless turned off) | `msp-sentinel-web-update.path`, `/usr/local/sbin/msp-sentinel-update-runner`, `/var/lib/msp-sentinel-update/` |
| Firewall, fail2ban, automatic security updates (unless turned off) | `ufw`, `/etc/fail2ban/jail.d/msp-sentinel.local`, `/etc/apt/apt.conf.d/20auto-upgrades` |

Re-running the installer with the same version is safe: it keeps the config, database and app key and re-applies
the rest. To change the HTTPS mode later, run it again from the source folder with the new option, for example
`sudo /opt/msp-sentinel-src/install/install.sh --domain sentinel.msp.example --tls proxy --proxy-ip 192.0.2.10`
(the one-line command only upgrades an installed server). A re-run sets the trusted proxy, replaces the
firewall's web rules, and turns the firewall, fail2ban and automatic updates on again unless you pass `--no-firewall`,
`--no-fail2ban` or `--no-auto-updates`. A re-run with a new backup passphrase replaces the old one: keep the old
passphrase for older backups. On hosts with IPv6 turned off, the Nginx site listens on IPv4 only.

Then check everything with `sudo -u sentinel php8.4 /opt/msp-sentinel/bin/doctor.php`, or under
**Administration → System**.

## After installing

1. **Settings → Alerts:** set up email (SMTP) and, if you like, a Teams or Slack webhook. Use the test buttons.
2. **Settings → Report branding:** your company name, logo, colour and contact details.
3. **Users:** add your technicians (role *technician*) and anyone who only needs to read (role *viewer*).
4. **Clients:** add a client, record the scan authorisation with the approved addresses, and run a first scan.
5. Optionally, get a free **NVD API key** and set `nvd.api_key` in the config: vulnerability lookups get about ten
   times faster.
6. If you skipped it during install, encrypt the daily backups: see [backup.md](backup.md).
7. To look around first, load **demo data** under **Administration → System** (see
   [operations.md](operations.md#demo-data)). Remove it before adding real clients, or keep it on a dev server.

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
