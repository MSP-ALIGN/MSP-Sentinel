#!/usr/bin/env bash
# MSP Sentinel installer and upgrader for Debian 13 (also Debian 12 and Ubuntu 24.04 LTS): Nginx, PHP-FPM 8.4, MariaDB.
#
# One-line install from GitHub (runs this script for you): see install.sh at the top of the repository.
#
# Install (from the unpacked release folder; the one-line install.sh at the top asks for all of this step by step):
#   sudo ./install/install.sh --domain sentinel.msp.example [--tls letsencrypt --email admin@msp.example]
#   sudo ./install/install.sh --domain sentinel.msp.example --tls proxy --proxy-ip 192.0.2.10
#   Options: --tls letsencrypt|selfsigned|proxy (default selfsigned; --certbot is the same as --tls letsencrypt),
#   --proxy-ip IP, --no-firewall, --no-fail2ban, --no-auto-updates, --no-web-update. A backup passphrase can be given in the
#   environment variable SENTINEL_BACKUP_PASSPHRASE (never on the command line).
# Upgrade (from the NEW release folder):
#   sudo ./install/install.sh --upgrade
# See what it would do, without changing anything:
#   ./install/install.sh --dry-run --domain sentinel.msp.example
#
# What it does (install): installs packages, creates the "sentinel" system user,
# copies the app to /opt/msp-sentinel, creates the database and a random
# database password, writes config/config.php with a fresh app key, runs the
# migrations, sets up a dedicated PHP-FPM pool, the Nginx site (HTTPS with a
# Let's Encrypt or self-signed certificate), cron jobs and log rotation, asks
# for the first admin, and runs the health check.
#
# Upgrade: backs up first, replaces the code (config and storage are kept),
# runs the migrations, reloads PHP-FPM and runs the health check.
#
# Security notes:
# - Code is owned by root and only readable by the app (root:sentinel, 0640);
#   only storage/ and the log folder are writable. The scan worker runs as
#   "sentinel", never root; PHP-FPM runs as www-data with group "sentinel".
#   Only public/assets (CSS, JS, fonts) is world-readable, so Nginx can serve it.
# - Safe to re-run: an existing config and database are kept (for example to
#   add --certbot later). Upgrades stop the worker cron while code changes.
# - The database password is generated, passed to MariaDB and to the config
#   writer on stdin, and never printed or put on a command line.
# - It refuses to overwrite an existing install (use --upgrade) or to downgrade.
set -euo pipefail

APP_DIR=/opt/msp-sentinel
DB_NAME=msp_sentinel
DB_USER=msp_sentinel
PHPV=8.4
PHP_BIN="php${PHPV}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

mode=install
domain=""
email=""
certbot=0
tls=selfsigned
proxy_ip=""
firewall=1
web_update=1
fail2ban=1
auto_updates=1
dry=0
# The backup passphrase is taken out of the environment at once, so no child process (migrations, PHP jobs) inherits it.
backup_pass="${SENTINEL_BACKUP_PASSPHRASE:-}"
unset SENTINEL_BACKUP_PASSPHRASE
skip_os=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="${2:-}"; shift 2 ;;
    --email) email="${2:-}"; shift 2 ;;
    --certbot) certbot=1; tls=letsencrypt; shift ;;
    --tls) tls="${2:-}"; shift 2 ;;
    --proxy-ip) proxy_ip="${2:-}"; shift 2 ;;
    --no-firewall) firewall=0; shift ;;
    --no-fail2ban) fail2ban=0; shift ;;
    --no-auto-updates) auto_updates=0; shift ;;
    --no-web-update) web_update=0; shift ;;
    --upgrade) mode=upgrade; shift ;;
    --dry-run) dry=1; shift ;;
    --skip-os-check) skip_os=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
# Ownership and modes for the code (storage/ is left alone: it is shared, setgid, group-writable).
fix_permissions() {
  run find "$APP_DIR" -path "$APP_DIR/storage" -prune -o -exec chown root:sentinel {} +
  run find "$APP_DIR" -path "$APP_DIR/storage" -prune -o -type d -exec chmod 0750 {} +
  run find "$APP_DIR" -path "$APP_DIR/storage" -prune -o -type f -exec chmod 0640 {} +
  run chmod 0750 "$APP_DIR/install/install.sh"
  # Nginx (www-data, not in the sentinel group) serves static files directly: let it traverse to public/assets.
  run chmod o+x "$APP_DIR" "$APP_DIR/public"
  run chmod -R o+rX "$APP_DIR/public/assets"
}
# Pool, cron and log rotation from the templates (re-applied on upgrades; no domain needed).
write_service_files() {
  render php-fpm-pool.conf | write_file "/etc/php/${PHPV}/fpm/pool.d/msp-sentinel.conf" 0644
  render cron | write_file /etc/cron.d/msp-sentinel 0644
  render logrotate | write_file /etc/logrotate.d/msp-sentinel 0644
  write_web_update
}
# "Update now" in the web interface: a root-owned runner started by a systemd path unit when the web app creates
# storage/update-request (see src/System/WebUpdate.php). Only for installs made with the one-line installer
# (they have msp-sentinel-update). An administrator who turned it off keeps it off across upgrades.
write_web_update() {
  local state=/var/lib/msp-sentinel-update
  [ -f /etc/msp-sentinel/update.env ] || [ "$dry" -eq 1 ] || return 0
  if [ "$web_update" -eq 0 ]; then
    run rm -f "$state/enabled"
    if [ "$dry" -eq 1 ]; then echo "  [dry-run] systemctl disable --now msp-sentinel-web-update.path"; else systemctl disable --now msp-sentinel-web-update.path >/dev/null 2>&1 || true; fi
    return 0
  fi
  if [ -d "$state" ] && [ ! -f "$state/enabled" ]; then
    echo "  Updating from the web interface stays off on this server (it was turned off)."
    return 0
  fi
  run install -d -o root -g sentinel -m 0750 "$state"
  render msp-sentinel-update-runner | write_file /usr/local/sbin/msp-sentinel-update-runner 0755
  render msp-sentinel-web-update.path | write_file /etc/systemd/system/msp-sentinel-web-update.path 0644
  render msp-sentinel-web-update.service | write_file /etc/systemd/system/msp-sentinel-web-update.service 0644
  run install -m 0644 /dev/null "$state/enabled"
  run systemctl daemon-reload
  # Optional feature: a problem here is reported, never allowed to stop an install or upgrade.
  if [ "$dry" -eq 1 ]; then
    echo "  [dry-run] systemctl reset-failed + enable --now msp-sentinel-web-update.path"
  else
    systemctl reset-failed msp-sentinel-web-update.path >/dev/null 2>&1 || true
    systemctl enable --now msp-sentinel-web-update.path >/dev/null 2>&1 \
      || echo "  Warning: could not start msp-sentinel-web-update.path (Update now in the web interface). Check: systemctl status msp-sentinel-web-update.path"
  fi
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
# valid_ip ADDR: one IPv4 address (each part 0-255) or an IPv6 address (hex groups and colons only).
valid_ip() {
  local a="$1" o g n=0
  if [[ "$a" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    # No leading zeros (some tools read 010 as octal) and each part 0-255.
    for o in "${BASH_REMATCH[@]:1}"; do [[ "$o" =~ ^(0|[1-9][0-9]*)$ ]] && [ "$o" -le 255 ] || return 1; done; return 0
  fi
  # IPv6: groups of 1-4 hex digits, at most one "::", eight groups without "::" or fewer with it.
  [[ "$a" =~ ^[0-9A-Fa-f:]{2,39}$ ]] || return 1
  case "$a" in *:::*) return 1 ;; esac
  [ "$(grep -o '::' <<<"$a" | wc -l)" -le 1 ] || return 1
  local IFS=:
  for g in $a; do [ -z "$g" ] && continue; [ "${#g}" -le 4 ] || return 1; n=$((n + 1)); done
  if [[ "$a" == *::* ]]; then [ "$n" -le 7 ]; else [ "$n" -eq 8 ] && [[ "$a" != :* && "$a" != *: ]]; fi
}
# Older msp-sentinel-update commands wrote the build stamp without the repository: add it from update.env
# (checked as owner/name) so the web interface can tell how far behind its branch this server is.
stamp_repo() {
  [ "$dry" -eq 0 ] && [ -f "$SRC/BUILD" ] && [ -f /etc/msp-sentinel/update.env ] || return 0
  grep -q '^repo=' "$SRC/BUILD" && return 0
  local r; r="$(sed -n 's/^SENTINEL_REPO=\([A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]*\)$/\1/p' /etc/msp-sentinel/update.env | head -1)"
  [ -n "$r" ] && printf 'repo=%s\n' "$r" >> "$SRC/BUILD"
  return 0
}
# Run a command, or only show it in a dry run.
run() {
  if [ "$dry" -eq 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}
# Write stdin to a file (shown, not written, in a dry run).
write_file() {
  local path="$1" mode="$2"
  if [ "$dry" -eq 1 ]; then printf '  [dry-run] write %s (mode %s)\n' "$path" "$mode"; cat > /dev/null; return; fi
  ( umask 077; cat > "$path.tmp" )
  chmod "$mode" "$path.tmp"
  mv -f "$path.tmp" "$path"
}
# Fill a template: placeholders are replaced with values the script validated.
render() {
  local ipv6='cat'
  # Hosts with IPv6 turned off can't bind [::]; drop those listen lines there.
  [ -f /proc/net/if_inet6 ] || ipv6="grep -v \[::\]"
  sed -e "s#__DOMAIN__#${domain}#g" -e "s#__ROOT__#${APP_DIR}#g" -e "s#__PHP__#${PHP_BIN}#g" -e "s#__CERT__#${cert:-}#g" -e "s#__KEY__#${key:-}#g" -e "s#__PROXY__#${proxy_ip:-}#g" "$SRC/install/templates/$1" | $ipv6
}

[ -f "$SRC/VERSION" ] && [ -f "$SRC/public/index.php" ] || die "Run this from an unpacked MSP Sentinel release."
new_version="$(tr -d '[:space:]' < "$SRC/VERSION")"
if [ "$dry" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then die "Run as root (sudo)."; fi

if [ "$skip_os" -eq 0 ]; then
  [ -r /etc/os-release ] || die "Cannot detect the operating system."
  . /etc/os-release
  case "${ID:-}-${VERSION_ID:-}" in
    debian-13|debian-12|ubuntu-24.04) ;;
    *) die "Supported: Debian 13 (recommended), Debian 12 and Ubuntu 24.04 (found ${PRETTY_NAME:-unknown}). Use --skip-os-check at your own risk." ;;
  esac
fi

# ---------------------------------------------------------------- upgrade
if [ "$mode" = upgrade ]; then
  [ -f "$APP_DIR/VERSION" ] && [ -f "$APP_DIR/config/config.php" ] || [ "$dry" -eq 1 ] || die "No install found in $APP_DIR."
  old_version="$( { cat "$APP_DIR/VERSION" 2>/dev/null || true; } | tr -d '[:space:]')"; old_version="${old_version:-0.0.0}"
  if [ "$(printf '%s\n%s\n' "$old_version" "$new_version" | sort -V | tail -1)" != "$new_version" ]; then
    die "Refusing to downgrade from $old_version to $new_version."
  fi
  say "Upgrading $old_version -> $new_version"
  say "Stopping the scheduled jobs while the code changes"
  run mv -f /etc/cron.d/msp-sentinel /etc/msp-sentinel/cron.paused
  # Put the jobs back whatever happens below.
  trap '[ -f /etc/msp-sentinel/cron.paused ] && mv -f /etc/msp-sentinel/cron.paused /etc/cron.d/msp-sentinel || true' EXIT
  if [ "$dry" -eq 0 ]; then
    waited=0
    while pgrep -u sentinel -f "$APP_DIR/bin/(worker|feeds|discover|backup).php" >/dev/null; do
      [ "$waited" -ge 3600 ] && die "A Sentinel job is still running after an hour. Pause scanning in the web interface, then run the upgrade again."
      [ "$waited" -eq 0 ] && echo "  Waiting for a running job (for example a scan) to finish..."
      sleep 10; waited=$((waited + 10))
    done
  fi
  say "Backing up first"
  run install -d -o sentinel -g sentinel -m 0700 /var/backups/msp-sentinel
  run runuser -u sentinel -- sh -c '[ -f /etc/msp-sentinel/backup.env ] && . /etc/msp-sentinel/backup.env; exec "$0" "$1"/bin/backup.php --dir=/var/backups/msp-sentinel --keep=14 ${SENTINEL_BACKUP_ENCRYPT:+--encrypt}' "$PHP_BIN" "$APP_DIR"
  say "Replacing the code (config and storage are kept)"
stamp_repo
  run rsync -a --delete --exclude '/config/config.php*' --exclude /storage/ --exclude /dist/ "$SRC/" "$APP_DIR/"
  fix_permissions
  say "Database migrations"
  run runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/migrate.php"
  say "Service files (PHP-FPM pool, cron, log rotation)"
  write_service_files
  run rm -f /etc/msp-sentinel/cron.paused   # the new cron file was just written
  run systemctl reload "php${PHPV}-fpm"
  say "Health check"
  run runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/doctor.php" || true
  say "Upgrade to $new_version finished."
  exit 0
fi

# ---------------------------------------------------------------- install
[[ "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "--domain must be a host name such as sentinel.msp.example (lower case)."
case "$tls" in letsencrypt) certbot=1 ;; selfsigned|proxy) certbot=0 ;; *) die "--tls must be letsencrypt, selfsigned or proxy." ;; esac
if [ "$certbot" -eq 1 ]; then
  [[ "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "--tls letsencrypt needs --email (for Let's Encrypt expiry notices)."
fi
if [ "$tls" = proxy ]; then
  # One plain IP address (it goes into the Nginx allow rule, the firewall and the config): checked strictly here.
  valid_ip "$proxy_ip" || die "--tls proxy needs --proxy-ip with the reverse proxy's IP address (one address)."
fi
existing=0
if [ -f "$APP_DIR/config/config.php" ]; then
  existing=1
  installed_version="$( { cat "$APP_DIR/VERSION" 2>/dev/null || true; } | tr -d '[:space:]')"
  [ "$installed_version" = "$new_version" ] || die "$APP_DIR has version ${installed_version:-unknown}. Use --upgrade to change versions."
  echo "  Existing install of the same version found: keeping its config and database, re-applying the rest."
fi
say "Installing MSP Sentinel $new_version for https://$domain"

say "Packages"
run apt-get update
run apt-get install -y ca-certificates curl gnupg lsb-release rsync nmap nginx mariadb-server mariadb-client openssl
if [ "${ID:-}-${VERSION_ID:-}" = debian-13 ]; then
  : # Debian 13 ships PHP 8.4 itself: no extra package source needed.
elif [ "${ID:-ubuntu}" = debian ]; then
  # PHP 8.4 from packages.sury.org (Debian 12 ships 8.2).
  run install -d -m 0755 /etc/apt/keyrings
  run curl -fsSL https://packages.sury.org/php/apt.gpg -o /etc/apt/keyrings/sury-php.gpg
  echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ $(. /etc/os-release && echo "$VERSION_CODENAME") main" | write_file /etc/apt/sources.list.d/sury-php.list 0644
else
  # PHP 8.4 from the ondrej/php PPA (Ubuntu 24.04 ships 8.3).
  run apt-get install -y software-properties-common
  run add-apt-repository -y ppa:ondrej/php
fi
run apt-get update
run apt-get install -y "php${PHPV}-fpm" "php${PHPV}-cli" "php${PHPV}-mysql" "php${PHPV}-mbstring" "php${PHPV}-curl" "php${PHPV}-xml" "php${PHPV}-gd"
if [ "$certbot" -eq 1 ]; then run apt-get install -y certbot; fi
extra=()
[ "$firewall" -eq 1 ] && extra+=(ufw)
[ "$fail2ban" -eq 1 ] && extra+=(fail2ban)
[ "$auto_updates" -eq 1 ] && extra+=(unattended-upgrades)
if [ "${#extra[@]}" -gt 0 ]; then run apt-get install -y "${extra[@]}"; fi

say "System user and folders"
if ! id sentinel >/dev/null 2>&1; then
  run useradd --system --home-dir "$APP_DIR" --no-create-home --shell /usr/sbin/nologin sentinel
fi
run install -d -o root -g sentinel -m 0750 "$APP_DIR"
stamp_repo
run rsync -a --exclude '/config/config.php*' --exclude /storage/ --exclude /dist/ "$SRC/" "$APP_DIR/"
# A release archive has no BUILD stamp: drop one left by an earlier git-based install, so the
# interface never shows a stale branch (or a development badge) for this code.
[ -f "$SRC/BUILD" ] || run rm -f "$APP_DIR/BUILD"
fix_permissions
[ -d "$APP_DIR/storage" ] || run install -d -o sentinel -g sentinel -m 2770 "$APP_DIR/storage"
run install -d -o sentinel -g sentinel -m 2770 /var/log/msp-sentinel
run install -d -o sentinel -g sentinel -m 0700 /var/backups/msp-sentinel
run install -d -o root -g sentinel -m 0750 /etc/msp-sentinel
run install -d -m 0755 /var/www/letsencrypt

say "Database"
db_pass="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-32)"
if [ "$existing" -eq 1 ]; then
  echo "  Kept the existing database and its password."
elif [ "$dry" -eq 1 ]; then
  echo "  [dry-run] create database $DB_NAME and user $DB_USER@localhost (password generated, sent on stdin)"
else
  systemctl enable --now mariadb
  mariadb <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$db_pass';
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$db_pass';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL
fi

say "Configuration"
if [ "$existing" -eq 1 ]; then
  echo "  Kept $APP_DIR/config/config.php."
  if [ -n "$proxy_ip" ]; then
    # Switching to (or re-running) proxy mode: without this the proxy's address would count as every user's.
    run "$PHP_BIN" "$APP_DIR/bin/setup-config.php" --update --trusted-proxy="$proxy_ip"
    run chown root:sentinel "$APP_DIR/config/config.php"
  fi
elif [ "$dry" -eq 1 ]; then
  echo "  [dry-run] php bin/setup-config.php --public-url=https://$domain --db-host=localhost${proxy_ip:+ --trusted-proxy=$proxy_ip} (password on stdin)"
else
  printf '%s\n' "$db_pass" | "$PHP_BIN" "$APP_DIR/bin/setup-config.php" --public-url="https://$domain" --db-host=localhost --db-name="$DB_NAME" --db-user="$DB_USER" ${proxy_ip:+--trusted-proxy="$proxy_ip"}
  chown root:sentinel "$APP_DIR/config/config.php"
  chmod 0640 "$APP_DIR/config/config.php"
fi
unset db_pass

say "Database migrations"
run runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/migrate.php"

say "PHP-FPM pool, cron jobs and log rotation"
write_service_files
run systemctl enable --now "php${PHPV}-fpm"
run systemctl restart "php${PHPV}-fpm"

if [ "$tls" = proxy ]; then
  say "Nginx behind the reverse proxy ($proxy_ip)"
  render nginx-proxy.conf | write_file /etc/nginx/sites-available/msp-sentinel 0644
  run ln -sf /etc/nginx/sites-available/msp-sentinel /etc/nginx/sites-enabled/msp-sentinel
  run rm -f /etc/nginx/sites-enabled/default
  run nginx -t
  run systemctl reload nginx
  echo "  Point the proxy at http://<this server>:80 for https://$domain. It must pass the Host header and send"
  echo "  X-Forwarded-For and X-Forwarded-Proto: https. Only $proxy_ip may connect."
else
say "Nginx and HTTPS"
cert="/etc/ssl/msp-sentinel/selfsigned.crt"
key="/etc/ssl/msp-sentinel/selfsigned.key"
run install -d -m 0700 /etc/ssl/msp-sentinel
if [ "$dry" -eq 1 ] || [ ! -f "$cert" ]; then
  run openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" -keyout "$key" -out "$cert"
fi
render nginx.conf | write_file /etc/nginx/sites-available/msp-sentinel 0644
run ln -sf /etc/nginx/sites-available/msp-sentinel /etc/nginx/sites-enabled/msp-sentinel
run rm -f /etc/nginx/sites-enabled/default
run nginx -t
run systemctl reload nginx
if [ "$certbot" -eq 1 ]; then
  run certbot certonly --webroot -w /var/www/letsencrypt -d "$domain" --email "$email" --agree-tos --non-interactive \
      --deploy-hook "systemctl reload nginx"
  cert="/etc/letsencrypt/live/$domain/fullchain.pem"
  key="/etc/letsencrypt/live/$domain/privkey.pem"
  render nginx.conf | write_file /etc/nginx/sites-available/msp-sentinel 0644
  run nginx -t
  run systemctl reload nginx
  echo "  Let's Encrypt certificate installed; it renews automatically (certbot's timer)."
else
  echo "  Using a self-signed certificate. For a trusted one, re-run this installer with --tls letsencrypt --email you@msp.example, or install your own."
fi
fi

if [ "$firewall" -eq 1 ]; then
  say "Firewall (ufw)"
  # Every port sshd listens on (it may have several Port lines); 22 if sshd can't tell us.
  ssh_ports="$( { sshd -T 2>/dev/null || true; } | awk '/^port [0-9]+$/{print $2}' | sort -un | tr '\n' ' ')"; ssh_ports="${ssh_ports:-22}"
  run ufw default deny incoming
  run ufw default allow outgoing
  for p in $ssh_ports; do run ufw limit "${p}/tcp" comment 'SSH (rate-limited)'; done
  # Remove web rules an earlier run added (e.g. 80/443 open to all before switching to proxy mode), newest first.
  if [ "$dry" -eq 0 ]; then
    { ufw status numbered 2>/dev/null || true; } | sed -n 's/^\[ *\([0-9]*\)\].*# \(MSP Sentinel\|HTTP redirect and Lets Encrypt\).*/\1/p' | sort -rn \
      | while read -r n; do ufw --force delete "$n" >/dev/null; done
  else
    echo "  [dry-run] remove earlier MSP Sentinel web rules from ufw"
  fi
  if [ "$tls" = proxy ]; then
    run ufw allow from "$proxy_ip" to any port 80 proto tcp comment 'MSP Sentinel via reverse proxy'
  else
    run ufw allow 80/tcp comment 'MSP Sentinel HTTP redirect and Lets Encrypt'
    run ufw allow 443/tcp comment 'MSP Sentinel HTTPS'
  fi
  run ufw --force enable
fi

if [ "$fail2ban" -eq 1 ]; then
  say "fail2ban (SSH sign-in protection)"
  # Debian 13 logs to the journal (no /var/log/auth.log), so the systemd backend is used.
  f2b_ports="$( { sshd -T 2>/dev/null || true; } | awk '/^port [0-9]+$/{print $2}' | sort -un | paste -sd, -)"
  printf '%s\n' '# Written by the MSP Sentinel installer. Web sign-ins are throttled by Sentinel itself.' '[sshd]' 'enabled = true' 'backend = systemd' \
    "port = ${f2b_ports:-ssh}" 'maxretry = 5' 'findtime = 10m' 'bantime = 1h' | write_file /etc/fail2ban/jail.d/msp-sentinel.local 0644
  run systemctl enable fail2ban
  run systemctl restart fail2ban
fi

if [ "$auto_updates" -eq 1 ]; then
  say "Automatic security updates"
  printf '%s\n' 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' | write_file /etc/apt/apt.conf.d/20auto-upgrades 0644
  run systemctl enable --now unattended-upgrades
fi

# An existing passphrase file from before 1.34 (0640 root:sentinel) was readable by the PHP-FPM pool: owner-only now.
if [ -f /etc/msp-sentinel/backup.env ] && [ "$dry" -ne 1 ]; then
  chown sentinel:sentinel /etc/msp-sentinel/backup.env && chmod 0600 /etc/msp-sentinel/backup.env
fi

if [ -n "$backup_pass" ]; then
  say "Encrypted backups"
  if [ -f /etc/msp-sentinel/backup.env ]; then
    echo "  Note: replacing the existing backup passphrase. Older backups still need the OLD passphrase: keep it."
  fi
  if [ "$dry" -eq 1 ]; then
    echo "  [dry-run] write /etc/msp-sentinel/backup.env (mode 0600, sentinel:sentinel) with the passphrase"
  else
    # POSIX single quotes (each ' becomes '\''), because the cron job sources this file with sh (dash), which
    # does not understand bash's $'...' quoting. Readable by root and the backup job (user sentinel) only: not by the
    # PHP-FPM pool, which shares the sentinel group (1.34 audit). Never printed.
    q="'$(printf '%s' "$backup_pass" | sed "s/'/'\\\\''/g")'"
    ( umask 077  # owner-only from the moment it exists
      { echo '# Written by the MSP Sentinel installer: nightly backups are encrypted with this passphrase. Keep a copy in your vault.'
        echo 'export SENTINEL_BACKUP_ENCRYPT=1'
        printf 'export SENTINEL_BACKUP_PASSPHRASE=%s\n' "$q"; } > /etc/msp-sentinel/backup.env.tmp )
    unset q
    chmod 0600 /etc/msp-sentinel/backup.env.tmp
    # Self-test: the file must give back exactly this passphrase under sh (through the environment, not argv). Run
    # while root still owns the file: root never sources a file the sentinel user could have changed (1.34 review).
    SENTINEL_PP_EXPECT="$backup_pass" sh -c '. /etc/msp-sentinel/backup.env.tmp; [ "$SENTINEL_BACKUP_PASSPHRASE" = "$SENTINEL_PP_EXPECT" ]' \
      || { rm -f /etc/msp-sentinel/backup.env.tmp; die "Could not store the backup passphrase safely; backups were left unencrypted."; }
    chown sentinel:sentinel /etc/msp-sentinel/backup.env.tmp
    mv -f /etc/msp-sentinel/backup.env.tmp /etc/msp-sentinel/backup.env
    echo "  Nightly backups will be encrypted. Keep the passphrase in your password vault: without it they can't be restored."
  fi
fi

say "First admin"
# Questions go to the terminal (/dev/tty), so this also works when the script itself arrives on stdin (curl | bash).
# Unattended: set SENTINEL_ADMIN_USER, SENTINEL_ADMIN_NAME and SENTINEL_ADMIN_EMAIL; a random password is then printed once.
have_tty() { [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null || return 1; }
admin_user="${SENTINEL_ADMIN_USER:-}"; admin_name="${SENTINEL_ADMIN_NAME:-}"; admin_email="${SENTINEL_ADMIN_EMAIL:-}"
if [ "$existing" -eq 1 ] || [ "$dry" -eq 1 ]; then
  echo "  Skipped (existing install or dry run)."
elif have_tty; then
  [ -n "$admin_user" ] || read -r -p "Admin user name: " admin_user </dev/tty
  [ -n "$admin_name" ] || read -r -p "Admin display name: " admin_name </dev/tty
  [ -n "$admin_email" ] || read -r -p "Admin email: " admin_email </dev/tty
  runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/create-admin.php" --username="$admin_user" --name="$admin_name" --email="$admin_email" </dev/tty
elif [ -n "$admin_user" ] && [ -n "$admin_name" ] && [ -n "$admin_email" ]; then
  admin_pass="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-20)Aa1!"
  printf '%s\n' "$admin_pass" | runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/create-admin.php" --username="$admin_user" --name="$admin_name" --email="$admin_email"
  echo "  Admin $admin_user created. Password (shown once, change it after signing in): $admin_pass"
  unset admin_pass
else
  echo "  Create it later: sudo -u sentinel $PHP_BIN $APP_DIR/bin/create-admin.php --username=jdoe --name=\"Jane Doe\" --email=jdoe@msp.example"
fi

say "Health check"
run runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/doctor.php" || true

say "Done. Open https://$domain and sign in; you will be asked to set up two-factor authentication."
echo "Back up $APP_DIR/config/config.php somewhere safe: its app key is needed to restore."
