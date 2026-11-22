#!/usr/bin/env bash
# MSP Sentinel installer and upgrader for Ubuntu 24.04 LTS and Debian 12 (Nginx, PHP-FPM 8.4, MariaDB).
#
# Install (from the unpacked release folder):
#   sudo ./install/install.sh --domain sentinel.msp.example [--certbot --email admin@msp.example]
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
dry=0
skip_os=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="${2:-}"; shift 2 ;;
    --email) email="${2:-}"; shift 2 ;;
    --certbot) certbot=1; shift ;;
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
}
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
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
  sed -e "s#__DOMAIN__#${domain}#g" -e "s#__ROOT__#${APP_DIR}#g" -e "s#__PHP__#${PHP_BIN}#g" -e "s#__CERT__#${cert:-}#g" -e "s#__KEY__#${key:-}#g" "$SRC/install/templates/$1" | $ipv6
}

[ -f "$SRC/VERSION" ] && [ -f "$SRC/public/index.php" ] || die "Run this from an unpacked MSP Sentinel release."
new_version="$(tr -d '[:space:]' < "$SRC/VERSION")"
if [ "$dry" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then die "Run as root (sudo)."; fi

if [ "$skip_os" -eq 0 ]; then
  [ -r /etc/os-release ] || die "Cannot detect the operating system."
  . /etc/os-release
  case "${ID:-}-${VERSION_ID:-}" in
    ubuntu-24.04|debian-12) ;;
    *) die "Supported: Ubuntu 24.04 and Debian 12 (found ${PRETTY_NAME:-unknown}). Use --skip-os-check at your own risk." ;;
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
if [ "$certbot" -eq 1 ]; then
  [[ "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "--certbot needs --email (for Let's Encrypt expiry notices)."
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
if [ "${ID:-ubuntu}" = debian ]; then
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

say "System user and folders"
if ! id sentinel >/dev/null 2>&1; then
  run useradd --system --home-dir "$APP_DIR" --no-create-home --shell /usr/sbin/nologin sentinel
fi
run install -d -o root -g sentinel -m 0750 "$APP_DIR"
run rsync -a --exclude '/config/config.php*' --exclude /storage/ --exclude /dist/ "$SRC/" "$APP_DIR/"
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
elif [ "$dry" -eq 1 ]; then
  echo "  [dry-run] php bin/setup-config.php --public-url=https://$domain --db-host=localhost (password on stdin)"
else
  printf '%s\n' "$db_pass" | "$PHP_BIN" "$APP_DIR/bin/setup-config.php" --public-url="https://$domain" --db-host=localhost --db-name="$DB_NAME" --db-user="$DB_USER"
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

say "Nginx and HTTPS"
cert="/etc/ssl/msp-sentinel/selfsigned.crt"
key="/etc/ssl/msp-sentinel/selfsigned.key"
run install -d -m 0700 /etc/ssl/msp-sentinel
if [ "$dry" -eq 1 ] || [ ! -f "$cert" ]; then
  run openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" -keyout "$key" -out "$cert"
fi
render nginx.conf | write_file /etc/nginx/sites-available/msp-sentinel 0644
run ln -sf /etc/nginx/sites-available/msp-sentinel /etc/nginx/sites-enabled/msp-sentinel
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
else
  echo "  Using a self-signed certificate. For a trusted one, re-run this installer with --domain $domain --certbot --email you@msp.example, or install your own."
fi

say "First admin"
if [ "$existing" -eq 0 ] && [ "$dry" -eq 0 ] && [ -t 0 ]; then
  read -r -p "Admin user name: " admin_user
  read -r -p "Admin display name: " admin_name
  read -r -p "Admin email: " admin_email
  runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/create-admin.php" --username="$admin_user" --name="$admin_name" --email="$admin_email"
else
  echo "  Create it later: sudo -u sentinel $PHP_BIN $APP_DIR/bin/create-admin.php --username=jdoe --name=\"Jane Doe\" --email=jdoe@msp.example"
fi

say "Health check"
run runuser -u sentinel -- "$PHP_BIN" "$APP_DIR/bin/doctor.php" || true

say "Done. Open https://$domain and sign in; you will be asked to set up two-factor authentication."
echo "Back up $APP_DIR/config/config.php somewhere safe: its app key is needed to restore."
