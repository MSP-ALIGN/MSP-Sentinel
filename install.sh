#!/usr/bin/env bash
# =============================================================================
#  MSP Sentinel - one-line installer / upgrader for Debian 13 (trixie)
#  (Debian 12 and Ubuntu 24.04 LTS also work)
#
#  Fresh install, on a new Debian 13 VM (a minimal Debian may need `apt install -y curl sudo` first, as root):
#    curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install.sh | sudo -E bash
#
#  Development server (follows the develop branch: newest changes, before they reach main and a release):
#    curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/develop/install-dev.sh | sudo -E bash
#
#  Upgrade an existing install (stays on the branch it was installed from):
#    sudo msp-sentinel-update
#
#  With a terminal it runs a 7-step wizard (host name, HTTPS, firewall, SSH protection, security updates,
#  backups, first admin) and shows a summary to confirm before changing anything.
#
#  Unattended install: set any of these to skip the matching question
#    SENTINEL_DOMAIN       host name users browse to, e.g. sentinel.msp.example
#    SENTINEL_TLS          letsencrypt (public DNS + port 80 open), selfsigned (default) or proxy
#    SENTINEL_LE_EMAIL     Let's Encrypt expiry notices (letsencrypt only)
#    SENTINEL_PROXY_IP     the reverse proxy's IP address (proxy only)
#    SENTINEL_FIREWALL / SENTINEL_FAIL2BAN / SENTINEL_AUTO_UPDATES   1 (default) or 0
#    SENTINEL_BACKUP_PASSPHRASE   encrypt nightly backups (at least 12 characters; empty: unencrypted)
#    SENTINEL_ADMIN_USER / SENTINEL_ADMIN_NAME / SENTINEL_ADMIN_EMAIL   first admin (password printed once)
#    SENTINEL_REPO         owner/name (default MSP-ALIGN/MSP-Sentinel)
#    SENTINEL_BRANCH       branch to install and update from (default main; develop for test servers)
#    SENTINEL_FORCE=1      skip the operating system check
#    SENTINEL_DRY_RUN=1    show what would be done, change nothing (with SENTINEL_SRC: use that folder)
#
#  What it does: installs git, fetches MSP Sentinel from GitHub into /opt/msp-sentinel-src, and runs
#  install/install.sh (Nginx, PHP-FPM 8.4, MariaDB, database, config with a fresh app key, cron jobs,
#  HTTPS, first admin, health check). It also installs `msp-sentinel-update`, which fetches the same
#  branch again and runs the upgrade (backup first).
#
#  Security notes: nothing secret is passed on a command line or printed (except a generated first-admin
#  password in unattended mode, shown once). Answers are checked before use. The source is fetched over
#  HTTPS from the public repository; review this script before piping it to a shell if you prefer.
# =============================================================================
set -Eeuo pipefail
umask 022

REPO="${SENTINEL_REPO:-MSP-ALIGN/MSP-Sentinel}"
BRANCH="${SENTINEL_BRANCH:-main}"
SRC_DIR=/opt/msp-sentinel-src
APP_DIR=/opt/msp-sentinel
DRY="${SENTINEL_DRY_RUN:-0}"

c_ok=$'\e[32m'; c_err=$'\e[31m'; c_0=$'\e[0m'
log() { printf '%s==>%s %s\n' "$c_ok" "$c_0" "$*"; }
die() { printf '%sERROR:%s %s\n' "$c_err" "$c_0" "$*" >&2; exit 1; }
trap 'die "Install stopped at line $LINENO (command: $BASH_COMMAND)"' ERR
run() { if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }
# Questions go to the terminal: under `curl | bash` the script itself is on stdin.
have_tty() { [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null || return 1; }
# ask VAR "Prompt" "default": from the environment if set, else the terminal, else the default (or stop if required).
ask() {
  local __var=$1 prompt=$2 def=${3:-} reply=
  [ -n "${!__var:-}" ] && return
  if ! have_tty; then
    [ -n "$def" ] || die "$__var is required (no terminal available to ask)."
    printf -v "$__var" '%s' "$def"; return
  fi
  read -r -p "$prompt${def:+ [$def]}: " reply </dev/tty
  printf -v "$__var" '%s' "${reply:-$def}"
}

[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "SENTINEL_REPO must be owner/name."
[[ "$BRANCH" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,59}$ && "$BRANCH" != *..* ]] || die "SENTINEL_BRANCH is not a valid branch name."
[ "$DRY" = 1 ] || [ "$(id -u)" -eq 0 ] || die "Run as root: curl -fsSL ... | sudo -E bash"

. /etc/os-release
if [ "${SENTINEL_FORCE:-0}" != 1 ]; then
  case "${ID:-}-${VERSION_ID:-}" in
    debian-13|debian-12|ubuntu-24.04) ;;
    *) die "This installer targets Debian 13 (found: ${PRETTY_NAME:-unknown}). Set SENTINEL_FORCE=1 to try anyway." ;;
  esac
fi

log "Fetching MSP Sentinel ($REPO, branch $BRANCH)"
if [ -n "${SENTINEL_SRC:-}" ] && [ "$DRY" = 1 ]; then
  SRC_DIR="$SENTINEL_SRC"   # dry runs (tests): use an existing checkout, fetch nothing
else
  run apt-get update -qq
  run apt-get install -y -qq git ca-certificates curl rsync
  if [ -d "$SRC_DIR/.git" ]; then
    run git -C "$SRC_DIR" fetch --depth 1 origin "$BRANCH"
    run git -C "$SRC_DIR" reset --hard FETCH_HEAD
  else
    run git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" "$SRC_DIR"
  fi
  # Build stamp (copied into the app): the web interface shows the branch and commit, and marks non-main
  # installs as development builds so nobody mistakes a test server for production.
  if [ "$DRY" = 1 ]; then echo "  [dry-run] write $SRC_DIR/BUILD (branch $BRANCH)"
  else printf 'branch=%s\ncommit=%s\n' "$BRANCH" "$(git -C "$SRC_DIR" rev-parse HEAD)" > "$SRC_DIR/BUILD"; fi
fi
if [ "$BRANCH" != main ]; then
  printf '%sDevelopment build:%s branch %s gets changes before they are released. Use it for a test server, not for client work.\n' "$c_err" "$c_0" "$BRANCH"
fi

install_update_command() {
  # The update command remembers the repository and branch this install follows.
  if [ "$DRY" = 1 ]; then printf '  [dry-run] write /usr/local/sbin/msp-sentinel-update (follows %s, branch %s)\n' "$REPO" "$BRANCH"; return; fi
  install -d -m 0755 /etc/msp-sentinel
  printf 'SENTINEL_REPO=%s\nSENTINEL_BRANCH=%s\n' "$REPO" "$BRANCH" > /etc/msp-sentinel/update.env
  chmod 0644 /etc/msp-sentinel/update.env
  cat > /usr/local/sbin/msp-sentinel-update <<'UPD'
#!/usr/bin/env bash
# Updates MSP Sentinel from the branch it follows (see /etc/msp-sentinel/update.env), then runs the upgrade
# (which backs up first, stops the scheduled jobs while the code changes, migrates and checks health).
set -Eeuo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo msp-sentinel-update)." >&2; exit 1; }
. /etc/msp-sentinel/update.env
[[ "$SENTINEL_BRANCH" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,59}$ && "$SENTINEL_BRANCH" != *..* ]] || { echo "Bad branch in update.env" >&2; exit 1; }
git -C /opt/msp-sentinel-src fetch --depth 1 origin "$SENTINEL_BRANCH"
git -C /opt/msp-sentinel-src reset --hard FETCH_HEAD
printf 'branch=%s\ncommit=%s\n' "$SENTINEL_BRANCH" "$(git -C /opt/msp-sentinel-src rev-parse HEAD)" > /opt/msp-sentinel-src/BUILD
exec bash /opt/msp-sentinel-src/install/install.sh --upgrade
UPD
  chmod 0755 /usr/local/sbin/msp-sentinel-update
}

if [ -f "$APP_DIR/config/config.php" ]; then
  log "Existing install found: upgrading"
  install_update_command
  args=(--upgrade)
  [ "$DRY" = 1 ] && args+=(--dry-run)
  [ "${SENTINEL_FORCE:-0}" = 1 ] && args+=(--skip-os-check)
  exec bash "$SRC_DIR/install/install.sh" "${args[@]}"
fi

# ------------------------------------------------------------------ wizard ----
step() { if have_tty; then printf '\n%s[%s/7] %s%s\n' "$c_ok" "$1" "$2" "$c_0"; fi; }
note() { if have_tty; then printf '      %s\n' "$@"; fi; }
# ask_yes VAR "Question" default(1|0): yes/no, from the environment (y/n, yes/no or 1/0) or the terminal.
ask_yes() {
  local __var=$1 q=$2 def=$3 reply=
  if [ -n "${!__var:-}" ]; then
    case "${!__var,,}" in y|yes|1) printf -v "$__var" 1 ;; n|no|0) printf -v "$__var" 0 ;; *) die "$__var must be y or n." ;; esac
    return
  fi
  if ! have_tty; then printf -v "$__var" '%s' "$def"; return; fi
  read -r -p "      $q [$( [ "$def" = 1 ] && echo Y/n || echo y/N )]: " reply </dev/tty
  case "${reply,,}" in y|yes) printf -v "$__var" 1 ;; n|no) printf -v "$__var" 0 ;; *) printf -v "$__var" '%s' "$def" ;; esac
}
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
if have_tty; then printf '\n%sMSP Sentinel setup%s: seven short steps, then a summary to confirm. Sentinel is only installed once you confirm.\n' "$c_ok" "$c_0"; fi

step 1 "Host name"
note "The name users type in the browser, e.g. sentinel.msp.example. It must point at this server (or at your proxy)."
ask SENTINEL_DOMAIN "      Host name"
SENTINEL_DOMAIN="$(printf '%s' "$SENTINEL_DOMAIN" | tr 'A-Z' 'a-z')"
[[ "$SENTINEL_DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "That is not a host name: $SENTINEL_DOMAIN"

step 2 "HTTPS"
note "1) letsencrypt  - free trusted certificate; needs public DNS for the name and port 80 reachable from the internet" \
     "2) selfsigned   - for internal use; browsers warn until you trust the certificate" \
     "3) proxy        - a reverse proxy (BunkerWeb, Nginx Proxy Manager, Caddy, a load balancer...) handles HTTPS;" \
     "                  Sentinel listens on plain HTTP and only accepts the proxy's address"
if [ -z "${SENTINEL_TLS:-}" ] && have_tty; then
  read -r -p "      Choose 1, 2 or 3 [2]: " tls_choice </dev/tty
  case "${tls_choice:-2}" in 1|letsencrypt) SENTINEL_TLS=letsencrypt ;; 2|selfsigned) SENTINEL_TLS=selfsigned ;; 3|proxy) SENTINEL_TLS=proxy ;; *) die "Choose 1, 2 or 3." ;; esac
fi
SENTINEL_TLS="${SENTINEL_TLS:-selfsigned}"
case "$SENTINEL_TLS" in letsencrypt|selfsigned|proxy) ;; *) die "SENTINEL_TLS must be letsencrypt, selfsigned or proxy." ;; esac
if [ "$SENTINEL_TLS" = letsencrypt ]; then
  ask SENTINEL_LE_EMAIL "      Email for Let's Encrypt expiry notices"
  [[ "$SENTINEL_LE_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "That is not an email address."
elif [ "$SENTINEL_TLS" = proxy ]; then
  note "The proxy must send the Host header, X-Forwarded-For and X-Forwarded-Proto: https, to http://<this server>:80."
  ask SENTINEL_PROXY_IP "      The proxy's IP address (one address)"
  valid_ip "$SENTINEL_PROXY_IP" || die "That is not one IP address: $SENTINEL_PROXY_IP"
fi

step 3 "Firewall"
note "ufw: allow SSH (rate-limited) and the web ports$( [ "$SENTINEL_TLS" = proxy ] && echo ' (port 80 from the proxy only)' ), block everything else inbound."
ask_yes SENTINEL_FIREWALL "Turn on the firewall?" 1

step 4 "SSH protection"
note "fail2ban bans addresses after repeated failed SSH sign-ins (Sentinel throttles web sign-ins itself)."
ask_yes SENTINEL_FAIL2BAN "Install fail2ban?" 1

step 5 "Automatic security updates"
note "Debian security patches are installed automatically every day (unattended-upgrades)."
ask_yes SENTINEL_AUTO_UPDATES "Turn on automatic security updates?" 1

step 6 "Backups"
note "Sentinel backs up its database and config every night (kept 14 days). With a passphrase they are encrypted." \
     "Keep the passphrase in your password vault: without it an encrypted backup can't be restored. Leave empty to skip."
if [ -z "${SENTINEL_BACKUP_PASSPHRASE:-}" ] && have_tty; then
  while true; do
    IFS= read -r -s -p "      Backup passphrase (at least 12 characters, empty for none): " pp1 </dev/tty; echo >/dev/tty
    [ -z "$pp1" ] && break
    [ "${#pp1}" -ge 12 ] || { note "Too short."; continue; }
    IFS= read -r -s -p "      The same passphrase again: " pp2 </dev/tty; echo >/dev/tty
    [ "$pp1" = "$pp2" ] && { SENTINEL_BACKUP_PASSPHRASE="$pp1"; break; }
    note "They don't match; try again."
  done
  unset pp1 pp2
fi
if [ -n "${SENTINEL_BACKUP_PASSPHRASE:-}" ] && [ "${#SENTINEL_BACKUP_PASSPHRASE}" -lt 12 ]; then die "The backup passphrase must be at least 12 characters."; fi

step 7 "First admin"
note "The first administrator. You choose the password next; two-factor authentication is set up at first sign-in."
if have_tty; then
  ask SENTINEL_ADMIN_USER "      User name"
  [[ "$SENTINEL_ADMIN_USER" =~ ^[A-Za-z0-9._-]{3,50}$ ]] || die "User names: 3 to 50 letters, digits, dots, dashes or underscores."
  ask SENTINEL_ADMIN_NAME "      Display name"
  ask SENTINEL_ADMIN_EMAIL "      Email"
  [[ "$SENTINEL_ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "That is not an email address."
fi

# ----------------------------------------------------------------- summary ----
yn() { [ "$1" = 1 ] && echo yes || echo no; }
if have_tty; then
  printf '\n%sSummary%s\n' "$c_ok" "$c_0"
  printf '      Address:            https://%s\n' "$SENTINEL_DOMAIN"
  case "$SENTINEL_TLS" in
    letsencrypt) printf '      HTTPS:              Let'"'"'s Encrypt (notices to %s)\n' "$SENTINEL_LE_EMAIL" ;;
    selfsigned) printf '      HTTPS:              self-signed certificate\n' ;;
    proxy) printf '      HTTPS:              by the reverse proxy %s (Sentinel: plain HTTP on port 80, for the proxy only)\n' "$SENTINEL_PROXY_IP" ;;
  esac
  printf '      Firewall (ufw):     %s\n      fail2ban (SSH):     %s\n      Security updates:   %s\n' "$(yn "$SENTINEL_FIREWALL")" "$(yn "$SENTINEL_FAIL2BAN")" "$(yn "$SENTINEL_AUTO_UPDATES")"
  printf '      Backups encrypted:  %s\n' "$( [ -n "${SENTINEL_BACKUP_PASSPHRASE:-}" ] && echo yes || echo no )"
  printf '      First admin:        %s (%s, %s)\n' "${SENTINEL_ADMIN_USER:-later}" "${SENTINEL_ADMIN_NAME:-}" "${SENTINEL_ADMIN_EMAIL:-}"
  printf '      Source:             %s, branch %s%s\n' "$REPO" "$BRANCH" "$( [ "$BRANCH" != main ] && echo ' (DEVELOPMENT BUILD: for testing)' )"
  read -r -p "      Install with these settings? [y/N]: " go </dev/tty
  case "${go,,}" in y|yes) ;; *) die "Sentinel was not installed." ;; esac
fi

args=(--domain "$SENTINEL_DOMAIN" --tls "$SENTINEL_TLS")
[ "$SENTINEL_TLS" = letsencrypt ] && args+=(--email "$SENTINEL_LE_EMAIL")
[ "$SENTINEL_TLS" = proxy ] && args+=(--proxy-ip "$SENTINEL_PROXY_IP")
[ "$SENTINEL_FIREWALL" = 1 ] || args+=(--no-firewall)
[ "$SENTINEL_FAIL2BAN" = 1 ] || args+=(--no-fail2ban)
[ "$SENTINEL_AUTO_UPDATES" = 1 ] || args+=(--no-auto-updates)
[ "$DRY" = 1 ] && args+=(--dry-run)
[ "${SENTINEL_FORCE:-0}" = 1 ] && args+=(--skip-os-check)
# The admin details and the backup passphrase travel in the environment, never on a command line.
export SENTINEL_ADMIN_USER="${SENTINEL_ADMIN_USER:-}" SENTINEL_ADMIN_NAME="${SENTINEL_ADMIN_NAME:-}" SENTINEL_ADMIN_EMAIL="${SENTINEL_ADMIN_EMAIL:-}"
export SENTINEL_BACKUP_PASSPHRASE="${SENTINEL_BACKUP_PASSPHRASE:-}"

log "Installing MSP Sentinel for https://$SENTINEL_DOMAIN"
install_update_command
exec bash "$SRC_DIR/install/install.sh" "${args[@]}"
