#!/usr/bin/env bash
# =============================================================================
#  MSP Sentinel - one-line installer / upgrader for Debian 13 (trixie)
#  (Debian 12 and Ubuntu 24.04 LTS also work)
#
#  Fresh install, on a new Debian 13 VM (a minimal Debian may need `apt install -y curl sudo` first, as root):
#    curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install.sh | sudo -E bash
#
#  Upgrade an existing install:
#    sudo msp-sentinel-update
#
#  Unattended install: set any of these to skip the matching question
#    SENTINEL_DOMAIN       host name users browse to, e.g. sentinel.msp.example
#    SENTINEL_TLS          letsencrypt (public DNS + port 80 open) or selfsigned (default)
#    SENTINEL_LE_EMAIL     Let's Encrypt expiry notices (letsencrypt only)
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
have_tty() { [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; }
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

ask SENTINEL_DOMAIN "Host name users browse to (e.g. sentinel.msp.example)"
SENTINEL_DOMAIN="$(printf '%s' "$SENTINEL_DOMAIN" | tr 'A-Z' 'a-z')"
[[ "$SENTINEL_DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "That is not a host name: $SENTINEL_DOMAIN"
ask SENTINEL_TLS "Certificate: letsencrypt (public DNS, port 80 open) or selfsigned" "selfsigned"
case "$SENTINEL_TLS" in letsencrypt|selfsigned) ;; *) die "SENTINEL_TLS must be letsencrypt or selfsigned." ;; esac
args=(--domain "$SENTINEL_DOMAIN")
if [ "$SENTINEL_TLS" = letsencrypt ]; then
  ask SENTINEL_LE_EMAIL "Email for Let's Encrypt expiry notices"
  [[ "$SENTINEL_LE_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "That is not an email address."
  args+=(--certbot --email "$SENTINEL_LE_EMAIL")
fi
[ "$DRY" = 1 ] && args+=(--dry-run)
[ "${SENTINEL_FORCE:-0}" = 1 ] && args+=(--skip-os-check)

log "Installing MSP Sentinel for https://$SENTINEL_DOMAIN"
install_update_command
exec bash "$SRC_DIR/install/install.sh" "${args[@]}"
