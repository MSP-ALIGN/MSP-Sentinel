#!/usr/bin/env bash
# MSP Sentinel on-premises agent installer for Debian 13 (also Debian 12 and Ubuntu 24.04 LTS), on a mini-PC or VM at
# the client's site. One-line install from GitHub: see install-agent.sh at the top of the repository.
#
# Install (from the unpacked release folder, with a one-time code from the client page in Sentinel; without
# --code it asks for the code, which keeps it out of the shell history and the process list):
#   sudo ./install/agent-install.sh --server https://sentinel.msp.example [--code SNE-XXXXX-XXXXX-XXXXX-XXXXX] [--ca /path/ca.pem]
# Upgrade (from the NEW release folder; keeps the enrolment):
#   sudo ./install/agent-install.sh --upgrade
# Remove (also revoke the agent in Sentinel):
#   sudo ./install/agent-install.sh --uninstall
# Give an agent the release key by hand (only needed when the old key file was lost and the key was replaced on the
# System page; the key is shown there):
#   sudo ./install/agent-install.sh --upgrade --release-key BASE64KEY
# See what it would do, without changing anything:
#   ./install/agent-install.sh --dry-run --server https://sentinel.msp.example --code SNE-...
#
# What it does (install): installs PHP (CLI) and nmap, creates the unprivileged
# "sentinel-agent" system user, copies the release to /opt/sentinel-agent,
# enrols the agent with the code (pinning Sentinel's signing key), and starts
# the hardened systemd service "sentinel-agent".
#
# Security notes:
# - The agent runs as "sentinel-agent", never root, with one capability (listening on UDP 137
#   for NetBIOS name requests): scans are unprivileged TCP connect scans.
# - Remote updates (from Sentinel's Agents page) are installed by a root helper
#   (sentinel-agent-update.path/.service) only when signed with the maintainer's release key,
#   pinned here at /etc/sentinel-agent/release-key.pub; Sentinel can't vouch for code. The systemd unit locks down the
#   file system (only its state folder is writable) and forbids privilege gain. The helper starts through a root-owned
#   launcher outside the code folder (/usr/local/lib/sentinel-agent/update-launcher.php), which also puts the code
#   folder back if an update stopped half-way (power cut), at the helper's next run or the agent's next start.
# - The config (with the agent token and the pinned server key, site and client)
#   is /etc/sentinel-agent/agent.json, owned by root and only readable by the
#   agent (0640): the agent can't change what it trusts. Only its state folder
#   /var/lib/sentinel-agent is writable. The token is never printed.
# - The agent only connects out to Sentinel over HTTPS; no inbound port is opened.
# - Safe to re-run: an existing enrolment is kept unless you remove it.
set -euo pipefail

APP_DIR=/opt/sentinel-agent
CONF_DIR=/etc/sentinel-agent
STATE_DIR=/var/lib/sentinel-agent
# The update helper's launcher, outside the code folder (see install/linux/agent-update-launcher.php). The systemd
# units name this path as is.
LAUNCHER_DIR=/usr/local/lib/sentinel-agent
PHPV=8.4
PHP_BIN="php${PHPV}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

mode=install
server=""
code=""
ca=""
release_key=""
dry=0
skip_os=0
while [ $# -gt 0 ]; do
  case "$1" in
    --server) server="${2:-}"; shift 2 ;;
    --code) code="${2:-}"; shift 2 ;;
    --ca) ca="${2:-}"; shift 2 ;;
    --release-key) release_key="${2:-}"; shift 2 ;;
    --upgrade) mode=upgrade; shift ;;
    --uninstall) mode=uninstall; shift ;;
    --dry-run) dry=1; shift ;;
    --skip-os-check) skip_os=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
run() {
  if [ "$dry" -eq 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}
write_file() {
  local path="$1" mode="$2"
  if [ "$dry" -eq 1 ]; then printf '  [dry-run] write %s (mode %s)\n' "$path" "$mode"; cat > /dev/null; return; fi
  ( umask 077; cat > "$path.tmp" )
  chmod "$mode" "$path.tmp"
  mv -f "$path.tmp" "$path"
}
copy_code() {
  run install -d -o root -g sentinel-agent -m 0750 "$APP_DIR"
  run rsync -a --delete --exclude /config/ --exclude /storage/ --exclude /dist/ --exclude /tests/ "$SRC/" "$APP_DIR/"
  run chown -R root:sentinel-agent "$APP_DIR"
  run find "$APP_DIR" -type d -exec chmod 0750 {} +
  run find "$APP_DIR" -type f -exec chmod 0640 {} +
  run chmod 0750 "$APP_DIR/install/agent-install.sh"
}
unit() {
  render "${1:-sentinel-agent.service}"
}
render() {
  sed -e "s#__ROOT__#${APP_DIR}#g" -e "s#__PHP__#/usr/bin/${PHP_BIN}#g" -e "s#__CONF__#${CONF_DIR}#g" "$SRC/install/templates/$1"
}
# Remote updates (1.22): pin the maintainer's release public key OUTSIDE the code folder (root-owned; a remote update
# never changes it), and install the root update helper's path unit. Without a key in the release, remote updates stay
# off and the agent can only be upgraded by hand.
# Whether a release key was pinned at enrolment (in agent.json): parsed as JSON, not matched as text. When agent.json
# can't be read or parsed, say yes, so a key file from the release folder never replaces a pin we couldn't check.
enrolment_key_pinned() {
  [ -f "$CONF_DIR/agent.json" ] || return 1
  "$PHP_BIN" -r '$c = json_decode((string) @file_get_contents($argv[1]), true); exit(!is_array($c) || (is_string($c["release_public_key"] ?? null) && $c["release_public_key"] !== "") ? 0 : 1);' "$CONF_DIR/agent.json"
}

release_key_and_helper() {
  # The release key normally comes from Sentinel (at enrolment, or offered later); a key given with --release-key
  # replaces the pinned one (after a lost key was replaced on the System page). A key file in the release folder is
  # only used when none is pinned yet. An existing pin is never changed silently.
  if [ -n "$release_key" ]; then
    printf '%s' "$release_key" | grep -Eq '^[A-Za-z0-9+/]{43}=$' || die "--release-key must be the base64 public key shown on Sentinel's System page."
    if [ "$dry" -eq 1 ]; then printf '  [dry-run] write %s/release-key.pub\n' "$CONF_DIR"; else
      printf '%s\n' "$release_key" > "$CONF_DIR/release-key.pub.tmp"; chown root:root "$CONF_DIR/release-key.pub.tmp"; chmod 0644 "$CONF_DIR/release-key.pub.tmp"
      mv -f "$CONF_DIR/release-key.pub.tmp" "$CONF_DIR/release-key.pub"; fi
    echo "  Release key pinned from --release-key."
  elif [ ! -s "$CONF_DIR/release-key.pub" ] && [ -s "$SRC/install/release-key.pub" ] && ! enrolment_key_pinned; then
    # (Not when a key was pinned at enrolment: it is in agent.json, and a key file here would take its place.)
    run install -o root -g root -m 0644 "$SRC/install/release-key.pub" "$CONF_DIR/release-key.pub"
  fi
  # The helper's results: root-owned, readable by the agent, not changeable by it.
  run install -d -o root -g sentinel-agent -m 0750 /var/lib/sentinel-agent-update
  # The helper's launcher (root-owned, outside the code folder): repairs an update stopped half-way, then runs the
  # helper. Written on install and on every --upgrade.
  run install -d -o root -g root -m 0755 "$LAUNCHER_DIR"
  run install -o root -g root -m 0644 "$SRC/install/linux/agent-update-launcher.php" "$LAUNCHER_DIR/update-launcher.php"
  render sentinel-agent-update.service | write_file /etc/systemd/system/sentinel-agent-update.service 0644
  render sentinel-agent-update.path | write_file /etc/systemd/system/sentinel-agent-update.path 0644
  run systemctl daemon-reload
  run systemctl enable --now sentinel-agent-update.path
}

[ -f "$SRC/VERSION" ] && [ -f "$SRC/bin/sentinel-agent.php" ] && [ -f "$SRC/install/linux/agent-update-launcher.php" ] || die "Run this from an unpacked MSP Sentinel release."
if [ "$dry" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then die "Run as root (sudo)."; fi

if [ "$mode" = uninstall ]; then
  say "Removing the agent"
  run systemctl disable --now sentinel-agent sentinel-agent-update.path || true
  run rm -f /etc/systemd/system/sentinel-agent.service /etc/systemd/system/sentinel-agent-update.service /etc/systemd/system/sentinel-agent-update.path
  run systemctl daemon-reload
  run rm -rf "$APP_DIR" "$APP_DIR.old" "$APP_DIR.new" "$APP_DIR.failed" "$CONF_DIR" "$STATE_DIR" /var/lib/sentinel-agent-update "$LAUNCHER_DIR"
  run userdel sentinel-agent || true
  echo "  Removed. Also revoke the agent on the client page in Sentinel, so its token stops working."
  exit 0
fi

if [ "$skip_os" -eq 0 ]; then
  [ -r /etc/os-release ] || die "Cannot detect the operating system."
  . /etc/os-release
  case "${ID:-}-${VERSION_ID:-}" in
    debian-13|debian-12|ubuntu-24.04) ;;
    *) die "Supported: Debian 13 (recommended), Debian 12 and Ubuntu 24.04 (found ${PRETTY_NAME:-unknown}). Use --skip-os-check at your own risk." ;;
  esac
fi

if [ "$mode" = upgrade ]; then
  [ -f "$CONF_DIR/agent.json" ] || [ "$dry" -eq 1 ] || die "No enrolled agent found ($CONF_DIR/agent.json)."
  say "Upgrading the agent to $(tr -d '[:space:]' < "$SRC/VERSION")"
  run systemctl stop sentinel-agent || true
  copy_code
  unit | write_file /etc/systemd/system/sentinel-agent.service 0644
  release_key_and_helper
  run systemctl start sentinel-agent
  say "Done"
  exit 0
fi

# ---------------------------------------------------------------- install
case "$server" in https://*) ;; *) die "Give the Sentinel address with --server https://..." ;; esac
printf '%s' "$server" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$' || die "The --server value must be https://host[:port] only."
# From the one-line installer (install-agent.sh) the code arrives on stdin; otherwise ask on the terminal.
if [ -z "$code" ] && [ "${SENTINEL_AGENT_CODE_STDIN:-0}" = 1 ]; then
  read -r code || true
fi
if [ -z "$code" ] && [ "$dry" -eq 0 ]; then
  { read -r -s -p "One-time enrolment code from Sentinel: " code; echo; } </dev/tty
fi
[ "$dry" -eq 1 ] && [ -z "$code" ] && code="SNE-XXXXX-XXXXX-XXXXX-XXXXX"
printf '%s' "$code" | grep -Eq '^SNE(-[A-Z2-9]{5}){4}$' || die "That is not a valid enrolment code (SNE-XXXXX-XXXXX-XXXXX-XXXXX)."
if [ -n "$ca" ] && [ ! -r "$ca" ] && [ "$dry" -eq 0 ]; then die "CA file not readable: $ca"; fi
if [ -f "$CONF_DIR/agent.json" ] && [ "$dry" -eq 0 ]; then die "This machine is already enrolled. Use --upgrade, or --uninstall first."; fi

say "Packages (PHP ${PHPV} CLI, nmap)"
run apt-get update
run apt-get install -y ca-certificates curl gnupg rsync nmap
if [ "${ID:-}-${VERSION_ID:-}" = debian-13 ]; then
  : # Debian 13 ships PHP 8.4 itself.
elif [ "${ID:-}" = debian ]; then
  # PHP 8.4 from packages.sury.org (Debian 12 ships 8.2).
  run install -d -m 0755 /etc/apt/keyrings
  run curl -fsSL https://packages.sury.org/php/apt.gpg -o /etc/apt/keyrings/sury-php.gpg
  echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ $(. /etc/os-release && echo "$VERSION_CODENAME") main" | write_file /etc/apt/sources.list.d/sury-php.list 0644
else
  # PHP 8.4 from the ondrej/php PPA (Ubuntu 24.04 ships 8.3); adding it again is harmless.
  run apt-get install -y software-properties-common
  run add-apt-repository -y ppa:ondrej/php
fi
run apt-get update
run apt-get install -y "php${PHPV}-cli" "php${PHPV}-curl" "php${PHPV}-xml" "php${PHPV}-mbstring"

say "System user and code"
if ! id sentinel-agent >/dev/null 2>&1; then run useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin sentinel-agent; fi
copy_code
run install -d -o root -g sentinel-agent -m 0750 "$CONF_DIR"
run install -d -o sentinel-agent -g sentinel-agent -m 0700 "$STATE_DIR"
if [ -n "$ca" ]; then run install -o root -g sentinel-agent -m 0640 "$ca" "$CONF_DIR/ca.pem"; ca="$CONF_DIR/ca.pem"; fi

say "Enrolling with Sentinel (pins its signing key, site and client)"
# The code is passed on stdin, never on a command line; it works once and expires in 24 hours.
if [ "$dry" -eq 1 ]; then
  printf '  [dry-run] runuser -u sentinel-agent -- %s %s/bin/sentinel-agent.php enrol --server %s --code-stdin --config %s/agent.json\n' "$PHP_BIN" "$APP_DIR" "$server" "$STATE_DIR"
else
  printf '%s\n' "$code" | runuser -u sentinel-agent -- "$PHP_BIN" "$APP_DIR/bin/sentinel-agent.php" enrol --server "$server" --code-stdin --config "$STATE_DIR/agent.json" ${ca:+--ca "$ca"}
fi
# The agent may read its config but not change it (it holds the pinned key, site and client).
run mv -f "$STATE_DIR/agent.json" "$CONF_DIR/agent.json"
run chown root:sentinel-agent "$CONF_DIR/agent.json"
run chmod 0640 "$CONF_DIR/agent.json"

say "Service"
unit | write_file /etc/systemd/system/sentinel-agent.service 0644
release_key_and_helper
run systemctl enable --now sentinel-agent
say "Done. The agent checks in within a minute; see the client page in Sentinel. Logs: journalctl -u sentinel-agent"
