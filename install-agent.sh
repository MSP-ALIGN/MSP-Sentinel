#!/usr/bin/env bash
# =============================================================================
#  MSP Sentinel on-premises agent - one-line installer for Debian 13 (Debian 12 and Ubuntu 24.04 also work)
#
#  On the appliance at the client's site, with a one-time enrollment code from the client page in Sentinel:
#    curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install-agent.sh | sudo -E bash
#  It asks for the Sentinel address and the code. Unattended: set SENTINEL_SERVER (https://...) and
#  SENTINEL_CODE. SENTINEL_CA=/path/ca.pem when Sentinel's certificate is from a private CA.
#  SENTINEL_BRANCH (default main) and SENTINEL_REPO (owner/name) choose the source.
#
#  Upgrade later: sudo msp-sentinel-agent-update
#
#  What it does: installs git, fetches the release into /opt/sentinel-agent-src and runs
#  install/agent-install.sh (unprivileged user, hardened service, enrollment that pins Sentinel's key, site
#  and client). The code is passed on stdin, never on a command line.
# =============================================================================
set -Eeuo pipefail
umask 022

REPO="${SENTINEL_REPO:-MSP-ALIGN/MSP-Sentinel}"
BRANCH="${SENTINEL_BRANCH:-main}"
SRC_DIR=/opt/sentinel-agent-src

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
have_tty() { [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null || return 1; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "SENTINEL_REPO must be owner/name."
[[ "$BRANCH" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,59}$ && "$BRANCH" != *..* ]] || die "SENTINEL_BRANCH is not a valid branch name."
[ "$(id -u)" -eq 0 ] || die "Run as root: curl -fsSL ... | sudo -E bash"

server="${SENTINEL_SERVER:-}"
if [ -z "$server" ]; then
  have_tty || die "SENTINEL_SERVER is required (no terminal available to ask)."
  read -r -p "Sentinel address (https://...): " server </dev/tty
fi
case "$server" in https://*) ;; *) die "The Sentinel address must start with https://" ;; esac
ca="${SENTINEL_CA:-}"
if [ -n "$ca" ]; then
  [ -f "$ca" ] && [ -r "$ca" ] || die "SENTINEL_CA must be a readable CA certificate file (PEM)."
  ca="$(readlink -f -- "$ca")"
fi
code="${SENTINEL_CODE:-}"
if [ -z "$code" ]; then
  have_tty || die "SENTINEL_CODE is required (no terminal available to ask)."
  { read -r -s -p "One-time enrollment code: " code; echo; } </dev/tty
fi

apt-get update -qq
apt-get install -y -qq git ca-certificates curl rsync
if [ -d "$SRC_DIR/.git" ]; then
  git -C "$SRC_DIR" fetch --depth 1 origin "$BRANCH" && git -C "$SRC_DIR" reset --hard FETCH_HEAD
else
  git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" "$SRC_DIR"
fi
cat > /usr/local/sbin/msp-sentinel-agent-update <<UPD
#!/usr/bin/env bash
# Updates the MSP Sentinel agent from $REPO, branch $BRANCH (enrollment is kept).
set -Eeuo pipefail
git -C $SRC_DIR fetch --depth 1 origin "$BRANCH"
git -C $SRC_DIR reset --hard FETCH_HEAD
exec bash $SRC_DIR/install/agent-install.sh --upgrade
UPD
chmod 0755 /usr/local/sbin/msp-sentinel-agent-update
# The code reaches the installer through its environment-free prompt path: on stdin via a here-string.
SENTINEL_AGENT_CODE_STDIN=1 bash "$SRC_DIR/install/agent-install.sh" --server "$server" ${ca:+--ca "$ca"} <<<"$code"
