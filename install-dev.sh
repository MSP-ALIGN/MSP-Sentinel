#!/usr/bin/env bash
# =============================================================================
#  MSP Sentinel - one-line install of a DEVELOPMENT server (Debian 13; Debian 12 and Ubuntu 24.04 also work)
#
#    curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/develop/install-dev.sh | sudo -E bash
#
#  The same guided install as install.sh, but the server follows the develop branch: it gets changes before
#  they are merged to main and released, so you can try them first. `sudo msp-sentinel-update` keeps it on
#  develop. The web interface shows a "Development build" badge on every page.
#
#  Use a separate server (or VM) and a separate host name from production, and don't scan clients from it
#  unless you would scan them from production too: the same written authorisation rules apply.
#
#  Every SENTINEL_* setting of install.sh works here too. SENTINEL_BRANCH picks another branch (for example a
#  feature branch); the default is develop.
#
#  Security notes: this fetches install.sh from the same branch over HTTPS from the public repository into a
#  private temporary file and runs it; nothing secret is passed on a command line.
# =============================================================================
set -Eeuo pipefail
umask 077

export SENTINEL_BRANCH="${SENTINEL_BRANCH:-develop}"
REPO="${SENTINEL_REPO:-MSP-ALIGN/MSP-Sentinel}"
# Checked here because both go into the download URL (install.sh checks them again).
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "SENTINEL_REPO must be owner/name." >&2; exit 1; }
[[ "$SENTINEL_BRANCH" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,59}$ && "$SENTINEL_BRANCH" != *..* ]] || { echo "SENTINEL_BRANCH is not a valid branch name." >&2; exit 1; }

# Tests and dry runs: use the local copy instead of downloading.
if [ -n "${SENTINEL_SRC:-}" ] && [ "${SENTINEL_DRY_RUN:-0}" = 1 ]; then
  exec bash "$SENTINEL_SRC/install.sh"
fi

command -v curl >/dev/null || { echo "curl is needed: apt install -y curl" >&2; exit 1; }
tmp="$(mktemp)"
trap 'rm -f -- "$tmp"' EXIT
curl -fsSL --proto '=https' "https://raw.githubusercontent.com/$REPO/$SENTINEL_BRANCH/install.sh" -o "$tmp"
# Not exec: the trap must still remove the temporary file afterwards.
bash "$tmp"
