#!/usr/bin/env bash
# Build a release archive: dist/msp-sentinel-<version>.tar.gz, dist/SHA256SUMS and dist/AGENT-MANIFEST-SHA256 (the
# agent manifest hash admins compare before signing the version on Sentinel's System page; publish it with the
# release notes).
#
# Usage: bin/build-release.sh [--out DIR] [--allow-dirty]
#
# The archive is made with "git archive" from the committed HEAD, so it holds
# exactly what is in git, minus the paths marked export-ignore in
# .gitattributes (tests, dev files). File times come from the commit and gzip
# stores no name or time, so the same commit always gives the same bytes
# (reproducible). Sign SHA256SUMS yourself, e.g.: gpg --armor --detach-sign dist/SHA256SUMS
#
# Security: refuses to build from a working tree with uncommitted changes
# (unless --allow-dirty), so a release never contains unreviewed files.
# config/config.php and storage/ are never in git, so never in a release.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/dist"
allow_dirty=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --allow-dirty) allow_dirty=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

cd "$root"
version="$(tr -d '[:space:]' < VERSION)"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION must be x.y.z (found: $version)" >&2; exit 1
fi
if [ "$allow_dirty" -eq 0 ] && [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Uncommitted changes: commit them first (or use --allow-dirty for a test build)." >&2; exit 1
fi
if [ "$(git show HEAD:VERSION | tr -d '[:space:]')" != "$version" ]; then
  echo "VERSION in the working tree differs from the committed one." >&2; exit 1
fi

mkdir -p "$out"
name="msp-sentinel-$version"
git -c tar.umask=0022 archive --worktree-attributes --format=tar --prefix="$name/" HEAD | gzip -n -9 > "$out/$name.tar.gz"
( cd "$out" && sha256sum "$name.tar.gz" > SHA256SUMS )
# The agent manifest hash of exactly this archive (unpacked to a temporary folder): what Sentinel's System page signs.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$out/$name.tar.gz" -C "$tmp"
php "$root/bin/release-sign.php" hash --dir "$tmp/$name" | sed -n 's/^Manifest SHA-256: //p' > "$out/AGENT-MANIFEST-SHA256"
[ -s "$out/AGENT-MANIFEST-SHA256" ] || { echo "Could not compute the agent manifest hash." >&2; exit 1; }
echo "Built $out/$name.tar.gz"
cat "$out/SHA256SUMS"
echo "Agent manifest SHA-256 (publish with the release notes): $(cat "$out/AGENT-MANIFEST-SHA256")"
