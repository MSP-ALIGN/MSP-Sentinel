#!/usr/bin/env bash
# MSP Sentinel agent on Proxmox VE (1.36): creates an unprivileged Debian 13 LXC container ready for the agent.
# Run it on the Proxmox host as root. It only creates and starts the container; the agent itself is then installed
# inside it with the normal install command from Sentinel's enrolment page (the enrolment code is never passed here).
#
# Usage:
#   bash proxmox-agent-ct.sh --bridge vmbr0 [--vlan 20] [--ip dhcp | --ip 10.0.20.50/24 --gw 10.0.20.1]
#        [--ctid 120] [--hostname sentinel-agent] [--storage local-lvm] [--template-storage local]
#        [--memory 1024] [--cores 1] [--disk 8] [--dry-run]
#
# What it creates: unprivileged=1 and features nesting=1 (so the agent keeps its full systemd hardening), start at
# boot, one network card on the bridge (and VLAN) of the client's network. Defaults suit one agent (1 core, 1 GB RAM,
# 8 GB disk).
#
# Security assumptions: every input is checked against a strict pattern before it reaches pct or pveam (no shell
# evaluation of values); nothing is downloaded except Proxmox's own Debian template through pveam.
set -euo pipefail

ctid="" ; bridge="" ; vlan="" ; ip="dhcp" ; gw="" ; host="sentinel-agent" ; storage="local-lvm" ; tstorage="local"
memory=1024 ; cores=1 ; disk=8 ; dry=0
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }
run() { if [ "$dry" -eq 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ctid) ctid="${2:-}"; shift 2 ;;
    --bridge) bridge="${2:-}"; shift 2 ;;
    --vlan) vlan="${2:-}"; shift 2 ;;
    --ip) ip="${2:-}"; shift 2 ;;
    --gw) gw="${2:-}"; shift 2 ;;
    --hostname) host="${2:-}"; shift 2 ;;
    --storage) storage="${2:-}"; shift 2 ;;
    --template-storage) tstorage="${2:-}"; shift 2 ;;
    --memory) memory="${2:-}"; shift 2 ;;
    --cores) cores="${2:-}"; shift 2 ;;
    --disk) disk="${2:-}"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
done

# Strict input checks: values go to pct as single arguments, and must look like what Proxmox expects.
[[ "$bridge" =~ ^[A-Za-z][A-Za-z0-9_.-]{0,14}$ ]] || die "--bridge is required: the bridge of the client's network, e.g. vmbr0."
[ -z "$vlan" ] || [[ "$vlan" =~ ^[0-9]{1,4}$ && "$vlan" -ge 1 && "$vlan" -le 4094 ]] || die "--vlan must be 1-4094."
[ -z "$ctid" ] || [[ "$ctid" =~ ^[1-9][0-9]{2,8}$ ]] || die "--ctid must be a number of 100 or more."
[[ "$host" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "--hostname must be a simple name (letters, digits, dashes)."
[[ "$storage" =~ ^[A-Za-z][A-Za-z0-9_.-]{0,39}$ ]] || die "--storage must be a Proxmox storage name."
[[ "$tstorage" =~ ^[A-Za-z][A-Za-z0-9_.-]{0,39}$ ]] || die "--template-storage must be a Proxmox storage name."
[[ "$memory" =~ ^[0-9]{3,6}$ && "$memory" -ge 512 ]] || die "--memory must be at least 512 (MB)."
[[ "$cores" =~ ^[0-9]{1,2}$ && "$cores" -ge 1 ]] || die "--cores must be 1 or more."
[[ "$disk" =~ ^[0-9]{1,4}$ && "$disk" -ge 4 ]] || die "--disk must be at least 4 (GB)."
if [ "$ip" != "dhcp" ]; then
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] || die "--ip must be dhcp or an address with prefix, e.g. 10.0.20.50/24."
  [[ "$gw" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "--gw is required with a fixed --ip, e.g. 10.0.20.1."
fi

if [ "$dry" -eq 0 ]; then
  [ "$(id -u)" -eq 0 ] || die "Run this on the Proxmox host as root."
  command -v pct >/dev/null && command -v pveam >/dev/null || die "pct and pveam not found: run this on a Proxmox VE host."
fi
if [ -z "$ctid" ]; then
  if [ "$dry" -eq 1 ]; then ctid=999; else ctid="$(pvesh get /cluster/nextid)"; fi
fi

say "Debian 13 template"
if [ "$dry" -eq 1 ]; then
  tmpl="debian-13-standard_13.1-2_amd64.tar.zst"
  echo "  [dry-run] pveam update; pveam download $tstorage <newest debian-13-standard>"
else
  pveam update >/dev/null
  tmpl="$(pveam available --section system | awk '$2 ~ /^debian-13-standard_/ {print $2}' | sort -V | tail -1)"
  [ -n "$tmpl" ] || die "No Debian 13 template offered by pveam."
  if ! pveam list "$tstorage" | grep -q "$tmpl"; then
    pveam download "$tstorage" "$tmpl"
  fi
fi

net="name=eth0,bridge=${bridge},ip=${ip}${gw:+,gw=${gw}}${vlan:+,tag=${vlan}}"
say "Creating container $ctid ($host)"
run pct create "$ctid" "${tstorage}:vztmpl/${tmpl}" --hostname "$host" --ostype debian --unprivileged 1 --features nesting=1 \
  --cores "$cores" --memory "$memory" --swap 512 --rootfs "${storage}:${disk}" --net0 "$net" --onboot 1
run pct start "$ctid"

say "Next steps"
cat <<NEXT
  1. In Sentinel: open the client, Agents, record the site's internal authorisation, then Create an enrolment code.
  2. On this host: pct enter $ctid
  3. Inside the container: apt-get update && apt-get install -y curl, then paste the install command from the
     enrolment page and enter the code when asked.
NEXT
