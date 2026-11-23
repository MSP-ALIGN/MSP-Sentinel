# Windows agent (in progress)

The on-premises agent will also run natively on Windows, for client sites without a Linux machine. It is the same
agent program (PHP) with a small platform layer; jobs, signatures, scans, results, updates and moves work as on
Linux. This page records the agreed design. **Status: the platform layer is done and tested; the installer, the
service and the update task are being built and need testing on a real Windows machine.**

## Agreed choices

- **Windows Server 2022 and 2025, and Windows 11** (64-bit).
- **No Npcap.** nmap runs unprivileged TCP connect scans (`-sT --unprivileged`, discovery with TCP connect pings), as
  the Linux agent already does. Npcap is not needed or used. The free Npcap can't be installed unattended, and
  bundling it needs a paid licence. Scans on Windows are slower, because Windows' connect calls are slower.
- **A real Windows service through WinSW** (MIT licence; one program, its SHA-256 pinned in the installer). It runs
  under its own virtual service account (`NT SERVICE\SentinelAgent`, no password, not an administrator) and restarts
  on failure.
- **A one-line PowerShell install** (as administrator) that asks for the enrolment code, downloads PHP (windows.php.net,
  NTS x64) and nmap (nmap.org) with pinned SHA-256 checksums, installs WinSW and the agent, sets permissions, and
  enrols.
- **Updates through a SYSTEM scheduled task**, the Windows twin of the Linux root update helper.

## How it stays safe on Windows

| | Linux | Windows |
|---|---|---|
| Agent runs as | `sentinel-agent` user, hardened systemd unit | `NT SERVICE\SentinelAgent` virtual account (WinSW) |
| Code | `/opt/sentinel-agent`, root-owned | `C:\Program Files\MSP Sentinel Agent`, Administrators/SYSTEM only (read for the agent) |
| Config (token, pinned keys) | `/etc/sentinel-agent`, root-owned, agent reads | `C:\ProgramData\MSP Sentinel Agent\config`, Administrators/SYSTEM write, agent reads |
| Agent's writable folder | `/var/lib/sentinel-agent` | `C:\ProgramData\MSP Sentinel Agent\state` |
| Update helper | root, path unit; reads staged files through a collector run as the agent | SYSTEM task; **downloads and checks the release itself** (see below) |
| Name-poisoning listener | UDP 137 and 5355 | off: Windows itself owns those ports |
| ARP table (MAC addresses) | `/proc/net/arp` | `arp -a` |

**Why the Windows update task downloads the release itself:** on Windows the agent's account could create junctions
in its own folder. If SYSTEM read or deleted staged files there, a compromised agent could redirect it. So the agent
only writes a small request (the version and request id, and for a release key offer the offer signed by Sentinel).
The SYSTEM task:

1. reads that request (size-capped);
2. fetches the manifest and files from Sentinel with the agent's own config;
3. checks them with the pinned release key (and offers with Sentinel's key from the config, as on Linux);
4. installs the files into a new folder, runs the self-check as the agent, swaps folders, restarts the service, and
   rolls back if it doesn't stay up;
5. writes its result into its own folder, which the agent can read but not change.

It never deletes or writes in the agent's folder.

## Done so far

- `src/AgentClient/Platform.php`:
  - the Windows paths;
  - nmap's install folder;
  - `arp -a` parsing (unicast entries only);
  - no name listener on Windows;
  - diagnostics without Linux-only values.
- The test suite runs the real agent in Windows mode (`testing.platform`): scans, MAC addresses from `arp -a` output,
  diagnostics.

## Still to do

- `install-agent.ps1`: downloads with pinned checksums, WinSW service, ACLs, enrolment with the code prompt,
  uninstall.
- The SYSTEM update task (PHP, run by Task Scheduler) and the agent's Windows request hand-off.
- The enrolment page and docs: the PowerShell command next to the Linux one.
- Testing on Windows Server 2022/2025 and Windows 11. PowerShell can't be run in the build environment, so each
  step needs a check on a real machine.
