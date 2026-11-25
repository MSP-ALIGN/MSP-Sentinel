# Windows agent (1.26, preview)

The on-premises agent will also run natively on Windows, for client sites without a Linux machine. It is the same
agent program (PHP) with a small platform layer; jobs, signatures, scans, results, updates and moves work as on
Linux.

**Status: preview.** The agent program, the update task and the enrollment page are built and tested by the test suite
(which runs on Linux with the Windows platform forced). The PowerShell installer could not be run where it was
written: test it on a Windows Server 2022/2025 or Windows 11 machine before using it at a client.

## Install

1. On the client's Agents page, record an internal authorization and click **Create an enrollment code**.
2. On the Windows machine, open PowerShell with **Run as administrator** and paste the Windows command shown on the
   enrollment page:

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((Invoke-RestMethod https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install-agent.ps1))) -Server https://sentinel.msp.example
   ```

   It asks for the code. Add `-Ca C:\path\ca.pem` for a private CA.
3. The agent appears on the Agents page within a minute. The service is **MSP Sentinel Agent** (services.msc), and
   its log is in `C:\ProgramData\MSP Sentinel Agent\logs`.

Upgrade by hand: run the same command with `-Upgrade`; it keeps the enrollment. Remove: `-Uninstall`, and revoke the
agent in Sentinel. Give the release key by hand: `-Upgrade -ReleaseKey BASE64KEY`.

What the installer checks before it runs anything:

- **PHP 8.4 (NTS x64):** the SHA-256 that windows.php.net publishes in its release list.
- **nmap:** the SHA-256 in nmap.org's digest file, and a valid Authenticode signature. It is installed silently
  first; where that can't finish (the free nmap's bundled Npcap waits for a click), its setup window opens: click
  through it and untick Npcap. An nmap that is already installed is used as it is.
- **Visual C++ runtime:** a valid Microsoft signature.
- **WinSW 2.12.0:** a SHA-256 pinned in the script.
- **The agent code:** downloaded from GitHub (the same trust as the Linux one-line install).

Remote updates afterwards are checked with the pinned release key.

## Agreed choices

- **Windows Server 2022 and 2025, and Windows 11** (64-bit).
- **No Npcap.** nmap runs unprivileged TCP connect scans (`-sT --unprivileged`, discovery with TCP connect pings), as
  the Linux agent already does. Npcap is not needed or used. The free Npcap can't be installed unattended, and
  bundling it needs a paid license. Scans on Windows are slower, because Windows' connect calls are slower.
- **A real Windows service through WinSW** (MIT license; the .NET Framework build, its SHA-256 pinned in the
  installer). It runs under its own virtual service account (`NT SERVICE\SentinelAgent`, no password, not an
  administrator) and restarts on failure. Its privileges are limited to SeChangeNotifyPrivilege and
  SeCreateGlobalPrivilege (`sc privs`). By default every service can impersonate clients, which known tools turn into
  SYSTEM.
- **A one-line PowerShell install** (as administrator) that asks for the enrollment code, downloads PHP (windows.php.net,
  NTS x64) and nmap (nmap.org), checks them against the SHA-256 their sites publish, installs WinSW (SHA-256 pinned)
  and the agent, sets permissions, and enrolls.
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

**The update task runs through a small launcher outside the code folder** (`agent-update-launcher.php`). PHP keeps
the script it started with open, and Windows can't rename a folder with an open file in it. The launcher also repairs
an update that stopped half-way.

**The installer never acts through links, and never trusts a folder it didn't make.**

- **Links:** before changing permissions or deleting anything, it refuses if one of its folders is a junction or link.
  It deletes with `rmdir /s`, which removes links but never what they point to.
- **Fresh install:** it creates the ProgramData folder itself (failing if someone recreated it in between), replaces
  its whole permission list in one step (SYSTEM and Administrators only, owner Administrators), and checks that
  nothing was created inside meanwhile.
- **`-Upgrade`:** it refuses unless the service exists and the data, config and update folders are still owned and
  writable only by Administrators and SYSTEM.

**After a crash in the middle of an update:**

- A marker in the update task's own folder makes the next run set the service back to start automatically and start
  it.
- If the code folder is missing, the launcher puts the previous one back first.

**Why the Windows update task downloads the release itself:** on Windows the agent's account could create junctions
in its own folder. If SYSTEM read or deleted staged files there, a compromised agent could redirect it. So the agent
only writes a small request (the version and request id, and for a release key offer the offer signed by Sentinel).
The SYSTEM task:

1. reads that request (size-capped);
2. fetches the manifest and files from Sentinel with the agent's own config;
3. checks them with the pinned release key (and offers with Sentinel's key from the config, as on Linux);
4. installs the files into a new folder, runs the new release's self-check, swaps folders, restarts the service, and
   rolls back if it doesn't stay up;
5. writes its result into its own folder, which the agent can read but not change.

It never deletes or writes in the agent's folder. It reads only the two small request files there, and only when the
folder and the files resolve to themselves (no junction, link or pipe).

## Limits on Windows

- **Slower scans.** There is no Npcap, so discovery and port scans use Windows' connect calls, which nmap's
  documentation says are slower.
- **No name-poisoning check.** Windows uses the UDP 137 and 5355 ports itself, so the agent can't listen on them.
- **Diagnostics leave out uptime and free memory.**
- **nmap may need a click-through.** The installer first runs nmap's setup silently (at most 5 minutes, or 2
  minutes with no one at the screen). nmap itself installs silently; the free edition's bundled Npcap can't, so it
  all finishes on its own only where an Npcap at least as new as nmap's bundled one is already installed (an older
  Npcap still asks). Otherwise the silent setup is stopped. nmap itself usually works by then (Zenmap and Ncat may
  be missing; the agent needs neither), and the install carries on; if not, nmap's setup window opens and waits up
  to 30 minutes: click through and untick Npcap. For an unattended install on such a machine (an RMM tool running as
  SYSTEM, with no desktop), install nmap first (`nmap-<version>-setup.exe` from nmap.org, Npcap unticked); the
  installer then uses it and needs no clicks. Without a desktop, it stops with a clear message when nmap can't be
  installed silently.
- **Not verified on Windows yet:**
  - The `sc queryex` output the update task reads is assumed to be in English.
- **Updates use the address the agent was enrolled with.** The update task doesn't follow a move to a new Sentinel
  address, because it never reads the agent's own folder. Keep the old address working, or upgrade by hand after a
  move.
- **The update task's pre-flight is its own fixed check** (1.35.1): it asks this machine's PHP for its version and
  extensions without running any of the new release's code as SYSTEM (on Linux the new release's self-check runs as
  the agent's user). Anything else wrong shows up in the health check after the swap, which rolls back.
- **The update task's own code runs from a frozen copy** (1.35): `C:\Program Files\MSP Sentinel Agent\updater`,
  outside `app\`, which remote updates never change, so the task code never comes from a new release.
  `install-agent.ps1` refreshes it on install and `-Upgrade`; an agent updated from an older version makes it once
  from its installed release (if Windows doesn't let the old launcher be replaced while it runs, run
  `install-agent.ps1 -Upgrade` once to finish the change).
  The code is signed and verified first.

## What to check on a real Windows machine

1. A fresh install on Server 2022, Server 2025 and Windows 11:
   - the service runs as `NT SERVICE\SentinelAgent`;
   - the agent appears in Sentinel;
   - a scan completes.
2. The agent can't write its config or code folders, and SYSTEM's task runs every 5 minutes.
3. **Update to x.y.z** from Sentinel installs, and a broken release rolls back.
4. A release key offer is pinned, and a rotation is followed.
5. `-Upgrade` and `-Uninstall` work.
6. `whoami /priv`, run inside the service, shows only SeChangeNotifyPrivilege and SeCreateGlobalPrivilege. Test that
   the service account can't get its default privileges back by registering a scheduled task as itself (known for
   LOCAL SERVICE; check `NT SERVICE\SentinelAgent`).
7. `sc.exe config ... obj= "NT SERVICE\SentinelAgent"` works without a password on PowerShell 5.1 and 7.
8. A rename of `app\` while the update task runs from the launcher succeeds.
9. PHP's `realpath` resolves a junction or mount point on the state folder, so the task refuses it.

**Agents installed with 1.26.0:** run `install-agent.ps1 -Upgrade` once. Their update task runs from inside the code
folder, so it can't swap it, and they don't yet have the launcher or the privilege limits.
