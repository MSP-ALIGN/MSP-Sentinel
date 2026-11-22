# On-premises agent (internal scans)

The agent is a small Linux appliance at a client's site. It finds the devices on the internal network, their open
services and versions, certificates and web pages, and reports them to Sentinel, which turns them into findings
(vulnerable services, certificate problems) and new-device alerts.

## How it stays safe

- **Outbound only.** The agent connects out to Sentinel over HTTPS. Nothing at the site needs an inbound firewall
  rule, and Sentinel never connects to the agent.
- **Approved networks only.** An admin records an *internal authorisation* for the site: who at the client approved
  scanning, the dates, and exactly which internal networks (private addresses only: 10.x, 172.16-31.x, 192.168.x and
  IPv6 fc00::/7; each at most a /16, at most four /16 in total). Sentinel signs it with a key derived from the config
  file's app key, which is not in the database.
- **Signed jobs.** Every job carries the signed authorisation and is itself signed. When it enrolled, the agent pinned
  Sentinel's key and the site and client it belongs to. It runs a job only if both signatures check out, the job is
  for this agent, site and client, has not run before, has not expired, the authorisation is valid today, and every
  target is inside the signed networks. So someone who could change Sentinel's database but not its config file can't
  make an agent scan networks that were never approved for its site.
- **Limit: revoking.** Revoking an authorisation is recorded in the database (not signed): it stops new jobs and
  running scans, and their results are ignored. Someone who can change the database could undo a revocation, and the
  agent would again accept jobs for those (once approved) networks until the authorisation's end date. Keep end dates
  short, protect the database like the rest of the server, and revoke the agent too if you need to be sure.
- **Results checked again.** Sentinel ignores reported devices outside the authorisation.
- **No remote control.** The agent runs scans and returns results. It never runs commands it receives, and it has
  no shell access for anyone.
- **Gentle and unprivileged.** Discovery and port scans are TCP connect scans with nmap at slow timing and a rate
  limit (the same rules as external scans). The agent runs as its own user (`sentinel-agent`) with no extra
  capabilities in a locked-down systemd service.
- **Kill switch.** *Pause* on the site (technicians and admins) stops running agent scans at the agent's next
  check-in, within a minute. The global kill switch and pausing the client do the same.
- **Revocable.** Revoking the agent on the client page makes its token stop working immediately.

## Schedule

Inside the client's scan window: a **full scan** weekly (discovery, ports, service versions, certificates and start
pages) and a **light sweep** daily (which devices are on the network, for new-device alerts). Scheduled scans start
only inside the window and stop when it closes; an unfinished full scan continues with the devices it didn't reach in
the next window. Admins can start a full scan at any time with *Scan now* and a reason (not limited to the window).
The first full scan of a site is the baseline: it records the devices without alerting. After that, devices never
seen before are announced, unless NinjaOne already reports their address. A device keeps its identity by MAC address
when the agent can see it (same network segment), so an address change from DHCP is not a new device. Devices whose
ports no completed scan has checked for 30 days are marked as removed.

While a job runs, the agent checks in every 30 seconds; if it stops checking in for an hour the job expires. Finished
results are kept on the appliance and sent again until Sentinel accepts them.

## Install

1. On the client page, under **On-premises agents**, record an internal authorisation for the site.
2. Click **Create an enrolment code** (admins). The code is shown once and works once, within 24 hours.
3. On the appliance (Ubuntu 24.04 or Debian 12, a mini-PC or VM with a network interface on the internal network),
   copy and unpack the Sentinel release archive, then run:

   ```sh
   sudo ./install/agent-install.sh --server https://sentinel.msp.example
   ```

   It asks for the code (so it stays out of the shell history and the process list); `--code` also works. Add
   `--ca /path/ca.pem` if Sentinel uses a certificate from a private CA. `--dry-run` shows every step first.

   The config (`/etc/sentinel-agent/agent.json`, with the token and the pinned key, site and client) belongs to root and
   is only readable by the agent; only `/var/lib/sentinel-agent` (job history, results waiting to be sent) is writable.
4. The agent appears on the client page within a minute.

Upgrade: unpack the new release on the appliance and run `sudo ./install/agent-install.sh --upgrade` (the enrolment
is kept). Remove: `sudo ./install/agent-install.sh --uninstall`, and revoke the agent on the client page.

## Operations

- Logs: `journalctl -u sentinel-agent`. Status: `sudo -u sentinel-agent php8.4 /opt/sentinel-agent/bin/sentinel-agent.php status --config /etc/sentinel-agent/agent.json`.
- Updates: the agent does not update itself. Unpack a new release on the appliance and run the installer with
  `--upgrade`.
- An agent that was revoked stops and is not restarted by systemd.
- If a job is refused, the log says why (for example "targets outside the signed authorisation" or "job expired").
  Check the internal authorisation's dates and networks, and the appliance's clock.
- The agent's clock should be correct (NTP): jobs carry an expiry time.

## What is graded

- Known vulnerabilities in the services the agent finds, matched like external services. Service banners from Linux
  distribution builds are never "confirmed" (the fix may be backported).
- Certificates: expired, still accepting TLS 1.0/1.1, or a weak key. Self-signed certificates and name mismatches
  are normal on internal devices and are not findings.
- Risky internal protocols (1.7), checked read-only on each device of a full scan:
  - **Fail:** SMBv1 enabled; Telnet open; SNMP answering the default "private" community (usually read-write).
  - **Warning:** SMB signing not required; Remote Desktop without Network Level Authentication; FTP open; SNMP
    answering "public"; a login page served over plain HTTP.

  How: SMB offers only the old SMBv1 dialect, then reads whether signing is required in a normal negotiation (no
  session, no login). RDP asks for TLS without NLA and reads the server's answer (no login). SNMP sends one read of
  the system description with "public" and "private" (SNMPv2c, and SNMPv1 if there was no answer) to UDP 161, which
  is listed in the signed job: this is trying a well-known default credential, read only. Telnet and FTP are judged
  by the service nmap identifies, on any port.

  A check that can't decide is never a finding, and it doesn't erase an earlier answer either: a device that was
  briefly unreachable keeps its findings until a check answers again.
