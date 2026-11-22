# On-premises agent (internal scans)

The agent is a small Linux appliance at a client's site. It finds the devices on the internal network, their open
services and versions, certificates and web pages, and reports them to Sentinel, which turns them into findings
(vulnerable services, certificate problems) and new-device alerts.

## How it stays safe

- **Outbound only.** The agent connects out to Sentinel over HTTPS. Nothing at the site needs an inbound firewall
  rule, and Sentinel never connects to the agent.
- **Approved networks only.** An admin records an *internal authorisation* for the site: who at the client approved
  scanning, the dates, and exactly which internal networks (private addresses only, each at most a /16, at most four
  /16 in total). Sentinel signs it with a key derived from the config file's app key, which is not in the database.
- **Signed jobs.** Every job carries the signed authorisation and is itself signed. The agent pinned Sentinel's key
  when it enrolled and runs a job only if both signatures check out, the job is for this agent, has not run before,
  has not expired, the authorisation is valid today, and every target is inside the signed networks. So someone who
  could change Sentinel's database but not its config file still can't make an agent scan anything else.
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
pages) and a **light sweep** daily (which devices are on the network, for new-device alerts). Admins can start a full
scan at any time with *Scan now* and a reason. The first full scan of a site is the baseline: it records the devices
without alerting. After that, devices never seen before are announced, unless NinjaOne already knows them (same
address or name). Devices that no full scan has seen for 30 days are marked as removed.

## Install

1. On the client page, under **On-premises agents**, record an internal authorisation for the site.
2. Click **Create an enrolment code** (admins). The code is shown once and works once, within 24 hours.
3. On the appliance (Ubuntu 24.04 or Debian 12, a mini-PC or VM with a network interface on the internal network),
   copy and unpack the Sentinel release archive, then run:

   ```sh
   sudo ./install/agent-install.sh --server https://sentinel.msp.example --code SNE-XXXXX-XXXXX-XXXXX-XXXXX
   ```

   Add `--ca /path/ca.pem` if Sentinel uses a certificate from a private CA. `--dry-run` shows every step first.
4. The agent appears on the client page within a minute.

Upgrade: unpack the new release on the appliance and run `sudo ./install/agent-install.sh --upgrade` (the enrolment
is kept). Remove: `sudo ./install/agent-install.sh --uninstall`, and revoke the agent on the client page.

## Operations

- Logs: `journalctl -u sentinel-agent`. Status: `sudo -u sentinel-agent php8.4 /opt/sentinel-agent/bin/sentinel-agent.php status --config /etc/sentinel-agent/agent.json`.
- An agent that was revoked stops and is not restarted by systemd.
- If a job is refused, the log says why (for example "targets outside the signed authorisation" or "job expired").
  Check the internal authorisation's dates and networks, and the appliance's clock.
- The agent's clock should be correct (NTP): jobs carry an expiry time.

## What is graded

- Known vulnerabilities in the services the agent finds, matched like external services. Service banners from Linux
  distribution builds are never "confirmed" (the fix may be backported).
- Certificates: expired, still accepting TLS 1.0/1.1, or a weak key. Self-signed certificates and name mismatches
  are normal on internal devices and are not findings.
- Version 2.1 adds risky internal protocols (SMBv1, SMB signing off, default SNMP communities, RDP without NLA,
  cleartext Telnet and FTP).
