# On-premises agents

Scan inside a client's network with a small agent at their site, keep it up to date, and turn on Active Directory
checks. The full detail (safety model, schedule, updates, release key, grading) is in the
[agent reference](../agent.md); the Windows version is in [windows-agent.md](../windows-agent.md).


The agent also runs [in Docker](docker-agent.md) (a container on a Linux Docker host) and [on Proxmox](proxmox-agent.md)
(an LXC container); Windows has its own [installer](../windows-agent.md).

## Before you start

- You need the **admin** role.
- Prepare a machine at the site that stays on: a mini-PC or VM with Debian 13 (or Debian 12 / Ubuntu 24.04), 2 CPU
  cores, 2 GB memory, 20 GB disk. It must sit on the network it scans (a VM needs a bridged adapter, not NAT) and
  reach Sentinel over outbound HTTPS. Nothing inbound is needed.
- Each client has a **Default** site. Add more sites on the client's **Overview** (Sites card) if it has several offices.

## Add an agent

1. **Record the internal authorisation first.** On the client's **Agents** page, click **Record a new internal
   authorisation** for the site: who at the client approved internal scanning, the dates, and the private networks
   (for example `10.20.0.0/24`; each at most a /16). The enrolment button only appears once the site has one.
2. Click **Create an enrolment code** for the site. The code is shown once and works once, within 24 hours.
3. The next page shows the install command for your Sentinel address with a copy button. Run it on the machine at
   the site, for example:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install-agent.sh | sudo SENTINEL_SERVER=https://sentinel.msp.example bash
   ```

   Type the code when asked.
4. **Check it worked.** The agent appears on the Agents page within a minute. On the machine,
   `journalctl -u sentinel-agent` shows its log.

After that the agent runs a full scan weekly and a light sweep daily, inside the client's scan window. Admins can
press **Scan now** for the site, with a reason. Internal devices and their findings show on the client's **Devices**
page.

## Update agents

1. On the client's **Agents** page, click **Update to x.y.z** for one agent, or **Update all agents**. Or update every
   client's agents at once under **Administration → System**.
2. Each agent updates at its next check-in between scans and only installs code signed with your release key. Create
   the release key once under **Administration → System → Release key**, and **Sign this version** after each
   Sentinel update. Signing asks for the **expected manifest SHA-256**: copy it from the release notes
   (`AGENT-MANIFEST-SHA256`) or compute it on your own computer with `php bin/release-sign.php hash --ref vX.Y.Z`.
   Your browser signs only if it matches. See [the agent reference](../agent.md#updates-from-sentinel-122).
3. The Agents page shows "Updated to x.y.z", or why it was refused. If the new version doesn't stay running, the
   agent goes back to the previous one by itself.
4. The root update helper runs from a frozen copy that remote updates never change, so a new release never runs as
   root (or SYSTEM on Windows). When a release changes the helper or the services, its notes ask for a one-off manual
   upgrade (`agent-install.sh --upgrade`, or `install-agent.ps1 -Upgrade` on Windows).

## Turn on Active Directory checks

1. Create an ordinary domain user for Sentinel (no admin rights), for example `svc-sentinel`.
2. On the **Agents** page, under **Active Directory checks** for the site, enter the domain (`corp.example`), the
   domain controller's IP address (inside the site's internal authorisation), the account and its password. Save.
   Open Sentinel through its `https://` address: your browser seals the password for that agent, so Sentinel never
   sees it.
3. At the next full scan the agent fetches the domain controller's certificate. Check the fingerprint shown and click
   **Trust this certificate**. From the next full scan, the agent signs in and reads the directory.

The agent **remembers the domain controller address it first signed in to** for that domain, in `dc-pins.json` in
its state folder (on Linux `/var/lib/sentinel-agent/dc-pins.json`). It won't send the password to any other address,
even if Sentinel asks. If the domain controller really moves, someone on the agent machine deletes that file; the
agent then pins the new address at its next sign-in.

## Good to know

- **Pause** on the site stops agent scans within a minute. **Revoke** stops an agent's token at once.
- Agents only connect out, scan only the networks in the signed internal authorisation, and never run commands they
  receive.
- Under **Administration → System**, **Move agents** moves every agent to a new Sentinel address.
- Scan gentleness, check-in interval, **Diagnostics** and **Restart** are set per site on the Agents page.
- A failed directory read (wrong password, changed certificate) keeps the earlier results and shows the error.
