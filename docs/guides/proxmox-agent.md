# Run an agent on Proxmox

Run the on-premises agent in a Proxmox VE container (LXC) on the client's network. It is a normal agent install inside
a small Debian 13 container, so it updates from Sentinel like any appliance agent. (A Proxmox VM works too: install
Debian 13 in it and follow the [agent guide](agents.md).)

## Before you start

- A Proxmox VE host with a bridge on the client's network (and the VLAN tag, if the network is a VLAN).
- In Sentinel: the client's **Agents** page, with the site's **internal authorisation** recorded.

## Set it up

1. **Create the container.** Either use the helper on the Proxmox host (as root):

   ```sh
   bash proxmox-agent-ct.sh --bridge vmbr0 --vlan 20            # DHCP
   bash proxmox-agent-ct.sh --bridge vmbr0 --ip 10.0.20.50/24 --gw 10.0.20.1
   ```

   (`install/proxmox-agent-ct.sh` in the release; `--dry-run` shows what it would do.) It downloads Proxmox's Debian 13
   template if needed and creates an **unprivileged** container with **nesting** on, 1 core, 1 GB RAM, 8 GB disk,
   started at boot.

   Or create it yourself in the Proxmox web UI: Debian 13 template, **Unprivileged container** ticked, **Nesting**
   ticked (Options → Features), network on the client's bridge and VLAN.
2. In Sentinel, click **Create an enrolment code** for the site.
3. On the Proxmox host: `pct enter <CTID>`. Inside the container: `apt-get update && apt-get install -y curl`, then
   paste the install command from the enrolment page and enter the code when asked.
4. The agent shows as **Online** on the Agents page, with an **LXC** badge.

## Good to know

- **Nesting keeps the full hardening.** The agent's service uses systemd's sandbox, which needs nesting in an
  unprivileged container. The installer checks: without it, it relaxes only the sandbox options, warns you, and tells
  you to run `pct set <CTID> --features nesting=1`, restart the container and run the installer with `--upgrade` again.
- **Updates** come from Sentinel as for any agent (**Update to x.y.z** on the Agents page).
- **Unprivileged containers only.** The agent doesn't need a privileged container; don't give it one.
- Scanning works through the container's network card on the bridge, so the container must be on the network (or VLAN)
  you want scanned.
