# On-premises agent (internal scans)

The agent is a small Linux appliance at a client's site (or, as a preview, a Windows machine: see
[windows-agent.md](windows-agent.md)). It finds the devices on the internal network, their open
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
  limit (the same rules as external scans). The agent runs as its own user (`sentinel-agent`) in a locked-down
  systemd service with one capability: `CAP_NET_BIND_SERVICE`, to listen on UDP 137 for NetBIOS name requests (it
  never answers them). No raw sockets.
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
   The page after it has everything for the install: the code with a copy button, the commands with your Sentinel
   address filled in (`app.public_url`), how to check the result, and troubleshooting. It also warns when the site
   has no internal authorisation valid today (the agent would enrol but not scan).
3. Prepare the appliance: a mini-PC or VM that stays on, Debian 13 (or Debian 12 / Ubuntu 24.04 LTS), 64-bit; 2 CPU
   cores, 2 GB memory and 20 GB disk are plenty. It must sit on the internal network it scans (a VM needs a bridged
   adapter / external virtual switch, not NAT), ideally with a fixed address or DHCP reservation, and reach Sentinel
   over outbound HTTPS (443) plus the package mirrors (and GitHub for the one-line install). Nothing inbound.

   Either use the one-line install, which asks for the code (and the Sentinel address, unless given):

   ```sh
   curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install-agent.sh | sudo SENTINEL_SERVER=https://sentinel.msp.example bash
   ```

   With a private CA, add `SENTINEL_CA=/path/ca.pem` after `sudo`.

   (upgrade later with `sudo msp-sentinel-agent-update`), or copy and unpack the Sentinel release archive and run:

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
- Files in `/var/lib/sentinel-agent` (the only folder the service may write): `state.json` (jobs already run),
  `agent-key.pem` (the agent's private key for sealed passwords; never leaves the appliance) and
  `directory-credential.json` (the Active Directory password, still sealed). Reinstalling creates a new key: set the
  directory password again afterwards (the Agents page says so).

## Managing agents from Sentinel (1.21)

After the one-time install with an enrolment code, these are set on the client's **Agents** page (admins):

- **Scan gentleness** per site, part of each signed job (the agent accepts only these three; nothing faster than
  `-T3` can be asked for):
  - *Very gentle*: nmap's polite timing (`-T2`) with one probe at a time and at most 10 per second. The slowest.
  - *Gentle* (default): `-T2 --max-rate 50`. `-T2` pauses between probes, so in practice about 2-3 probes a second.
  - *Faster*: nmap's normal timing (`-T3`, at most 200 per second): no pauses and probes in parallel, so many times
    the traffic of *Gentle*. Use it only for networks that can take it.
- **Check-in interval** per site: 30 seconds to 10 minutes (default 1 minute). "Scan now", Restart and Diagnostics
  wait for the next check-in between scans. Pausing and stopping are still quick: running scans check in every 30
  seconds whatever the interval.
- **Diagnostics** (what the agent reports about itself; compare key fingerprints on the appliance before trusting
  them): the agent sends a report at its next check-in: versions (agent, PHP, nmap, system), free disk and
  memory, load, uptime, results waiting to upload, the clock difference with Sentinel (jobs carry expiry times, so
  more than a couple of minutes matters), its key fingerprint and whether it holds a directory password. Never the
  token or the password.
- **Restart**: the agent exits at its next check-in between scans (after a running scan), and its service starts it
  again a minute later. A restart goes out on its own, so no scan is lost.
- Agents older than 1.21.0 ignore the gentleness setting, Restart and Diagnostics; the Agents page says so. Upgrade
  them once by hand.

## Moving agents to a new Sentinel address (1.23)

When Sentinel gets a new address (or a certificate from a private CA): Administration → System → **Move agents to a
new Sentinel address**. Enter the new `https://` address, for a private CA only its certificate (PEM), and **your
password** (moving every agent is too powerful for a stolen session alone).

- The move is stored as one setting encrypted and authenticated with the app key from the config file, so it can't
  be edited in the database directly. Only agents at version 1.23.1 or later are asked to move.
- At their next check-in between scans, agents get the new address, signed with Sentinel's key (each agent at most 5
  times per move, 10 minutes apart; scans go on in between).
- **Each agent first asks the new address to prove it is this Sentinel, without sending it anything secret** (not
  even its token): the new address must return a signature over a random challenge, the agent and *that address*,
  made with the server key the agent pinned at enrolment. Sentinel only signs for the address an admin set, so a host
  that relays the challenge to the real Sentinel gets no signature for its own address. A wrong address gets only the
  challenge; the System page shows "not moved" with the reason.
- The agent keeps the new address (and CA) in its state folder, written for this agent and pinned key only: its
  config file is read-only and never changes. It restarts onto the new address.
- **Probation:** in the first 24 hours after a move (until 20 good check-ins), 10 failed check-ins in a row (about
  10 minutes) or a refusal of its token at the new address send the agent back to its configured address, and it
  tells Sentinel there. After probation the move is permanent: an outage (or a refusal from a misrouted proxy) at the
  new address doesn't strand agents at an old one.
- **Recall:** while moved, an agent asks its configured (original) address every 6 hours which address to use (a signed
  answer). If the move was cancelled or changed, it goes back. So keep the old address working (or pointing at this
  Sentinel): it is how Sentinel can always reach its agents again.
- The System page lists each agent: moved, waiting, not moved (why), or needing version 1.23.1 first. When every agent
  has moved, press **Move complete**: no more agents are asked, and moved agents stay (recall keeps confirming the new
  address). **Cancel and recall agents** brings moved agents back to their original address within about 6 hours.
  Both need your password.
- Moves made by 1.23.0 agents are kept when they update.

Re-enrolling is never needed: the agent's token and pinned key stay valid, because it is the same Sentinel. If the
new address uses the same private CA as before, the agent uses its configured CA when none is given.

Limit: anyone who can sign in as an admin (password and second factor), or who can write to the database AND reach the
web interface (by resetting an admin's password), can set a move to a host they control. The new address still has
to prove itself for that address, and the backstop is recall: as long as the original address answers for this
Sentinel, cancelling the move brings agents back. Protect admin accounts, the database and the config file like the
rest of the server.

## Updates from Sentinel (1.22)

Agents can be updated from Sentinel: **Update to x.y.z** per agent and **Update all agents** on the client's Agents
page, or **Update all agents** under Administration → System. An agent updates at its next check-in between scans.

**It only installs code signed with your release key.** Sentinel can ask an agent to update, but its own keys can't
vouch for code. What that protects, and what it doesn't, is under "What the release key protects" below.

1. The agent downloads the release from Sentinel (client sites need no access to GitHub) and checks it against the
   release public key it pinned (`/etc/sentinel-agent/release-key.pub`, else the key pinned at enrolment in the
   root-owned `agent.json`; an update never changes it): the signature, that it is the version asked for and newer than its own, and every file's SHA-256.
2. It stages the files in its state folder and asks the root update helper (`sentinel-agent-update.path` starts
   `bin/agent-update-runner.php`) to install them. The agent itself can't change its code.
3. **Root never touches the agent's folder** (its user could plant symlinks there). The helper has the staged release
   read by a collector running as the agent's user, and checks everything again in memory: the signature with the
   pinned key, the version (x.y.z, newer than the installed one; an unreadable installed version is refused) and every
   file's hash. Only then does it write the files into a new root-owned folder.
4. **Pre-flight:** the new release's own self-check runs as the agent's user (PHP version and extensions). A release
   that needs something the appliance doesn't have isn't installed.
5. It puts the new folder in place (the previous one stays as `/opt/sentinel-agent.old`), writes the systemd units
   from the new release and restarts the agent. **If the agent doesn't stay running, the previous version is put back
   and restarted** (rollback): it must be running 20 and 50 seconds later without having restarted. An update stopped
   half-way (power cut between the two renames) is repaired by systemd before the agent or the helper starts (a
   root step in both units puts `/opt/sentinel-agent.old` back), so the agent comes back on its own (1.28).
6. The result goes to `/var/lib/sentinel-agent-update` (root-owned; the agent can read it, not change it) and the
   Agents page shows it: "Updated to x.y.z", or why it was refused. The agent cleans up its own staging folder.

An update request is handed out at most 3 times, 30 minutes apart, with scans going on in between. Without a result
it ends with "no result from the update helper" (is `sentinel-agent-update.path` running?), so a stuck helper never
stops an agent's scans. The helper runs in a hardened systemd service and stops after 5 starts in 10 minutes.

Agents older than 1.22.0 (no helper) must be upgraded once by hand (`agent-install.sh --upgrade`); agents from 1.24.0
get the release key from Sentinel.
New PHP extensions or system packages are not installed by a remote update; release notes will say when a release
needs a manual upgrade.

**The release key (Administration → System → Release key).** Everything happens in your browser; Sentinel never
holds the private key.

1. **Create release key** (once): type a key-file password twice and your Sentinel password. Your browser makes an
   Ed25519 key pair and downloads the private key as a file locked with that password (PBKDF2-SHA256, 600,000 rounds,
   AES-256-GCM). Only the public half goes to Sentinel. Keep the file and its password safe (a password manager or
   offline storage); you need both to sign releases. **The key does not expire.**
2. **Sign this version** (after each Sentinel update): Sentinel lists its own files with their SHA-256; you pick the
   key file and type its password; your browser checks the file is the release key Sentinel uses, signs, and sends
   only the signature. Agents can then be updated to that version.
   The page shows the manifest's SHA-256 and every file that will be signed: compare the hash with the one published
   in the release notes for that version (`bin/release-sign.php sign` prints it; both use the same file list). Only
   the release's own folders and file types are listed: files of other types or outside those folders (a backup, a
   dump) never are. A stray file of a release type inside a release folder (say `src/extra.php`) would be, which is
   one more reason to compare the hash and look over the list.
3. **Agents learn the public key from Sentinel, once**: new agents at enrolment (the installer prints its fingerprint:
   compare it with the System page); agents enrolled before (1.24.0 or later) at their next check-in, through the root
   update helper, which pins it only when the agent has no key yet. A pinned key never changes without its own
   signature. The System page lists agents that have no key yet.
4. **Rotate the key** (you still have the key file): pick the current key file and its password, and a new password.
   The current key signs a statement naming the new key; agents check it with the key they pinned and switch on their
   own, also when they were offline for several rotations (each step is signed by the key before; the last 20 are
   kept). A new key file downloads; sign the version again with it.
5. **Replace the key** (the key file or its password is lost): a new key without the old one's signature. Agents that
   pinned the old key keep refusing updates until given the new key by hand (shown on the System page):
   `sudo /opt/sentinel-agent/install/agent-install.sh --upgrade --release-key BASE64KEY`.

**If the key file leaks**, rotate at once (the leaked key signs the change, which is still you if you rotate first),
or replace it and give agents the new key by hand.

The key is stored on Sentinel authenticated with the app key (from `config/config.php`), so a database write without
that app key (SQL injection, a stolen database password) can't plant a key agents would trust. Two limits: someone who
also has the app key (it is in `config.php`, and in unencrypted backups) can, and putting back an older value of the
setting (or restoring an older backup) brings back the older key. Agents that pinned a newer key refuse it; agents
with no key yet would take it.

**What the release key protects, and what it doesn't.**

- An agent that has pinned a key installs only code signed with it. Someone who takes over Sentinel (or its database)
  can't change that key on the agent or get other code installed there, as long as they don't have your key file
  and its password.
- An agent with **no key yet** trusts the first key Sentinel gives it (at enrolment, or the offer to older agents).
  If Sentinel is taken over before then, that could be the attacker's key. Create the release key soon after
  installing Sentinel, and check the fingerprint the agent installer prints against the System page.
- **Signing and rotating happen in a page Sentinel serves.** If the Sentinel server itself were taken over, its
  page could be changed to copy your key file and password while you use them, or show you changed files to sign.
  Only sign and rotate on a Sentinel you just updated yourself, compare the manifest hash with the release notes,
  and if you think the server was compromised, don't use the key there: rebuild the server, then replace the key
  and give agents the new one by hand. The command line remains for maintainers who sign from their git repository instead:
`php bin/release-sign.php keygen --out ~/sentinel-release.key`, then `sign --key …` for each release
(release/agent-manifest.*); a Sentinel with a key created on the System page uses that key.

Limit: Sentinel chooses WHICH signed release an agent gets (only newer ones are accepted). A compromised Sentinel
can't install unsigned code, but it could offer an older signed release that is still newer than an agent's version.
Upgrade agents promptly so they stay on the latest release.

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

## Active Directory checks (1.20)

With a read-only domain account, the agent reads the directory during each full scan and reports what attackers look
for first. Nothing is changed in the directory, and nothing that could log in (no password hashes) is read.

**Setting it up** (admins, on the client's **Agents** page, per site):

1. Create an ordinary domain user for Sentinel (no admin rights; members of Domain Users can read everything the checks
   need), for example `svc-sentinel`.
2. Under **Active Directory checks**, enter the domain (`corp.example`), the domain controller's IP address (it must be
   inside the site's internal authorisation), the account (`svc-sentinel@corp.example` or `CORP\svc-sentinel`) and its
   password, and click **Save**.
3. At the next full scan the agent fetches the domain controller's certificate and stops: the page shows its
   fingerprint. Check it, and click **Trust this certificate**. From the next full scan the agent signs in and reads.

To change the password later, open **Change settings or replace the password**, type the new password and save: the
agent collects it within a minute and the page shows when it confirmed it. Leaving the password empty keeps the
current one. **Turn off** deletes the settings and the results, and the agent deletes the password.

**How the password is protected:**

- **Sentinel never has it.** The password field is never sent. Your browser encrypts the password to the site
  agent's own public key (ECDH P-256, HKDF-SHA256, AES-256-GCM, with Web Crypto) and sends only the sealed box, bound
  to that agent, a one-off number and the account name. Sentinel stores the box until the agent collects it (signed
  with Sentinel's key, like jobs), and deletes it when the agent confirms, or after 24 hours. Sentinel can't open it,
  and neither can its database or backups.
- **Only that agent can open it.** The private key is created on the appliance and never leaves it. The agent keeps
  the box sealed on disk and opens it in memory only for the sign-in. A box sealed for another agent, changed on the
  way, or replayed is refused, and the page says so.
- **Never to an untrusted server.** The agent signs in over LDAPS (TLS from the first byte), and only when the
  domain controller's certificate matches the fingerprint you trusted. A different certificate (a renewed one, or
  something pretending to be the domain controller) gets nothing until you trust it.
- **The agent's key is pinned.** The first key an agent reports is kept. If it later reports a different one
  (reinstalled, or someone with its token or database access trying to swap in their own), the Agents page shows the
  new fingerprint and nothing is sealed to it until an admin approves it. Compare it with
  `sentinel-agent.php status` on the appliance (it prints "Agent key fingerprint"). After approving, set the password
  again: the old one was sealed to the old key.
- **Revoked means wiped.** A revoked agent deletes its sealed password before it stops.
- **HTTPS needed.** Browsers only allow this encryption on HTTPS pages: open Sentinel through its `https://`
  address to set or replace the password.
- **Limit.** Someone who fully took over the Sentinel server could change the page to capture passwords typed in
  future, or trust a certificate of their own and point the agent at a machine they control inside the client's
  network. Passwords already held by agents stay sealed. Protect the server accordingly. On the appliance itself, the
  sealed password and the agent's private key sit side by side: someone with root on the appliance (or its disk) can
  open it. Protect the appliance like any server that holds a credential.

**What is graded** (Balanced):

- **Fail:** accounts that don't require Kerberos pre-authentication (AS-REP roasting: crackable offline without any
  password); admin accounts with a service name (Kerberoasting); computers other than domain controllers trusted for
  unconstrained delegation; devices heard sending LLMNR/NetBIOS name requests (see below).
- **Warning:** other accounts with a service name; more than 5 Domain Admins; admin passwords that never expire; a
  krbtgt password older than a year; computers in use without LAPS (or LAPS not used at all); LDAP signing not
  required; admin accounts unused for 90 days.

Each finding lists up to 25 account or computer names (the agent sends up to 200 and the count). Disabled accounts
and computers that haven't signed in for 90 days are left out. "Admin" means `adminCount` set (protected groups) or
a direct member of Domain Admins.

Domain Admins is found by its well-known SID, so localised names work, and members through their primary group
count too.

**Not covered (yet):** only the one domain controller entered is checked for LDAP signing; LDAPS channel binding is
not checked; unconstrained delegation on user accounts is not checked; "admin" follows `adminCount`, so an account
that left the admin groups but still has `adminCount` set counts as an admin; Windows LAPS that stores passwords only
in Entra ID writes nothing to Active Directory, so those computers show as without LAPS.

*LDAP signing* is checked on the plain LDAP port (389) with a made-up account and a random password: a domain
controller that requires signing refuses before it looks at the account. The real password is never sent there.

A read that fails (wrong password, certificate changed, domain controller down) keeps the earlier results: no answer
is not evidence of a fix. The error shows on the Agents page.

## Name poisoning (LLMNR / NetBIOS)

During each full scan the agent listens for 2 minutes for LLMNR (UDP 5355) and NetBIOS name service (UDP 137)
requests (broadcast NetBIOS name queries only: node-status queries from inventory tools don't count, and neither does
the appliance itself). Devices that send them fall back to these protocols when DNS has no answer, so a poisoning tool (Responder
and the like) on the network could answer instead and capture their users' password hashes. The agent only listens:
it never answers or sends anything. Devices heard (inside the site's authorisation only) become one Fail finding,
with their names when the agent knows them. Devices only send these now and then, so the finding closes after three
quiet listens in a row. It works without the Active Directory checks.
