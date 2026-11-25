# Changelog

All notable changes, newest first. Versions follow semantic versioning: `x.Y.0` adds features, `x.y.Z` only fixes.

### 1.57.2 (2026-11-25): Device names and CVE versions

- **No more "localhost" devices.** Some machines (often a NAS, or a Linux box whose own name maps to localhost) answer
  the agent with "localhost". That is no longer used as the device's name: the device, and its findings, show its
  address instead. Devices already named "localhost" are renamed on upgrade.
- **The version the CVEs are for.** Vulnerability findings for internal devices put the installed version in the
  title (for example "Samba smbd 4.6.2 (port 139): 25 known CVE(s)") and start their details with "Installed version:
  4.6.2", saying whether the CVEs are confirmed for that version, a distribution build that may be backported, or
  possible because no version was reported.

### 1.57.1 (2026-11-25): Fixes from review

- **Sonar dots never overlap.** Clients are spaced evenly around the scope and staggered across their band, so many
  clients with the same score (every Good client, or many at 100) no longer pile on top of each other. A dot only
  moves when a client is added or removed.
- **Smooth refresh.** The once-a-minute dashboard refresh no longer makes the sweep jump back to the top.
- Dots ping as the sweep reaches them, not just before; the sweep line shows clearly in the light theme; band labels
  no longer sit under a dot.
- The dots are a mouse shortcut and stay out of the keyboard's tab order; the client risk grid beside the sonar
  links every client.

### 1.57.0 (2026-11-25): Threat level sonar

- **The main dashboard's threat level is now a sonar.** Every client is a dot in the band of its level: a red core
  for clients at risk, amber for needs attention and a green rim for good. Within its band, the higher a client's
  score, the closer it sits to the center, and each client keeps its place between refreshes. The center shows the
  highest client's score.
- **Hover a dot** for the client's name, level and score; **click it** to open the client.
- The sweep turns like the logo's radar and dots ping as it passes; nothing moves for people whose system asks for
  reduced motion. Up to 60 clients are drawn (worst first). Client pages keep their own gauge.

### 1.56.3 (2026-11-25): Fixes from review

- The Windows installer's check that the newly installed nmap runs never stops the install by mistake; it falls back
  to nmap's setup window instead.
- With no one at the screen (an RMM tool), the silent nmap attempt waits at most 2 minutes, and the message says
  whether nmap is missing or installed but not working.
- Stopping a stuck nmap setup only stops processes that setup started.

### 1.56.2 (2026-11-25): Silent nmap install on Windows where it can work

- **The Windows agent installer tries a silent nmap install first.** nmap itself installs silently; only the free
  edition's bundled Npcap waits for a click. So on a machine that already has Npcap (for example from Wireshark),
  the whole install is unattended again. Where the silent install can't finish within 5 minutes, it is stopped and
  the installer falls back to nmap's setup window as before (or, with no one at the screen, stops with a clear
  message).

### 1.56.1 (2026-11-25): Fixes from review

- Correcting the ITFlow ticket template retries tickets that failed on it at the next run, instead of up to a day
  later.
- The priority setting says plainly that a fixed priority applies to known-exploited findings too.

### 1.56.0 (2026-11-25): ITFlow ticket priority and category

- **One priority for every ticket.** Under **Integrations → ITFlow**, choose **Priority for Sentinel tickets**:
  *Automatic* (as before: High, Urgent when known exploited, Medium for the weekly ticket) or Low, Medium, High or
  Urgent for every ticket. ITFlow sets a ticket's SLA from its priority, so choosing a priority without an SLA keeps
  SLAs off Sentinel's tickets.
- **Category through a ticket template.** ITFlow's API can't set a category directly, so enter the number of an
  ITFlow ticket template that has the category you want. New tickets get its category (and any tags, tasks and due
  time); Sentinel's subject, details and priority are kept. A template ITFlow refuses is reported on the finding and
  retried later.

### 1.55.2 (2026-11-25): Clearer update check

- **Check now says what happened.** Instead of one message for every case ("did not get an answer"), it now says
  whether GitHub has no published release yet (or the repository is private), whether the server couldn't reach
  GitHub at all, or that the check is off. Servers installed from a branch are told how far behind their branch they
  are.

### 1.55.1 (2026-11-25): Fixes from review

- When a ticket closed in ITFlow is replaced and the new ticket can't be opened yet, the targets moving to it no longer
  keep the old ticket's ID in the new text field.
- The ticketing-layer tests no longer depend on which tests ran before them.

### 1.55.0 (2026-11-25): Tickets ready for other ticketing systems

Nothing changes in how ITFlow works.

- **Each ticket knows its system.** Every ticket Sentinel follows now records which ticketing system it belongs to,
  and its ID there as text, so systems with text ticket IDs fit. Existing tickets are filled in on upgrade.
- **Neutral ticket settings.** "Open tickets for findings", "since when" and the weekly Warnings ticket, and the last
  run's result, are stored under names that don't depend on ITFlow. Your current choices are copied over on upgrade.

### 1.54.1 (2026-11-25): Fixes from review

- **ITFlow sync keeps going.** When an ITFlow client is already linked to another Sentinel client (for example a demo
  client), the sync counts it as a conflict and carries on with the rest, instead of stopping.
- **The client form never fails on a taken ITFlow ID.** It says "already in use", also when the ID was linked elsewhere
  at the same moment.
- **Old duplicates.** On an install where two clients shared one ITFlow ID, the upgrade keeps the link on the older
  client, logs the other, and that client's Edit page shows "already in use" until the duplicate is cleared.
- Linking a client to ITFlow by name and "tickets only from now on" are saved together, so a broken run can never
  open tickets for old findings.

### 1.54.0 (2026-11-25): Client links ready for other ticketing systems

Nothing changes in how ITFlow works.

- **Client links in their own table.** The link between a Sentinel client and its client in the ticketing system now
  lives in one place that also fits systems with text IDs. Existing ITFlow links are copied over on upgrade. The ticket
  rules and the client sync read it from there.
- **Nothing breaks.** The ITFlow client ID on each client stays and is kept in step, so the REST API
  (`itflow_client_id`), MSP Align matching and the client form work as before. A ticketing-system client can still be
  linked to only one Sentinel client.

### 1.53.1 (2026-11-25): Fixes from review

- When a ticketing system can't look a ticket up after an unclear answer, the "check for a duplicate" warning is also
  in the finding's history, where technicians see it. (ITFlow can look tickets up, so this doesn't affect it.)
- The ITFlow connection is read once per run; tests of the ticketing layer no longer touch other clients.

### 1.53.0 (2026-11-25): Ready for more ticketing systems

The next step towards working with ticketing systems besides ITFlow. Nothing changes in how ITFlow works.

- **One ticketing layer.** Opening, following, resolving and reopening tickets, and the client sync, now go through a
  general ticketing layer, with ITFlow as its first system. Another PSA can be added later without touching the ticket
  rules (one ticket per issue, two-way status, rechecks, the weekly Warnings ticket).
- **Adapts to what a PSA can do.** A PSA that can reopen closed tickets gets them reopened instead of replaced. One
  that can't look a ticket up again after an unclear answer gets it opened again, with a note to check for a
  duplicate. ITFlow keeps its current behavior on both.
- Service boards and the client tag filter are used only with PSAs that have them.

### 1.52.1 (2026-11-25): Fixes from review

- A client linked to an RMM that is later turned off is never stuck: the Devices page still shows that link, and it
  can be unlinked. Links to an RMM Sentinel no longer supports never block a client.
- Two admins linking the same client to two RMMs at the same moment can't both succeed.
- Small safeguards for adding RMMs later (setting names, removing saved secrets).

### 1.52.0 (2026-11-25): Ready for more RMMs

The first step towards working with other RMMs and ticketing systems besides NinjaOne and ITFlow. Nothing changes in
how NinjaOne works.

- **One list of RMMs.** Each RMM Sentinel can connect to is described in one place: its settings, how they are
  checked, its setup steps and how to connect. The Integrations page draws its card, and saves and tests it, from that
  description, so adding another RMM later needs no new pages. NinjaOne keeps the same settings, address and audit
  entries.
- **One RMM per client.** A client is linked to one RMM at a time, so the same machines never come in twice with
  duplicate findings. Linking a client already linked elsewhere is refused with the reason.
- The Administration overview names the connected RMMs, and a client's Devices page no longer assumes NinjaOne.

### 1.51.1 (2026-11-25): Fixes from review

- The Getting started checklist can only be hidden by someone who sees every client, like other organization-wide
  settings.
- Links and bookmarks to the three help topics renamed in 1.51.0 still land on them.
- The Authorizations page loads only what it shows, and the dashboard checks the checklist once per page.

### 1.51.0 (2026-11-25): Easier to find your way, one vocabulary, US spelling

- **Main pages stay in reach.** Inside a client, the menu keeps Dashboard, All clients, All findings and Help.
  Finding and report pages keep their client's menu.
- **One name per page.** Each client page's heading is its section, with the client's name above it, and the browser
  tab reads "Client · Section". Menu labels match the headings ("Scans and ports", "Certificates and web pages",
  "Website and email"); Discovery sits next to Authorizations.
- **Getting started checklist** on the dashboard for whoever manages settings: time zone, a second admin, alerts,
  the first client, its authorization and the first scan, ticked off from what Sentinel already holds. One click hides
  it for everyone.
- **Scan now on the client's Overview**, where the help always said it was. The Authorizations page also lists each
  site's internal authorization, and the authorization form explains Change scope / renew.
- **Administration**: one entry in the user menu; the overview has a Roles card and complete descriptions; the API
  page has an API reference button. The engagements list can start a new engagement for a chosen client.
- **One vocabulary**: "finding", "agent host", "two-factor authentication", "Pen-test engagements", "Time zone";
  every Save button says what it saves, and new records use "Add". Text no longer assumes "an admin" where a role
  permission decides.
- **US spelling** throughout the interface, help and docs (authorization, organization, enrollment, canceled).
  Web addresses, API fields and settings keep their names, so links, bookmarks and integrations keep working. The
  agent accepts `enroll` as well as `enrol`.

### 1.50.1 (2026-11-25): Fixes from review

- **Safer device matching.** A MAC several agent devices share (a router or VPN server answering for others) no longer
  joins them all to one NinjaOne device. A real MAC the NinjaOne device doesn't list rules it out, a name only
  matches a device NinjaOne saw in the last day, and an address range two sites use stays ambiguous after one site's
  authorisation lapses.
- **Certificate findings keep their decisions.** The upgrade moves the evidence to the new form too, so false
  positives and accepted findings don't reopen. Where an endpoint had both an old "expired" and an "expires soon"
  finding, the open one is kept, and an open one combined into another closes with an honest ticket note instead of
  "Verified fixed".
- **An accepted Warning that becomes a Fail opens again** (an accepted "expires soon" certificate that expires), with
  a Fail deadline from that day.
- **Archived clients' tickets**: only open tickets get the note; a note ITFlow refuses no longer retries every run.
- NinjaOne MAC addresses are read only in their usual written forms; multicast and broadcast addresses are dropped.

### 1.50.0 (2026-11-25): The right device, one certificate finding, tidy tickets

- **Matching agents to NinjaOne devices.** Sentinel now uses the strongest evidence first: the network card's MAC
  address (NinjaOne's MACs now come over), then the address, then the name. An address only counts when the NinjaOne
  device was seen in the last day and only one site's networks cover it, so two clients both on 192.168.1.x, or a
  stale address, never join the wrong machines. A machine an agent saw without a name can still be matched by MAC.
- **Routers and firewalls.** A MAC that answers on several addresses is no longer used to tell devices apart, so
  each address stays its own device instead of overwriting one record.
- **One certificate finding.** A certificate that expires soon and then expires is the same finding: it moves from
  Warning to Fail and keeps its owner, history and ticket, instead of closing as "fixed" and opening a new one.
  Existing findings are moved to the new form on upgrade.
- **Archived clients' tickets.** When a client is archived in Sentinel, each of its open ITFlow tickets gets one note
  saying it is no longer followed. If the client is restored while a problem is still open, a new ticket is opened.

### 1.49.1 (2026-11-25): Fixes from review

- **Platform limits only for real operating systems.** NVD labels such as "node.js" or "WordPress", and other
  vendors' "IOS", no longer hide CVEs; Linux distributions (Debian, Ubuntu, Red Hat) count as Linux; NVD's "not on
  this platform" is never read as "only on it"; a CVE listed without a limit by any NVD answer keeps no limit.
  "Cisco IOS XE" is no longer read as macOS, and iPadOS counts as iOS.
- **Private MAC addresses.** Phones and laptops that rotate private MACs are recognised by their address, so each
  rotation isn't a new device and a new-device alert.
- **Gentler refresh.** The one-off refresh of cached vulnerability data (for platform limits) takes at most 50
  products per run, after the regular work, so a feeds run never stalls on it.
- **Clearer tickets.** Ticket history no longer says "confirmed fixed" when Sentinel stopped tracking a problem
  without a fix, and a ticket left open that way says "seen again" when the problem returns.
- **First sync as usual.** A newly linked source alerts and opens tickets normally from its first sync (the planned
  first-import summary was dropped: you're setting the client up and expect that data).
- A program list without any usable entry no longer clears a device's software; a re-link that loses a race says
  so plainly; the "alerts paused" notice says where the rest are.

### 1.49.0 (2026-11-25): Accurate data, calmer alerts and tickets

From a full review of how devices, findings, alerts and tickets fit together.

- **CVEs for the right platform.** NVD limits some CVEs to an operating system (for example Chrome "running on"
  Android or macOS). These are now reported only on devices running it, and never as confirmed when the OS is
  unknown. This removes many of the extra CVEs a NinjaOne connection brought onto Windows PCs. Cached NVD answers are
  fetched again in the background to pick this up.
- **Unknown is not fixed.** A device NinjaOne says nothing about in a sync (offline, or a report came back empty)
  keeps its last known antivirus, encryption and software, so its findings no longer close and reopen with a new
  due date, alert and ticket. An empty antivirus report never marks every PC as having no antivirus.
- **The right device.** An address DHCP gives to a different machine no longer carries over the old device's record,
  name and findings. Re-linking a client to another NinjaOne organisation retires the old organisation's devices.
- **No floods.** One run sends at most 60 immediate Fail alerts across clients (for example after new vulnerability
  data), then one notice. Linking a client to ITFlow, or restoring it, no longer opens tickets for months of old
  findings.
- **Honest tickets.** When Sentinel stops tracking a problem without seeing it fixed (device gone, source unlinked),
  the ticket gets a note saying so and stays open, instead of "Verified fixed". A ticket interrupted before it was
  opened is retried instead of blocking. Breached email addresses are masked in tickets, as in alerts.

### 1.48.1 (2026-11-24): Time zone fixes from review

- **Everything in your time.** The activity feeds on the dashboard and client overview, the certificate "Checked"
  times, and the dates in reports (first seen, fixed, decided) now use your time zone, or the client's in reports,
  like the rest.
- **The button says what it does.** After a Settings save that failed (for example a bad source address), the "move
  clients still on UTC" button named the time zone just typed, but moved clients to the saved one. It now names the
  saved one.
- Time zone names that PHP knows by an older alias are accepted, and stored times in ISO format are shown converted.

### 1.48.0 (2026-11-24): Times in your time zone

- **Your time, everywhere.** Under **Administration → Settings → General**, choose your time zone (for example
  America/Los_Angeles). Every time in Sentinel (scans, findings, notifications, the audit log, agents, integrations)
  is then shown in it and labelled, for example `2026-11-24 13:33 PST`. Each user can pick their own under **My
  profile → Time zone**.
- **New clients start in it,** also those added from ITFlow. Clients still on UTC are listed on the Settings page,
  with a button that moves them to your time zone (their scan window times stay the same numbers, now read as local
  time). It's audited.
- **Reports** show times in their client's time zone, labelled.
- **Still UTC underneath.** Sentinel keeps storing and comparing times in UTC, so daylight-saving changes never
  shift a scan, and the logs, agents and API agree. Leave the server's own clock on UTC.

### 1.47.2 (2026-11-24): Windows agent scans start

- **"Could not start nmap" on Windows is fixed.** The agent asked Windows to read nmap's input from `/dev/null`,
  which only exists on Linux, so every scan failed before it began. It now uses Windows' null device, gives nmap the
  environment Windows networking needs (without `SystemRoot`, Winsock can't start), and collects nmap's output in
  private temporary files, because PHP can't read process pipes on Windows without blocking. The stop check, kill
  switch and time limits keep working during a scan. Linux agents and Sentinel's own scans are unchanged.
- To get the fix, upgrade the Windows agent: run the install command again with `-Upgrade`, or send a signed remote
  update from the agent's page.

### 1.47.1 (2026-11-24): Engagement approval fixes from review

- **Back on means back on.** Approving checks the setting again in the same database statement, so turning
  two-person approval back on wins over a self-approval that was already in progress.
- **Everyone is told.** Approvers limited to some clients are now notified when the rule changes too.
- **Only on purpose.** The setting is turned off only by an explicit choice in the form, never by a request that
  leaves the field out.
- The dashboard and Engagements page wording follow the setting, and the "awaiting your approval" list no longer
  hides engagements you may approve behind ones you may not.

### 1.47.0 (2026-11-24): Choose one- or two-person approval for pen tests

- **Your choice.** Under **Administration → Settings → Pen-test engagements**, an Admin who holds every permission and
  sees every client can turn off two-person approval, with their own password. Everyone who may approve engagements
  is told, and the change is audited. It stays on by default.
- **With it off,** whoever creates an engagement may approve it themselves if their role may approve engagements,
  still with their password and still before anything runs. The engagement page, the audit log and the pen-test
  report say "single-person approval". A technician who can't approve still needs someone who can.
- **Never weaker after the fact.** Each engagement keeps the rule in force when it was created. One made under the
  two-person rule always needs a second person, and one made while it was off needs a second person again once the
  rule is back on.

### 1.46.1 (2026-11-24): Sign in with Microsoft setup fixes from review

- **No lock-out from the wrong tenant.** Once a tenant is saved, the setup script's details must come from that same
  tenant (409 otherwise), so a run signed in to the wrong one changes nothing. Switching needs **Switch to another
  Microsoft tenant** ticked for the code. Switching tenants, here or by hand, now also turns password sign-in back on
  for everyone whose Microsoft link it clears.
- **All or nothing.** Using the code and saving the details is one transaction. The code only works while the Admin
  who made it is still an active Admin with every client. Wrong details sent with the right code no longer count
  toward the address's rate limit.
- **The script.** The command shown works on Windows PowerShell 5.1 (TLS 1.2 first). The script shows the tenant and
  asks before changing it, keeps the app's other web settings, waits for a new app to be ready, accepts a Sentinel
  address with a sub-folder, and sends the expiry date in a format every regional setting gets right.
- Expiry reminders also come while sign-in is switched off.

### 1.46.0 (2026-11-24): Sign in with Microsoft sets itself up

- **No more app registration by hand.** Under **Administration → Integrations → Sign in with Microsoft**, enter your
  password and click **Create setup code**. Run the PowerShell command Sentinel shows on any Windows PC and sign in at
  Microsoft as an Entra admin. The script (`entra-sso-setup.ps1`) creates the app registration: single tenant,
  Sentinel's redirect address, sign-in permissions only (granted for the organisation), the auth_time claim and a
  12-month client secret. It sends the details to Sentinel with the one-time code, so the secret is never shown or
  copied. Then turn the switch on.
- **Renewals and reminders.** The card shows when the secret expires. Admins are reminded 30 and 7 days before and
  when it has expired. Running the script again with a new code adds a new secret and removes its older ones.
- **Safe by default.** The code lasts 30 minutes, works once, and only an Admin who sees every client can create one.
  The script never turns sign-in on, and a new tenant still clears every user's Microsoft link.

### 1.45.3 (2026-11-24): Windows agent installer and nmap

- **nmap's setup opens for you.** The free nmap installer has no silent mode (nmap.org keeps that for the paid OEM
  edition), so the Windows installer stopped after 5 minutes. It now says the nmap setup window is opening, to untick
  Npcap, and waits up to 30 minutes for you to click through. An nmap that is already installed is used as it is.
- **Unattended installs.** Run through an RMM tool as SYSTEM (no desktop), the installer stops at once when nmap is
  missing and says to install nmap first, instead of waiting for a window nobody can see.

### 1.45.2 (2026-11-24): Windows agent installer fix

- **The Windows installer runs again.** `install-agent.ps1` stopped with a parse error ("Unexpected token 'PHP'")
  before it did anything, because one line of the php.ini it writes left a string unclosed. Nothing was installed or
  changed by the failed run; run the same command again.
- The test suite now checks the quoting and brackets of every PowerShell script, so a script that doesn't parse
  can't ship again.

### 1.45.1 (2026-11-24): ITFlow tag filter fixes from review

- **No mass archive.** The sync also stops, changing nothing, when no client the key can see has the tag, or when
  ITFlow finds the tag but doesn't say which clients have it. Only client tags count: a contact or location tag of
  the same name is ignored.
- **"Don't sync with ITFlow" goes further.** An ITFlow client with the same name is no longer added beside it, it is
  not linked to MSP Align by ITFlow ID, and tickets waiting to be confirmed are left alone. When the switch is turned
  off again, only findings from then on get ITFlow tickets (no backlog). The form says that open tickets are no longer
  followed.
- The tag name refuses invisible and invalid characters.

### 1.45.0 (2026-11-24): Choose which ITFlow clients sync

- **Only tagged clients.** Under **Administration → Integrations → ITFlow**, tick **Only sync ITFlow clients with this
  tag** (default **Sentinel**, any case) and tag those clients in ITFlow. Untagged clients are not added; ones already
  in Sentinel are archived, and restored when the tag is added back. If the tags can't be read, or no client tag has
  that name, the sync stops and changes nothing. Needs an ITFlow with the tags API.
- **Leave a client out.** **Don't sync with ITFlow** on a client's Edit page: the sync never renames, archives or
  restores it, and Sentinel opens no ITFlow tickets for it.

### 1.44.1 (2026-11-24): ITFlow boards fixes from review

- **The Integrations page never waits on ITFlow.** The board list is read by **Test connection**, the client sync and
  ticket runs, and kept; before, every page view asked ITFlow and could hang while it was down.
- **A tech's work is never undone.** A ticket found again after an unclear answer is moved only while still new
  (15 minutes), and then without unassigning it.
- A chosen board that ITFlow no longer lists, or an ITFlow that lists no boards any more, is reported in the ticket
  run; "Alerts" is matched ignoring spaces, and the first such board is used; ITFlow's reason for refusing to list
  boards is shown.

### 1.44.0 (2026-11-24): ITFlow tickets on your Alerts board

- **Service boards.** On ITFlow builds with board support (the MountaineerIT build's `mit_boards` API), Sentinel moves
  each new ticket to a chosen board right after opening it, by default the board named **Alerts**, unassigned so the
  board's auto-assign and member notifications pick it up. Choose another board, or **Leave on ITFlow's default
  board**, under **Administration → Integrations → ITFlow**.
- **Never loses a ticket.** On stock ITFlow (no boards) nothing changes. If a move is refused, the ticket stays on
  ITFlow's default board and the last ticket run says so. A ticket found again after an unclear answer is moved too.

### 1.43.2 (2026-11-24): Sign in with Microsoft linking fixes from review

- **Linking needs your password** (a stolen session alone can't plant a lasting Microsoft sign-in) and **no existing
  link** (unlink first; a link is never replaced quietly). The linked account's name is shown on My profile and the
  user's page, and the user gets a notification when one is linked (migration 0050).
- **Resets remove the link:** an admin's password reset or two-factor reset clears the Microsoft link, as the account
  may be compromised. Unlinking a user whose password sign-in was off turns it back on, so they aren't locked out.
- Members whose tokens name the tenant in the older v1 form aren't refused as guests; a refused guest's directory is
  logged. Without the `auth_time` claim Sentinel always asks its own code and the server log says how to add it.
  Only a real duplicate counts as "already linked".

### 1.43.1 (2026-11-24): Sign in with Microsoft fixes from review

- **Accounts are linked by their owner, never by email address.** Each user signs in with their password and
  Sentinel's code, then links their Microsoft account under **My profile** (Microsoft asks them to prove it).
  Before, someone who could set an email address in the tenant (an Entra admin, a helpdesk, a guest invitation)
  could be linked to a Sentinel user with that address.
- **Only an Admin who sees every client** can change the Sign in with Microsoft settings, with their own password;
  before, anyone who could manage integrations could point it at another tenant. Changing the tenant clears every
  link.
- **Guests** from other directories are refused, and Sentinel's code is skipped only for MFA within the last hour
  (`max_age` and `auth_time`).
- Linking can't race to two accounts; network errors are no longer shown on the sign-in page.

### 1.43.0 (2026-11-24): Sign in with Microsoft

- **Sign in with Microsoft (Entra ID).** Your team signs in with their Microsoft 365 work account, the same tenant
  you use with ITFlow (ITFlow can't act as a sign-in provider itself). Set it up under **Administration →
  Integrations** with the app registration's tenant ID, client ID and secret (stored encrypted); it needs
  `app.public_url`. OpenID Connect with PKCE; the ID token's signature, issuer, audience, tenant, expiry and nonce
  are all checked.
- **Only existing users.** No account is created: the first sign-in links the Microsoft account to the one active
  user with the same email address, after that the link alone counts. Roles and clients stay managed in Sentinel.
- **Two-factor:** Sentinel's own code is skipped only when Microsoft confirms MFA; otherwise it is asked as usual.
- **Passwords stay as a fallback** and can be turned off per user; one active Admin who sees every client always
  keeps password sign-in. Accounts can be unlinked on the user's page. Sign-ins, links and failures are audited
  (migration 0049).

### 1.42.2 (2026-11-24): permissions and client lists fixes from review

- **Breached addresses stay masked** for anyone without **See breached addresses**: in reports (view, download and
  CSV, and the API's report HTML and CSV, where every email address is masked because reports are frozen copies), in
  alerts and emails, and in API notes. A masked API finding key keeps a short hash so two addresses that mask alike
  stay apart.
- **One MSP Align or ITFlow client per Sentinel client**, now also for the ITFlow sync and in the database (migration
  0048 adds the keys when there are no duplicates). The check runs only when the link changes, so an old duplicate no
  longer blocks other edits, and its message names no other client.
- Backup and feed notices go only to people who see every client; notifications are cleared only when someone's
  clients shrink. The user form's client choice is laid out properly; 1.40.0's notes now say 27 permissions.

### 1.42.1 (2026-11-24): client lists fixes from review

- **Org-wide pages and actions need every client:** the kill switch for all scanning (pause and resume), settings,
  integrations, the System page and the audit log, which reach or show every client. A limited user can still manage
  users, roles and API tokens within their clients.
- **One link per outside client:** an MSP Align client, and an ITFlow client, can each be linked to only one
  Sentinel client (before, linking a hidden client's Align record to your own showed its compliance data).
- **Within your clients:** the Unassigned, Overdue and Due-soon counts and the owner list on the Findings page;
  engagement approvers counted for the message; failed report-email and recheck notifications.
- Narrowing someone's clients clears their earlier notifications; an anonymous request's client list is empty.

### 1.42.0 (2026-11-24): API tokens follow permissions and clients

- **Clients:** a token only covers clients its creator sees ("All clients" only for someone who sees every client),
  checked when it is made and on every call: if the creator later sees fewer clients, the token is cut down to theirs.
- **Permissions:** triage and queueing scans need the creator's **Triage findings** and **Run scans and discovery**
  (since 1.40.1), and breached addresses come back masked unless the creator may see them in full.
- **The API page:** you see and revoke only tokens whose clients you all see, the scopes name the permission they
  need, and outbound events (which carry every client's changes) can only be set up by someone who sees every client.
  Existing tokens keep what they have, within their creator's rights.

### 1.41.0 (2026-11-24): limit users to their clients

- **Per-user client lists.** Each user sees every client (the default, so nothing changes on upgrade) or only a
  chosen list: **Administration → Users →** the user **→ Clients** (migration 0047).
- **Nothing of other clients.** For a limited user, other clients' pages and records (findings, reports, scans,
  engagements, authorisations, sites) answer "not found", checked once in the request kernel before any page code
  runs, and lists, counts, search, the dashboard, reports, engagements, notifications and alert emails leave them out.
  A test fails if any page with an ID lacks a client check.
- **Never more than you see.** You can only give clients you see yourself, and only manage users whose clients you
  all see. Findings can only be given to someone who sees the client; a client a limited user adds becomes theirs.
  The last active Admin who sees every client can't be limited, demoted or disabled.

### 1.40.1 (2026-11-24): roles and permissions fixes from review

- **API tokens never do more than their creator.** Only someone who may triage findings or start scans can give a
  token those rights, and a token loses them when its creator does (read access stays).
- **One active Admin always stays.** The lock-out guard now counts only the built-in Admin, which also gets every
  permission a later release adds; a custom role with every permission today would fall short then.
- **Checked again when saving.** Who may change a user or a role, and which role may be given, is checked again
  with the rows locked, so a role changed meanwhile by someone more powerful can't slip through or be saved over; a
  role deleted meanwhile gives a form error.
- **Pages show only what you may use:** the Administration overview shows only your areas, and the System page shows
  a release signer only the release key.
- **Breached addresses** on a finding's page are masked unless you may see them in full.
- Permissions that reach the whole system are marked **Near full control** on the Roles page. The demo data command
  picks an Admin by role.

### 1.40.0 (2026-11-24): roles and permissions

- **Permissions.** Every action now needs a permission: 27 of them in 7 groups (clients and scope, scanning,
  findings, reports, engagements, agents and devices, administration). Seeing clients and their findings needs none.
- **Built-in roles unchanged.** Viewer, Technician and Admin keep exactly the rights they had (a test checks every
  page and action against 1.39). Existing users keep their role (migration 0046).
- **Your own roles.** **Administration → Roles** creates roles from the permission list (or copies a built-in one),
  for example a "Lead technician" who may also set due dates and approve engagements, without full Admin. The
  **Who can do what** table shows every permission and which role holds it.
- **Never more than you hold.** You can only give permissions and roles you hold yourself, and can't change, reset
  the password or two-factor of, or disable a more powerful user. Nobody changes their own role, built-in roles never
  change, and at least one active user always holds every permission. Role changes are confirmed with your password,
  audited with what was added and removed, and sign the role's users out so they apply at once.
- **Alerts, owners and approvals follow permissions:** system, backup and feed alerts go to those who manage the
  system or settings; findings can be given to anyone who may triage; any second person who may approve engagements
  can approve; API tokens keep working while their creator may manage the API.

### 1.39.1 (2026-11-24): pen-test findings fixes from review

- **Retests only resolve what they really tested.** A host whose retest was stopped (kill switch), timed out or failed
  no longer resolves its findings, and neither does a retest that skipped a check on a host (UDP, the share check, the
  default-password test). Open ports found by an all-ports test need an all-ports retest, as in the retest letter.
- **No old results coming back.** Once the external scan has looked at a port again, or the agent has swept an address
  again (for the protocol problems it checks itself), that result decides. Before, fixing something the regular check
  reported could reopen the months-old pen-test result.
- **The masked default password stays in the pen-test report.** The finding (and so the API, ITFlow tickets and client
  reports) shows the account and service only.
- **A long share name with accents no longer breaks the client's findings refresh** (long keys are now shortened
  without cutting a character in two).
- A device whose name is one of several addresses gets its NTLM name too.

### 1.39.0 (2026-11-24): pen-test results become findings

- **Pen-test findings.** Each Fail and Warning of an approved engagement is now a finding (type **Pen test**), with the
  usual triage, owners, due dates, groups and ITFlow tickets; the engagement page keeps the raw results and the
  report is unchanged. "Worth knowing" results stay in the report. A problem the regular checks already raise (a risky
  port open to the internet, or an agent's protocol finding on the same address) isn't doubled. For each host and test
  the newest engagement that ran it decides: a retest that no longer finds a problem resolves its finding, and one
  that didn't run that test leaves it open (migration 0045).
- **Fixes to 1.38 from review:**
  - unlinking NinjaOne, or its organisation moving to another client, shows the agent's merged devices again at once
    (they were hidden, and their findings resolved, until the next agent check-in);
  - a Windows version seen from the network no longer raises a Fail: it is a Warning saying the edition is unknown,
    and builds that also ship as long-term (LTSC) editions are not judged;
  - Samba servers (NTLM build 0) are no longer shown as Windows 7, and a NAS banner wins;
  - a device without a host name gets its NTLM name and can be matched by address;
  - a scan where the NTLM answer is missing no longer replaces the known Windows build with a vaguer guess;
  - the combined device page lists each port once and shows the merged agent device's SNMP issues;
  - the device list counts open findings with an index instead of scanning them per device.

### 1.38.0 (2026-11-24): device OS from the network, one device per machine

- **Operating system and type for agent devices.** The agent reads a Windows machine's version and build over SMB
  without logging in (the NTLM handshake, as nmap's ntlm-info does) and Sentinel recognises other devices from their
  service banners and web pages (Linux distributions, NAS boxes, printers, firewalls, hypervisors). Devices now show
  their OS and are typed workstation, server or other. Windows 11 laptops in the demo data are workstations again.
- **One device per machine.** A machine that both the agent and NinjaOne report is one row in the Devices list
  (matched by address and name, or address alone when the agent saw no name). Its page combines NinjaOne's OS,
  antivirus and patches with the agent's services, certificates and findings. Admins can split a wrong match or merge
  by hand; nothing is deleted (migration 0044).
- **Fixes to 1.37 from review:**
  - the bulk action panel on Findings starts with no action and no decision chosen, and its note is limited to 500
    characters; the selection count is translated and stays right after going back;
  - **Backups are made another way** on the System page stops backup warnings and alerts;
  - a backup run stopped by a missing or short encryption passphrase is recorded as failed;
  - two backup runs at once both stay in the history.

### 1.37.0 (2026-11-24): backup status, picked findings, client risk at a glance

- **Backups you can see.** Each nightly backup records when it ran, whether it worked, its size and whether it was
  encrypted. **Administration → System → Backups** lists the last runs. The health check turns red, and admins get an
  alert (in-app and email, at most once a day), when the last backup failed or the last good one is over 2 days old.
- **Pick findings yourself.** In **One row per target**, tick findings (or a whole page) and apply one action to all of
  them: assign, accept risk / false positive / reopen, due date (admins) or verify fix.
- **The Clients list shows risk and open findings** for each client, with a link to its findings.

### 1.36.1 (2026-11-24): Docker and Proxmox agents, fixes from review

- **Docker:** `docker compose up`, `pull` and `logs` no longer need `SENTINEL_SERVER` (only enrolling does). A revoked
  agent's container stops for good instead of restarting. No PHP memory limit (as on the appliance). The enrolment
  code isn't shown while typed. Diagnostics say NetBIOS isn't heard in Docker. The guide covers a private CA and
  revoking.
- **Proxmox / LXC:** without nesting, the relaxed service settings now cover every option that needs a mount namespace
  (the agent would otherwise not start); the installer checks the service really started; a drop-in left from a
  container is removed on a VM and on uninstall.
- **Smaller fixes:** the Proxmox helper checks addresses strictly and refuses `--gw` with DHCP; the image workflow tags
  `latest` only for full releases and signs once by digest; an update request ended for a Docker agent is audited;
  `.dockerignore` leaves out `.env` files and bundles.

### 1.36.0 (2026-11-24): agents in Docker and on Proxmox

- **Docker agent.** `docker/agent/Dockerfile` and `docker/agent/docker-compose.yml` run the on-premises agent as a
  container on a Linux Docker host: host network (so discovery, MAC addresses and name requests work), unprivileged
  user, every capability dropped, read-only file system, config volume mounted read-only.
  - Updated by pulling a new image: Docker agents never get an in-place update. The Agents page shows
    "Update by pulling image x.y.z" instead of an Update button, and **Update all agents** says how many need a new
    image.
  - NetBIOS name requests (UDP 137) aren't heard in Docker; LLMNR requests are.
  - An optional GitHub Actions workflow publishes signed multi-architecture images to GitHub's registry when you push
    a release tag. See [the Docker guide](docs/guides/docker-agent.md).
- **Proxmox.** The normal installer works in an unprivileged Debian 13 LXC container. It checks systemd's sandbox and
  relaxes only that if the container has no nesting, with a warning. `install/proxmox-agent-ct.sh` creates a suitable
  container on the Proxmox host. See [the Proxmox guide](docs/guides/proxmox-agent.md).
- Agents report how they are installed: the Agents page shows a **Docker** or **LXC** badge (migration 0043).

### 1.35.1 (2026-11-24): update hardening, fixes from review

- **Windows: no new code as SYSTEM during an update either.** The update task's pre-flight used to run the new
  release's self-check as SYSTEM; it now asks PHP for its version and extensions with its own fixed code.
- **Giving agents a replaced release key needs no installed code:** `echo NEWKEY | sudo tee
  /etc/sentinel-agent/release-key.pub`. The installed copy of `agent-install.sh` refuses `--upgrade` (it is code a
  remote update delivered); upgrade from a downloaded, checked release.
- **The change-over to the frozen helper has a limit:** the update from 1.34 or older is still installed by the old
  helper, so the protection starts with the next update. Upgrade agents to 1.35 by hand once where that matters.
- **Smaller fixes:**
  - a Windows launcher that can't be swapped, or an update folder that can't be prepared, is logged in `update\task.log`;
  - half-made frozen copies are cleaned up;
  - `release-sign.php hash --ref` reads files without line-ending conversion and refuses an empty `--ref`;
  - `SHA256SUMS` now covers `AGENT-MANIFEST-SHA256`;
  - the docs say signing off the server is the strongest option.

### 1.35.0 (2026-11-24): agent updates can't run new code as root; signing checks the release hash

- **The agent update helper is frozen.** Linux agents run the root update helper from a root-owned copy in
  `/usr/local/lib/sentinel-agent-update`, and Windows agents run the SYSTEM update task from `updater\`, both outside
  the code folder that updates replace. A remote update no longer rewrites the systemd units either. So code from a new
  release only ever runs as the agent's unprivileged account, even if a release were signed through a compromised
  Sentinel.
  - Nothing to do: an agent makes its frozen copy at its next update, from the version it already runs. The installers
    refresh it on install and on a manual upgrade. On Windows, if the old launcher can't be swapped while it runs,
    `install-agent.ps1 -Upgrade` once finishes the change.
  - From now on, changes to the helper or the services arrive only with a manual upgrade; release notes will say so.
- **Signing a version checks its hash.** On **Administration → System → Sign this version**, paste the expected
  manifest SHA-256 from the release notes, or compute it on your own computer with
  `php bin/release-sign.php hash --ref vX.Y.Z` (no key needed). Your browser signs only if the files it is about to
  sign match; Sentinel checks again and records the hash in the audit log. Each release build now publishes
  `AGENT-MANIFEST-SHA256` next to `SHA256SUMS`.

### 1.34.0 (2026-11-24): security audit, search, confirmations, easier workflows and docs

- **Search.** A search box in the top bar finds clients, findings (title, target or CVE), external hosts, internal
  devices, engagements and help topics. Findings and the audit log get a "Contains" filter; Clients, Users, Devices,
  Engagements and Help get instant filter boxes.
- **"Are you sure?"** An in-page dialog says exactly what will happen before destructive, outbound or costly actions
  (deleting or revoking, sending tests, starting scans or rechecks, approving engagements, bulk triage).
- **Security audit fixes:**
  - Two-person approval of engagements can't be bypassed with an account the creator made or reset (30 days).
  - Creating a user, resetting a password or 2FA, changing a role or access, and creating API tokens ask for your own
    password. Engagement approval also refuses accounts linked to the creator the other way round or through a chain.
  - Changing the ITFlow or MSP Align address, or the SMTP host, clears the saved key or password.
  - Technicians' verify-fix rechecks wait for the scan window (admins' run straight away).
  - Encrypted settings and 2FA seeds are bound to their place; migration 0042 upgrades stored values.
  - Agents send the Active Directory password only to the domain and domain controller address they first signed in
    to (`dc-pins.json` on the agent; delete it there if the domain controller really moves).
  - Restoring a backup can't run client commands from a tampered dump, and keeps this server's program and folder
    settings; the backup passphrase file is owner-only.
  - Wildcards under shared platforms (`*.s3.amazonaws.com` and similar) are refused in the scan register. Entries
    saved before are not re-checked: look through your registers for such wildcards.
  - An enrolment code needs the site's internal authorisation first.
  - MSP Align links must be web addresses; Teams alert text can't add links or formatting.
  - Alerts are sent while a long scan runs; API lockouts are audited; notifications are marked read only on request.
  - The Update now card shows the installed and newest commit (branch code is unsigned).
- **Easier workflows:**
  - New engagements start with the gentle pace and without the all-ports test (the least risky choice).
  - Engagement approvals: other admins are notified, the dashboard shows what awaits you, and a new Engagements page
    lists every engagement. A lone admin is told to add a second one.
  - Finding pages show "Why it matters / How to fix".
  - Reports can be created from the Reports page.
  - First run: buttons to add a client and record its authorisation, "Not scanned yet" instead of a perfect score,
    clearer next steps and messages.
  - Readable evidence in client reports, an API reference page for admins, readable audit log rows, owner names in
    pickers, a type-to-search time zone field.
  - Opening a form's address as a page goes to the page that holds the form.
  - Phones: tables scroll inside their cards and the findings filters fold away.
- **Documentation:** task-based guides with a "Start here" page on GitHub, and in-app help reorganised the same way.

### 1.33.1 (2026-11-24): breach monitoring, fixes from review

- **No mass removal from an incomplete answer.** An answer that would remove more than half of the known breached
  addresses, or covers no domain at all, removes nothing and says so on the settings card. Only addresses of domains
  the answer covers (or that left the client's register) are ever removed.
- **An expired authorisation is not a fix:** that client's addresses and findings stay as they are.
- **A failed check is retried after 6 hours** (not a week), and a new API key can be checked at once.
- **Addresses are masked** in finding titles and targets, so in alerts, Teams/Slack messages and lists
  (`j***@client.example`). Viewers see them masked on the client page; the full address is in the finding's details
  for technicians and admins.
- **Archived clients' breach data is removed.**
- **Smaller fixes:**
  - each client's results are stored in one transaction;
  - breach evidence no longer changes with the provider's ordering;
  - future-dated breaches are treated as undated;
  - stricter domain checks;
  - a broader API key format;
  - a smaller answer size limit.

### 1.33.0 (2026-11-24): breach monitoring

- **Breached accounts.** Once a week, Sentinel asks XposedOrNot which addresses of your verified domains appear in
  known data breaches (**Administration → Integrations → Breach monitoring**).
  - Each address goes to the client whose authorisation lists its domain.
  - Verified domains in no client's register are listed and otherwise ignored.
- **One finding per address:**
  - Fail when a breach happened in the last 12 months;
  - Warning when all its breaches are older;
  - it lists each breach, its date and what was exposed, with advice: change the password and any reuse of it, turn
    on MFA, check recent sign-ins.

  Passwords are never stored or shown.
- **Safe by default:**
  - The API key is stored encrypted and never shown.
  - A failed check (provider unreachable, key refused, its daily limit) changes nothing.
  - An address no longer listed resolves.
  - **Check now** runs at most once an hour.
- **The client's Website & email page** lists the breached addresses.
- **Provider choice:** XposedOrNot is free (paid xonAPI+ keys for commercial volume work the same way). Have I Been
  Pwned has wider coverage but needs a paid key; it can be added later.

### 1.32.1 (2026-11-24): shared ITFlow tickets, fixes from review

- **No target is left without a ticket.** A fixed target that stays with a replaced ticket is released, and gets a
  ticket again if it comes back. So do targets whose ticket lost its leading finding (retention deletes old resolved
  findings) or whose replacement ticket ITFlow refused for good.
- **Large groups recheck each target once per close.** Before, more open targets than the recheck limit could queue
  rechecks in a loop.
- **No repeated notes** after a ticket is reopened or resolved for all targets.
- **Per-target notes count against the run's limit.** A refused note no longer holds up the ticket's other steps.
- **Known-exploited notes** also reach a shared ticket when only other targets are open.
- **The finding page** shows the shared ticket's real state for every target.
- **Members aren't listed** in the weekly Warnings ticket.
- **A retried replacement ticket** names the targets that moved to it.
- **Docs:** a new target only joins an open ticket; one that appears after the ticket was resolved gets its own.

### 1.32.0 (2026-11-24): one ITFlow ticket per issue

- **The same problem on several targets is one ITFlow ticket.** A finding with the same issue as an open ticket of
  the same client (the same CVE, or the same title) joins it with an internal "also found on <target>" note,
  instead of opening a ticket of its own. The finding page shows the shared ticket.
- **The ticket follows every target:**
  - a target fixed or decided while others are still open gets a note (and another if it comes back);
  - the ticket is resolved only when every target is fixed or decided, with one note listing them.
- **Closed in ITFlow** while targets are open: each open target is rechecked. If any is still there, a resolved
  ticket is reopened naming them. A closed ticket is replaced by one new ticket for the targets still open; the
  fixed ones stay with the old ticket.
- **Existing tickets work the same way:** new targets of their issue join them. Weekly Warnings tickets don't change.

### 1.31.1 (2026-11-24): grouped findings, fixes from review

- **Reports group exactly like the Findings list.** An issue with both Fail and Warning targets is one entry, under
  Fail. Headings count issues and findings.
- **Report snapshots hold each finding once** (before, the grouping stored them twice). A report too large to store
  is refused with a clear message.
- **The assignment email says how many findings** were assigned ("and N more") and links to the assignee's list.
- **A group's due date can go back to the policy**, recomputed once per client.
- **Bulk verify carries on** when one finding can't be rechecked.
- **Due-date filters** ("Overdue", "Due soon") sort groups by the nearest deadline.
- **Large groups load faster:** at most 100 targets per group are read (the rest via "Show all").
- **Layout:** an opened group keeps its other columns at the top.

### 1.31.0 (2026-11-24): grouped findings

- **Repeated findings are one row.** The same CVE, or the same problem, on several targets of one client is grouped
  in the Findings list ("on 3 targets"). Open the row to see each target. **One row per target** switches back.
- **Act on a whole group at once** (technicians and admins):
  - assign;
  - accept risk, false positive or reopen, with one note;
  - verify fix on each target;
  - one due date (admins).

  Each finding is checked exactly as a single click would check it: resolved and archived findings are skipped, and
  the verify limits apply. Each one is audited on its own, and the assignee gets one email for the group.
- **Reports list each problem once** with every target it was found on. Per-target evidence is in a small table,
  and the executive summary's top risks count issues, not targets.
- **Each target is still its own finding.** It is fixed, rechecked and resolved on its own.
- Grouped ITFlow tickets (one ticket per issue) follow in the next release.

### 1.30.1 (2026-11-24): share check, fixes from review

- **No false "anyone can list the shares" finding.** A server that refuses the list answers an empty list with
  "access denied" (Samba's "restrict anonymous = 1"). Before, that empty answer counted as a list.
- **Counts are honest.**
  - An empty drive root counts as readable with 0 items. Before, it was "not readable".
  - A count that didn't reach the end says "at least N".
  - A share that opened but couldn't be counted in time says so, instead of showing 0.
- **Long share names** (over 80 characters) are opened with their full name. Only the evidence is shortened.
- **Samba's anonymous sessions** are labelled anonymous, not guest.
- **Unsolicited server notices** no longer end the check for that host.
- **Docs:** servers that require SMB encryption show as refused. The check can miss an open share there, but never
  invents one.

### 1.30.0 (2026-11-24): safe SMB share check

- **The engagement's anonymous access test now checks Windows and NAS file shares.** It uses Sentinel's own SMB2
  client:
  - it signs in **anonymously**, with no username at all, so no account can ever be locked;
  - it reads the share list;
  - it opens each disk share's top folder for listing only and counts the items in it.

  It never opens a file, never goes into a subfolder and never writes. nmap's share script is still not used, because
  it writes a test file.
- **Evidence:** share names and item counts only, never file names.
- **Findings:**
  - a share readable without a password is a Fail;
  - a share list handed out to anyone is a Warning (a Fail from the internet).

  The report explains why open shares matter (ransomware spreads through them).
- **External and internal.** Internal runs need agents 1.30.0 for the share check; older agents still run the rest
  of the test.

### 1.29.1 (2026-11-23): default passwords, fixes from review

- **No username is ever tried twice on one host.** A device often serves the same login on several ports (80, 443,
  8080, FTP): before, each port got its own three attempts. The 5-second spacing now also applies between services.
- **Windows accounts are never tried.** IIS, WinRM/HTTP.sys (ports 5985, 5986, 47001) and IIS FTP are skipped, and
  so is any web page that also offers Windows sign-in (Negotiate/NTLM): its Basic login checks directory accounts.
- **Re-runs don't repeat attempts.** Running the tests again in the same engagement keeps the earlier result. A
  retest tries only the accounts that worked before, once each, to confirm they were changed.
- **A redirect no longer counts as a login.** Some devices answer a wrong password with a redirect.
- **At most 10 minutes per host** for this test.
- **More lockout answers recognised:** MariaDB's "account locked", and FTP replies that mention a lock or too many
  attempts.
- **Stricter checks on agent results** (a mask must hide something) and on the test-only spacing setting.
- **Internal runs now need agents 1.29.1** (1.29.0 agents don't have these limits).

### 1.29.0 (2026-11-23): default passwords in pen-test engagements

- **New engagement test: vendor default passwords.** It needs a second tick confirming the signed authorisation
  explicitly allows it (a new line in the annex, P3).
  - Services: FTP, web admin pages that ask for a Basic login, MySQL/MariaDB and PostgreSQL.
  - At most **three** published vendor defaults per service. Each uses a different account, so no account ever sees
    more than one failed attempt.
  - Attempts run one at a time, 5 seconds apart, and stop at the first success or at any lockout, block or
    "too many attempts" answer.
  - A login that works is closed at once; nothing is read.
  - Never SSH, Windows, Remote Desktop, WinRM or directory logins.
- **Databases open without a password:** Redis, MongoDB, Elasticsearch/OpenSearch and Memcached are checked without
  guessing. Open is a Fail (Memcached inside the network: Warning).
- **The password is never stored.** The evidence shows the username and the password masked (`a•••n`).
- **Runs externally and through the site agents.** Internal runs need agents 1.29.0 or later; older agents aren't
  given the job.
- **The report says exactly what was tried,** and the attack paths explain what a working default password means.

### 1.28.1 (2026-11-23): attack-surface checks, fixes from review

- **A zone with a wildcard record (`*.client.example`) is now reported as open.** Before, the name stopped the check
  and the open zone transfer was missed. Names in a zone are now read leniently and made safe for display.
- **A takeover check that can't decide keeps the earlier result.** A DNS failure or an unanswered web request no
  longer closes an open finding (and reopens it the next day).
- **Only public addresses are contacted.** A nameserver or cloud name that resolves to a private, loopback or other
  reserved address (perhaps your own network) is skipped.
- **No takeover reports for names nobody else can claim.** Only Amazon S3 names count for AWS (not load balancers,
  databases or API gateways). A cloud name that no longer resolves counts only where anyone can register it again
  (Azure, Elastic Beanstalk, Heroku). The title now says "an unclaimed name".
- **Pauses and scope changes take effect within one name.** Every name is checked against the live scope right
  before it is checked. The DNS step stops after 10 minutes and continues with the next job.
- **The caps always pick the same names.** The client's own names come first, in a fixed order, so findings don't
  come and go.
- **Demo clients are never DNS-checked**, and removing demo data also removes their DNS results.
- **Stricter zone transfer reading:**
  - exactly our question;
  - complete messages over TCP;
  - "open" only once a record of the zone itself arrives.
- **Linux agent updates stop the agent before swapping folders and before a rollback.** The new repair step then
  can't race them. If the swap fails, the agent is started again.

### 1.28.0 (2026-11-23): attack-surface checks

- **DNS zone transfers.** For each domain in the authorisation, Sentinel asks each of the domain's own listed
  nameservers (at most 4, two addresses each) for a zone transfer, once a day at most. A nameserver that hands out the
  whole zone is a Fail: anyone can list every name, including internal and forgotten systems. Only the first part of
  the answer is read (enough to prove it and show a few names).
- **Subdomain takeover.** Each authorised name, and each in-scope name seen on the client's addresses, is checked for a
  CNAME to a cloud service (Amazon S3, GitHub Pages, Heroku, Azure, Shopify and others) that no longer exists. Either
  the cloud name no longer resolves, or one request to the client's name gets the provider's own "no such site" page.
  Both are Fails: anyone could claim the name and serve content on the client's domain.
- **More management pages recognised:** hypervisors (VMware ESXi and vCenter, Proxmox, XenServer and XCP-ng,
  Nutanix), out-of-band management (iDRAC, iLO, IPMI and other BMCs, XClarity), NAS devices (Synology, QNAP,
  TrueNAS, unRAID, ReadyNAS, TerraMaster) and more network devices (UniFi, MikroTik, Omada). Each is a Fail when
  reachable from the internet. A product named only in a page's text is not flagged.
- **Default ports added:** 902 (VMware ESXi management, high risk), 5000 and 5001 (NAS admin pages), 8006 (Proxmox)
  and 9090 (management consoles). Agents check 902, 5001 and 8006 too.
- **The client's website card** has a DNS table: each nameserver's answer and each name's takeover check.
- **Fix: a Linux agent update stopped half-way (power cut between the two renames) now repairs itself.** The agent's
  service and the update helper put the previous version back before anything runs, so the agent starts again on
  its own. Before, the helper's code was in the missing folder, so nothing could repair it. Agents get this with their
  next update.

### 1.27.1 (2026-11-23): pen-test engagements, fixes from review

- **Anonymous access no longer lists SMB shares.** nmap's script for that writes and deletes a test file in every
  share, which breaks "nothing is written". Anonymous access now means FTP and NFS (read only).
- **nmap's "safe" scripts now exclude vulnerability checks.** Some of them send attack-like requests.
- **External engagement results are evidence only.** They no longer change the client's day-to-day services,
  certificates or findings (as the docs said).
- **All 65,535 ports need the normal pace.** At the gentle pace one host would take about 7 hours.
- **Exclusions are given as addresses, not names.** Agents also leave excluded hosts out of the discovery sweep.
- **The retest letter marks a finding "fixed" only when the same test ran again** and the host was tested to the end.
  IPv6 hosts are matched correctly.
- **When nmap can't run, an external engagement job fails** instead of queuing more jobs.
- **Clearer texts:** the test descriptions, the 200 packets a second limit, the cancel message for stopped
  engagements, and the docs (stop timing, how slices work, scope checks).

### 1.27.0 (2026-11-23): pen-test engagements

- **Pen-test engagements** (Client → Pen-test engagements): time-boxed, deeper tests the client authorises in
  writing. You attach the signed PDF; Sentinel keeps its SHA-256.
- **Only inside the authorised scope.** Each engagement has its own exclusions and a window of at most 14 days.
- **A different admin approves it**, with their password. **Stop engagement** is a kill switch that ends it for good.
- **Tests, chosen per engagement:**
  - all 65,535 TCP ports;
  - common UDP services (SNMP, NTP, SSDP; one read-only request each);
  - nmap's safe scripts;
  - anonymous-access checks (FTP, NFS; read only).

  The pace is gentle or normal (never faster). No password guessing, no exploits, nothing that changes the systems.
- **External tests run from Sentinel.** They run in 20-minute slices, and every host is checked against the
  engagement, its exclusions and the live scope before and during the test.
- **Internal tests run through the site agents** (agents must be 1.27.0 or later). The job is signed with the
  targets, exclusions, tests and end time. Agents stop on their own at the end time.
- **Findings come from the evidence:** anonymous FTP, SMBv1, open shares, SMB signing, NFS exports, SNMP default
  communities, UPnP and services exposed to the internet.
- **Penetration test report** (branded, frozen): summary, how the findings chain together, scope and authorisation,
  method, findings with evidence and fixes, systems tested. CSV export.
- **Retest letter** from a retest engagement: each earlier finding is marked fixed, still open or not retested.
- **New authorisation template annex** for engagements. See [docs/engagements.md](docs/engagements.md).

### 1.26.2 (2026-11-23): Windows agent, fixes from re-review

- **A fresh install creates its ProgramData folder itself.** It fails if someone recreated the folder in between,
  replaces the whole permission list in one step, and checks that nothing got in. A local user racing the install can
  no longer keep write access.
- **`-Upgrade` only trusts folders it made.** It refuses unless the service exists and the data, config and update
  folders are writable only by Administrators and SYSTEM.
- **nmap installs no longer fail because of an empty exit code.**
- **An update interrupted by a crash or reboot no longer leaves the service disabled or stopped.** The next update
  task run starts it again, and `-Upgrade` resets its start mode.
- **The update task is harder to fool and keeps more on failure:**
  - it checks the state folder afresh on every read, and logs when the folder is redirected;
  - it retries folder renames;
  - it keeps the failed copy when a rollback fails;
  - it logs when its result can't be written.
- **Agents installed with 1.26.0 need `install-agent.ps1 -Upgrade` once.**

### 1.26.1 (2026-11-23): Windows agent, fixes from review

- **The agent's service has only two privileges.** It can no longer impersonate clients, which known tools turn into
  SYSTEM (`sc privs`).
- **Updates can swap the code folder.** The update task now runs through a small launcher outside that folder.
  Windows can't rename a folder that holds an open file, and the launcher also repairs a half-finished update.
- **TLS uses the Windows certificate store.** PHP's curl has no CA bundle of its own on Windows.
- **The installer never acts through links or junctions** the agent could create:
  - it checks its folders before changing permissions on `-Upgrade`;
  - it deletes with `rmdir /s`, which removes links but never what they point to;
  - a fresh install starts from a new ProgramData folder owned by Administrators.
- **The update task:**
  - refuses a redirected state folder;
  - disables the service while it swaps folders, checks every rename, and says so if a rollback fails;
  - writes its result reliably;
  - keeps a log (`update\task.log`).
- **Installer details:**
  - WinSW's .NET Framework build;
  - nmap's publisher checked, and a time limit if its installer isn't silent;
  - no empty password argument;
  - the Visual C++ runtime version checked;
  - an absolute PHP extension folder;
  - each permission change checked;
  - the code wiped from memory;
  - `-Upgrade` pauses the update task and restarts the service if it fails.
- **The Windows command sets TLS 1.2 first.** The docs say exactly what is checked and what still needs testing on
  Windows.

### 1.26.0 (2026-11-23): Windows agent (preview)

- **The on-premises agent runs on Windows Server 2022/2025 and Windows 11**, installed with one PowerShell command (as
  administrator) shown on the enrolment page next to the Linux ones.
- **What the installer sets up:**
  - PHP 8.4, checked against windows.php.net's published SHA-256;
  - nmap without Npcap, checked against nmap.org's SHA-256 and its signature;
  - WinSW, with its SHA-256 pinned;
  - the "MSP Sentinel Agent" service, running under its own virtual account without admin rights, with only two
    privileges (no impersonation);
  - tight folder permissions.
- **Updates from Sentinel, built like the Linux ones.** A SYSTEM task downloads the release itself and checks it with
  the pinned release key, then installs it and rolls back if the service doesn't stay up. It never writes or deletes
  in the agent's own folder, and reads only the agent's small request from it (not through links or junctions).
- **Same agent program on both platforms.** Windows differences: MAC addresses come from `arp -a`, and there is no
  name-poisoning listener (Windows owns those ports). Scans are slower without Npcap.
- **Preview:** the PowerShell installer still needs testing on real Windows machines. See
  [docs/windows-agent.md](docs/windows-agent.md).

### 1.25.0 (2026-11-23): agent install steps

- **"How to add an agent" on the Agents card**: open until a client has its first agent.
- **The enrolment page has everything for the install**:
  - requirements (OS, size, bridged network, outbound HTTPS only);
  - the one-line and archive install commands with your Sentinel address, with copy buttons (the code is typed at
    the prompt, never put on a command line);
  - how to check it worked, including the release key fingerprint to expect;
  - troubleshooting.
- **It warns when the site has no internal authorisation valid today**, so the agent won't scan yet.
- **The one-line installer accepts `SENTINEL_CA=/path/ca.pem`** for a Sentinel with a private CA.
- Help topics can be linked directly.
- **Fixes from the second release-key review:**
  - The update helper never treats a damaged or wrongly owned key as "nothing pinned", so Sentinel can't slip in a
    new key that way.
  - The System page and `bin/release-sign.php` now list exactly the same files, so the manifest hashes match.
  - The installer reads the enrolment key as JSON.
  - The docs are more precise about what the app key protects (and that restoring an old value brings an old key
    back).

### 1.24.1 (2026-11-23): release key, fixes from review

- **Agents given the key at enrolment can now be updated.** The update helper only looked for the key file, so
  these agents refused every update.
- **The release key is stored authenticated with the app key**, so a database write alone can't plant a key agents
  would trust. A key made with 1.24.0 must be made again.
- **Only the release's own files are signed and sent to agents:** its own folders and file types. Other files left in
  Sentinel's folder (a backup, a dump) are no longer included.
- **Before signing, the page shows the manifest's SHA-256 and every file.** Compare the hash with the one in the
  release notes (`bin/release-sign.php sign` prints it).
- **Agents follow several rotations** (each step signed by the key before), not just the last one.
- **The agent installer prints the release key fingerprint at enrolment**, and the System page lists agents that have
  no key yet.
- **The docs now say what the key does and doesn't protect.** An agent with no key yet trusts the first key Sentinel
  gives it. Signing in a page Sentinel serves means a compromised server could copy the key file and its password
  while you use them.
- The key file name now includes its fingerprint. A pinned key is never overridden by a key file in a release folder.

### 1.24.0 (2026-11-23): release key in the web UI

- **The agent release key is created and used on Administration → System, in your browser.** The private key
  downloads as a password-protected file to your computer and never reaches Sentinel; Sentinel keeps only the public
  half. The key doesn't expire.
- **Sign each version from the System page** by picking the key file and typing its password. Only the signature is
  sent.
- **Agents learn the key from Sentinel:** at enrolment, or at their next check-in through the root update helper when
  they have none. A pinned key never changes by itself.
- **Rotate the key** with the old key file: the old key signs the change, so agents switch on their own. **Replace**
  it if the file is lost; agents then need the new key by hand (`agent-install.sh --release-key`).
- The command-line signing tool remains as an alternative.

### 1.23.2 (2026-11-23): agent moves, fixes from re-review

- **Older agents are never asked to move.** Only agents at 1.23.1 or later get move instructions, because 1.23.0
  agents sent their token before the proof.
- **Moves made by 1.23.0 agents are kept** when those agents update, instead of being dropped.
- **"Move complete" and "Cancel and recall agents" are now separate.** Move complete stops asking agents and keeps
  moved agents where they are. Cancel brings them back. Both need your password, and the page says what each does.
- **Password re-entry is throttled and failures are audited,** the same as on the profile page.
- **A 200 that isn't Sentinel's answer** counts only as a failed check-in at a new address.
- **After probation, a refusal at the new address no longer sends the agent back.**
- **Recall also notices a changed CA for the same address.**
- **Docs:** the limit on who can set a move is corrected.

### 1.23.1 (2026-11-23): agent moves, security fixes from review

- **No secrets go to an unproven address.** The new address is asked for its proof without the agent's token.
  1.23.0 sent the token first, so a mistyped or rogue address could collect agents' tokens.
- **The proof names the address.** Sentinel only signs proofs for the address an admin set, so a host that relays the
  challenge to the real Sentinel can't pass.
- **Starting a move needs your password**, and the move setting is encrypted and authenticated with the app key, so it
  can't be edited in the database directly (see the limit in docs/agent.md).
- **Agents can always be recalled.** While moved, an agent asks its original address every 6 hours, and comes back
  when the move was cancelled or changed.
- **Fallback only right after a move:** within 24 hours or the first 20 good check-ins. After that the move is
  permanent, so an outage can't strand agents at an old address. A fallback is reported, so the move isn't repeated
  in a loop.
- **Smaller fixes:**
  - Move instructions are limited, so they never stop scans.
  - Any non-answer at a new address counts as a failure, and a token refusal there sends the agent back instead of
    wiping it.
  - Writes are checked.
  - Agents ignore a move file from another enrolment.
  - The configured private CA is reused under a new name.
  - Address changes are audited.
- Moves set in 1.23.0 are cleared; set them again (with your password). Agents need 1.23.1.

### 1.23.0 (2026-11-23): move agents to a new Sentinel address

- **Move every agent to a new Sentinel address** (and a private CA's certificate, if needed) from Administration →
  System, without visiting any site.
- **Each agent only switches after the new address proves it is this Sentinel.** The new address must sign a random
  challenge with the key the agent pinned at enrolment. Hardened in 1.23.1: the token was sent before the proof.
- **Automatic fallback:** an agent goes back to its old address on its own if the new one fails 10 check-ins in a row.
- The System page shows each agent's state: moved, waiting, not moved (and why), or needing an update first.
- This completes managing agents from Sentinel: after the one-time install with an enrolment code, settings,
  diagnostics, restarts, updates and address moves all happen from the web UI.

### 1.22.2 (2026-11-23): agent updates, fixes from re-review

- **Repeat updates work.** In 1.22.1, the update helper's sandbox stopped the collector from removing the update
  request. After the first remote update, the helper restarted in a loop and later updates were ignored. The collector
  (running as the agent's user) can now remove it. The agent also removes a request the helper already answered, or
  one older than an hour.
- **Updating from 1.22.0 works.** The helper's result folder is created before its sandbox starts. A result left by
  the 1.22.0 helper is read once. A request is marked done once the agent runs the version asked for, even if its
  result was lost.
- **Safer swap:**
  - The agent must stay up for 50 seconds without restarting, or the previous version is put back.
  - A rollback that can't complete never leaves the appliance without an agent.
  - An update interrupted half-way is repaired on the next run.
- **Smaller fixes:**
  - The collector runs via `setpriv`, so a timeout reaches it.
  - The self-check must report the exact version being installed, and checks for PHP 8.3.
  - Results survive odd characters.
  - `release-sign` lists files that aren't part of the agent release.

### 1.22.1 (2026-11-23): agent updates, security fixes from review

- **Security fix:** the root update helper no longer reads, writes or deletes anything in the agent's own folder.
  The agent's user could plant symlinks there and get a root-owned file overwritten. A collector running as the
  agent's user now hands the staged release to the helper, which checks it in memory. Results go to a root-owned
  folder the agent can only read, and the agent cleans up its own staging. Versions that aren't x.y.z are never used.
- **Pre-flight and rollback:** the new release's self-check runs as the agent's user before anything is swapped. If
  the updated agent doesn't stay running, the previous version is put back automatically.
- **A stuck update can't stop scans.** A request is handed out at most 3 times, 30 minutes apart, with scans in
  between, then ends with a clear message.
- **Releases are signed exactly as the release archive ships them**, so Sentinels installed from the tarball can hand
  out every file.
- **Smaller fixes:**
  - The helper's systemd service is hardened, and limited to 5 starts in 10 minutes.
  - An unreadable installed version is refused.
  - "Update to" can be pressed again for a newer release.

### 1.22.0 (2026-11-23): agent updates from Sentinel

- **Update agents from Sentinel.** Use **Update to x.y.z** per agent, **Update all agents** per client, or **Update all
  agents** under Administration → System. Agents update at their next check-in between scans, download the release
  from Sentinel (no GitHub access needed at client sites) and report the result.
- **Only code signed with your release key is installed.** The key is pinned on each agent at install and never
  changed by an update. A root helper on the appliance checks the signature, the version (no downgrades) and every
  file again before installing. Sentinel can ask for an update but can't vouch for code, so a compromised Sentinel
  server can't push code to client networks.
- **New `bin/release-sign.php`** (for you only): `keygen` once, then `sign` for each release (see
  [docs/agent.md](docs/agent.md#updates-from-sentinel-122)). Until the release key is set up and a release is signed,
  no updates are offered.
- **Upgrade existing agents once by hand** (`agent-install.sh --upgrade`) to get the update helper and the pinned key.

### 1.21.1 (2026-11-23): agent settings, fixes from review

- **Restart, Diagnostics and Scan now are no longer lost.** Check-ins during a running scan, and the agent's
  `status` command, used to take these requests and ignore them. Now only the agent's idle check-ins between scans
  receive them. A restart is handed out on its own, so a queued scan isn't marked as sent and then expired. This also
  fixes an older problem: a scan queued while another was running could expire without running.
- **Honest gentleness settings:**
  - *Very gentle* now keeps nmap's polite timing with one probe at a time, at most 10 a second. The old `-T1`
    template waited 15 seconds between probes and couldn't finish real scans.
  - *Faster* (nmap `-T3`) is labelled as the much heavier traffic it really is.
- **Older agents are flagged.** The Agents page says when an agent older than 1.21.0 ignores these settings.
- **Diagnostics** are labelled as reported by the agent, and a key fingerprint that doesn't match the pinned key is
  flagged.
- **Smaller fixes:**
  - Requests are taken atomically.
  - Odd numbers in a report can't wipe it.
  - The settings audit entry records the old values.
  - Messages reflect longer check-in intervals.
  - Tests prove the external scanner always uses the default timing.

### 1.21.0 (2026-11-23): agent settings from the web UI

- **Manage agents from the client's Agents page** (admins) after the one-time install:
  - **Scan gentleness per site:** very gentle, gentle (the default) or faster (labels and timings corrected in
    1.21.1). It is signed into each job, and the agent refuses anything else.
  - **Check-in interval per site:** 30 seconds to 10 minutes.
  - **Diagnostics:** a report from the agent with versions, disk, memory, load, uptime, clock difference with
    Sentinel, key fingerprint and whether it holds a directory password. Never a secret.
  - **Restart:** between scans; the agent's service starts it again.
- Next: signed agent updates from Sentinel, then moving agents to a new Sentinel address.

### 1.20.1 (2026-11-23): Active Directory checks, fixes from review

- **The agent's key is pinned.** A changed key no longer replaces the old one silently. It waits on the Agents page
  until an admin compares its fingerprint, which the agent's `status` command now prints, and approves it. Nothing
  is sealed to an unapproved key, so someone holding an agent's token or with database access can't have the next
  password sealed to a key of their own.
- **A re-sent password is confirmed again.** Before, if the agent's confirmation got lost, a password the agent held
  showed as "failed (replay)". An old sealed password sent again under a new drop ID is refused.
- **NetBIOS:** only broadcast name queries count. Node-status queries from inventory tools and RMMs are no longer
  reported as name poisoning, and the appliance never reports itself. The finding closes only after three quiet
  listens in a row.
- **Domain Admins is found by its well-known SID**, so localised names work. Members through their primary group
  count too.
- **Smaller fixes:**
  - A password for an account that was changed is deleted from the agent, as is the password of a revoked agent.
  - An undecided LDAP signing probe keeps the earlier answer.
  - Turning the checks off closes their findings at once.
  - "Saved" is no longer shown when the page's script didn't run.
  - An unusable key file only turns off the AD checks, not the agent.
  - Paging is guarded against a domain controller that repeats pages or sends too much.

### 1.20.0 (2026-11-23): Active Directory checks

- **Active Directory checks through the on-premises agent** (first item of
  [docs/ROADMAP-security.md](docs/ROADMAP-security.md)). With a read-only domain account, the agent reads the
  directory at each full scan. Nothing is changed. Balanced grading:
  - **Fail:** AS-REP roastable accounts, Kerberoastable admin accounts, unconstrained delegation outside the domain
    controllers.
  - **Warning:** other Kerberoastable accounts, more than 5 Domain Admins, admin passwords that never expire, a
    krbtgt password over a year old, missing LAPS, LDAP signing not required, stale admin accounts.
  - Each finding lists up to 25 names, with step-by-step fixes in reports and ITFlow tickets. The findings also count
    on the Compliance page.
- **The password is sealed for the agent, never readable in Sentinel.** Your browser encrypts it to the site agent's
  own key (Web Crypto). Sentinel relays the sealed box, signed, and deletes it once the agent confirms. The agent keeps
  it sealed and opens it only for the sign-in. Replace it any time from the Agents page; the page shows when the agent
  last confirmed it.
- **The domain controller's certificate is trusted before the first sign-in.** The agent signs in over LDAPS only
  when the certificate matches the one you trusted. A changed certificate gets nothing.
- **LDAP signing** is checked with a made-up account; the real password never goes over plain LDAP.
- **Name poisoning:** the agent listens for 2 minutes per full scan for LLMNR/NetBIOS name requests and never
  answers. Devices sending them are a Fail.
- **Agent changes:**
  - The agent gets its own key pair, created on the appliance.
  - The service gets one capability (`CAP_NET_BIND_SERVICE`) to listen on UDP 137.
  - Agent files live in `/var/lib/sentinel-agent`.
  - Upgrade agents with `--upgrade` to use these features.

### 1.19.2 (2026-11-23): faster ticket lookup, device evidence tested

- **After an unclear answer from ITFlow, Sentinel looks for the ticket from the newest end** of the client's ticket
  list. It stops at tickets older than the create call, instead of reading the list from the oldest. Clients with
  thousands of tickets are handled in a few small reads, and no longer fall back to opening the ticket again with a
  duplicate warning.
- **New test:** a device finding counts as still there only when device data received after the ticket was closed
  still shows it. A refresh from stored data doesn't count.

### 1.19.1 (2026-11-23): two-way ITFlow tickets, fixes from review

- **A ticket is reopened only on clear evidence.** That means a "verify fix" recheck after the close that still sees
  the problem, or new device data that still shows it. Before, any findings refresh from stored data counted (the
  daily vulnerability update, a scan of another host, a recheck that couldn't tell), so a fixed problem could get its
  ticket reopened or replaced.
- **Rechecks follow the same limits as the button:** at most one per finding every 10 minutes, and the usual caps on
  waiting rechecks. They also wait for the client's scan window, since no person asked for them.
- **A ticket is given up as gone only after two "not found" answers an hour apart.** ITFlow answers "not found" for
  its own errors too. A finding whose ticket was deleted gets a new one while it's open.
- **A ticket whose create call got an unclear answer is looked for on two runs before it's opened again.** If it
  can't be settled, it's opened again with a note to check ITFlow for a duplicate, instead of blocking ticketing.
- **A problem reopened by hand after its ticket was done is followed again.** So is a problem fixed after Sentinel
  gave up waiting.
- **A refused API key user stops the run.** That covers an inactive or archived user, or a role without the Support
  module. Before, every item was marked failed and then waited up to a day.
- **The "verified fixed" note is sent once,** even if resolving the ticket has to be retried.
- **Smaller fixes:**
  - The first retry comes after 1 hour, as documented.
  - Tickets Sentinel resolved are followed for 30 days, not forever.
  - A refused replacement ticket is retried whatever the finding's severity.
- **Upgrade note:** on the first runs after updating, tickets of findings fixed since they were opened get a
  "verified fixed" note and are resolved, 50 per run.

### 1.19.0 (2026-11-23): ITFlow tickets both ways

- **Two-way status** (phase 3 of [docs/ROADMAP-itflow.md](docs/ROADMAP-itflow.md)):
  - When Sentinel no longer sees a problem, or someone marks it accepted risk or false positive, the ticket gets an
    internal note saying so and is resolved in ITFlow.
  - When a ticket is resolved or closed in ITFlow while the problem is still open, Sentinel checks again. A port or
    email problem gets a "verify fix" recheck at once; a device problem waits for the device's next data.
  - Gone: the finding closes and the ticket gets a "verified fixed" note.
  - Still there: a resolved ticket is reopened with what Sentinel still sees. A closed ticket can't be reopened in
    ITFlow, so it is replaced by a new ticket that names the old one.
  - A problem that comes back after its ticket was resolved reopens the ticket (or replaces it if it was closed).
  - The finding page shows each ticket's state and its earlier tickets.
- **Fixes from the 1.18.0 review:**
  - One ticket that ITFlow refuses (a deleted client, a closed ticket, no access) no longer stops all ticketing. It
    is retried later (after 1, 2, 4… hours) and the reason shows on the finding.
  - The ticket link goes to ITFlow's technician view. Sentinel no longer keeps ITFlow's client guest link, which
    carries a secret key.
  - A ticket whose create call timed out is found again in ITFlow instead of opened twice.
  - Known-exploited is decided from the CISA KEV list, not the finding's title. A finding added to the KEV list after
    tickets were turned on gets a ticket.
  - "Also open tickets for existing Fail findings" no longer sends a weekly Warnings ticket to every client at once.
    The weekly list always shows the new warnings first.

### 1.18.0 (2026-11-23): ITFlow tickets from findings

- **Findings open ITFlow tickets** (phase 2 of [docs/ROADMAP-itflow.md](docs/ROADMAP-itflow.md)): each Fail, and
  anything known to be exploited, gets its own ticket (High; Urgent when exploited) with what was found, where, the
  evidence, why it matters, how to fix it, the due date and a link back to Sentinel.
- Never two tickets for one finding; a finding that becomes known-exploited adds an internal note.
- Warnings are grouped into one ticket per client a week, when there are new ones.
- Tickets are internal (ITFlow doesn't email the client). Turning tickets on covers findings from then on; one button
  opens tickets for the existing Fails too. The finding page shows its ticket.
- Next: Sentinel resolves tickets it sees fixed, and closing a ticket in ITFlow makes Sentinel recheck (done in
  1.19.0).

### 1.17.0 (2026-11-22): clients from ITFlow

- **ITFlow client sync** (phase 1 of the ITFlow plan, see [docs/ROADMAP-itflow.md](docs/ROADMAP-itflow.md)): every
  15 minutes new ITFlow clients are added to Sentinel with their ITFlow ID, renames are applied, and archiving or
  unarchiving in ITFlow is followed. A new client is never scanned until its written authorisation is recorded.
- A Sentinel client with the same name is linked instead of duplicated; a client you archived yourself stays archived.
- With MSP Align connected, clients are linked to MSP Align automatically by their ITFlow ID.
- **Administration → Integrations → ITFlow**: address and API key (encrypted), Test connection and Sync now.
- Next: tickets from findings in ITFlow, and closing them from ITFlow.

### 1.16.0 (2026-11-22): compliance from MSP Align

- New **Compliance** page for each client: the frameworks assigned to it in MSP Align, and for every control in an
  area Sentinel checks, either the open Sentinel findings that affect it, "no problems found" (with what was
  checked), or "not checked yet". Read-only: control statuses stay in MSP Align.
- Findings are matched through MSP Align's crosswalk tags, so one mapping covers CIS, NIST CSF, HIPAA, CMMC,
  ISO 27001, PCI DSS, SOC 2, cyber insurance and custom frameworks.
- **Administration → Integrations → MSP Align**: address and API key (encrypted; a read-only key with
  clients:read and compliance:read is all it needs), with Test connection. Admins link each client on its
  Compliance page; the same name is suggested first.

### 1.15.0 (2026-11-22): tabbed settings and vulnerability data on demand

- **Administration → Settings** is now in tabs: General, Alerts, Fix due dates, Report branding and Vulnerability
  data. Links and saves land on the right tab.
- **Refresh now** for vulnerability data (CISA KEV, NVD, EPSS) in the Vulnerability data tab: it starts within
  5 minutes, and the tab shows when it is waiting, running and finished.
- **No more waiting for the first download:** the built-in scheduled job now checks every 5 minutes and refreshes when
  due (daily), so a new server has its vulnerability data within minutes of installing instead of the next morning.
  Existing servers pick up the new schedule with their next update. The health check no longer asks you to add a
  cron job that is already there.

### 1.14.0 (2026-11-22): NinjaOne

- **NinjaOne connector**, read-only, built on NinjaOne's published Public API 2.0. Every 6 hours, each linked client
  gets its computers with operating system (and its support date), antivirus, disk encryption (BitLocker), missing
  Windows updates and installed software, matched to known vulnerabilities. Findings follow the same grades as
  everything else.
- **Administration → Integrations**: enter your NinjaOne instance, client ID and client secret (encrypted, never
  shown again), with step-by-step instructions for the NinjaOne API app (Monitoring scope, Client credentials) and a
  **Test connection** button. Link each client to its NinjaOne organisation on the client's Devices page.
- Honest by design: anything NinjaOne doesn't report stays "unknown" rather than becoming a finding, and a sync with
  a failed page changes nothing.

### 1.13.1 (2026-11-22): Update now fixes

- Clicking **Update now** again within 15 minutes now says when the next update can start, instead of seemingly
  doing nothing.
- Quick repeated clicks no longer switch the server's update helper off (a too-strict systemd limit was removed;
  the helper's own one-update-per-15-minutes rule stays).
- An upgrade no longer stops at "Service files" when that helper is stuck; it resets it, or warns and carries on.
- If a request is not picked up, the System page says how to fix it on the server and lets you remove the request.

### 1.13.0 (2026-11-22): client pages

- Opening a client now switches the left menu to **that client's own menu**: Overview, Findings, External (scans and
  ports, vulnerabilities, certificates and web, website and email), Internal (agents, devices) and Manage
  (authorisations, discovery, reports), with **All clients** to go back. No more one long page.
- Each section is its own page with its own address (for example `/clients/12/devices`), and only loads what it shows.
- The client's forms and device pages keep the client menu; actions return you to the page you were on.

### 1.12.1 (2026-11-22): one-click Update now

- **Update now** is a one-click admin action again (with an "Are you sure?" prompt): no password or 2FA code. The
  server still only runs the normal update (backup first), at most once every 15 minutes, and every request is in
  the audit log.

### 1.12.0 (2026-11-22): update from the web interface

- **Update now** under **Administration → System**, on development and production servers installed with the
  one-line command. It asks for your password and a 2FA code, then runs the same `msp-sentinel-update` as on the
  server (backup first, fetch, database changes, health check) and shows its progress and output.
- The web app still runs without privileges: it only leaves an empty request file, and a small root-owned systemd
  service on the server runs the fixed update command. Admin-only, rate-limited and audited. Turn it off on the
  server with one command (see [docs/upgrade.md](docs/upgrade.md#from-the-web-interface)).
- **Update available** notice: servers that follow a branch see how many new commits it has since their install
  (part of the daily update check, or **Check now**).
- Existing servers get both with their next `sudo msp-sentinel-update`.

### 1.11.0 (2026-11-22): demo data

- **Demo data** for trying Sentinel out, testing or training: four made-up clients with findings of every kind
  (open, assigned, overdue, accepted, false positive and fixed), an on-premises agent with devices and risky
  protocols, inventory devices with patches and installed software, scan history, 90 days of trends and two reports.
- Load or remove it under **Administration → System → Demo data**, or on the server with
  `sudo -u sentinel php /opt/msp-sentinel/bin/demo.php --load` (`--remove`, `--status`).
- **Demo clients are never scanned.** They use `*.example` names and documentation-only addresses, carry a Demo
  badge, and every scan path refuses them: scheduled and manual scans, verify fix, discovery, agent jobs, inventory
  sync and vulnerability look-ups. Removing demo data deletes only demo clients and what belongs to them.

### 1.10.0 (2026-11-22): development servers

- **One-line install for a development server** that follows the `develop` branch, so changes can be tried before
  they reach production:
  `curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/develop/install-dev.sh | sudo -E bash`.
  `sudo msp-sentinel-update` keeps it on `develop`.
- Development servers show a **Development build** badge on every page. Administration → System shows the branch
  and commit of every install made with the one-line installer.
- See "Development server" in [docs/install.md](docs/install.md).

### 1.9.0 (2026-11-22): guided install

- The one-line install is now a **seven-step guided install** with a summary to confirm before anything changes:
  host name, HTTPS, firewall, fail2ban, automatic security updates, backup encryption and the first admin.
- **Three HTTPS choices:** Let's Encrypt, self-signed, or **behind a reverse proxy** (Sentinel listens on plain HTTP
  for the proxy's address only and trusts its forwarded headers).
- **Server hardening by default:** ufw firewall (SSH rate-limited), fail2ban for SSH, and Debian's automatic security
  updates. Each can be turned off.
- **Encrypted backups from day one:** set a backup passphrase during install.
- Every answer can also be given as a `SENTINEL_*` environment variable for unattended installs. New installer
  options: `--tls`, `--proxy-ip`, `--no-firewall`, `--no-fail2ban`, `--no-auto-updates`.
- Step-by-step guide in [docs/install.md](docs/install.md).

### 1.8.0 (2026-11-22): one-line install on Debian 13

- **One-line install** on a fresh Debian 13 VM:
  `curl -fsSL https://raw.githubusercontent.com/MSP-ALIGN/MSP-Sentinel/main/install.sh | sudo -E bash`. It asks for the
  host name, certificate and first admin (or takes them from environment variables for unattended installs), and adds
  `sudo msp-sentinel-update` for upgrades.
- The same for on-premises agents: `install-agent.sh`, with `sudo msp-sentinel-agent-update`.
- **Debian 13** is now the recommended system (it ships PHP 8.4, so no extra package source is needed). Debian 12 and
  Ubuntu 24.04 still work.
- The installers ask their questions on the terminal, so they also work when piped from `curl`.

### 1.7.0 (2026-11-22): risky internal protocols

- The on-premises agent now checks each device of a full scan for risky protocols, read-only:
  - **Fail:** SMBv1 enabled, Telnet open, SNMP answering the default "private" community.
  - **Warning:** SMB signing not required, Remote Desktop without Network Level Authentication, FTP open, SNMP
    answering "public", login pages over plain HTTP.
- No logins: SMB and RDP are read from the protocol negotiation. The SNMP check sends one read request with the
  default community names. A check that can't decide is never a finding.
- Plain-English explanations and fixes in reports; findings show on the device page.

### 1.6.0 (2026-11-22): on-premises agents

- **Internal scans** from a small Linux appliance at the client's site (Ubuntu 24.04 or Debian 12). The agent only
  connects out to Sentinel. Weekly full scans (devices, open services and versions, certificates, start pages) and
  daily light sweeps, inside the scan window; admins can scan now with a reason.
- **Signed scope:** each site gets an internal authorisation (private networks only, size-limited) that Sentinel
  signs with a key outside the database. Every job is signed too; the agent checks both signatures and refuses any
  target outside the signed networks. Results outside the authorisation are ignored.
- **Findings:** vulnerable services (distribution builds never "confirmed"), and certificates that are expired,
  accept TLS 1.0/1.1 or use a weak key. **New-device alerts** after a site's first (baseline) scan, unless NinjaOne
  already knows the device.
- **Control:** one-time enrolment codes, revocable agents, a kill switch per site, and an installer with a hardened,
  unprivileged systemd service. See [`docs/agent.md`](docs/agent.md).
- **Internal devices groundwork** for NinjaOne: installed software matched to vulnerabilities (one finding per device
  and program), unsupported Windows versions, antivirus, disk encryption and missing updates, with an Internet /
  Internal filter on the findings list. The NinjaOne connector itself follows in a later release.

### 1.5.0 (2026-11-22): fix workflow

- **Owners:** technicians and admins assign findings to an active technician or admin ("Assign to me" for yourself).
  The new owner gets a notification and an email. Viewers see owners but can't change them.
- **Due dates** for every open finding: known-exploited 7 days, other Fail 14 days, Warnings 30 days, counted from when
  it was first seen or reopened. Admins change the days in Settings, or set one finding's date with a reason.
  Accepted risks and false positives are never due.
- **Overdue at a glance:** overdue and due-soon badges, owner and due filters, and quick links ("Assigned to me",
  "Unassigned", "Overdue", "Due within 2 days").
- **Daily reminders** after 07:00 UTC: each owner's overdue and due-soon findings (one note and one email), and an
  overdue summary per client for the team addresses and webhook.
- **Verify fix:** recheck one finding straight away (one address and port, or one domain's email records), also
  outside the scan window, only while it is in scope and scanning isn't paused. Once every 10 minutes per finding.
  Resolves the finding when the problem is gone.
- The API returns each finding's owner and due date.

### 1.4.0 (2026-11-22): website and email security

- **Website checks** run with each port scan and once a day: HTTP to HTTPS redirects, logins served without
  encryption, security headers (HSTS, Content-Security-Policy and others), cookie flags and directory listings.
- **Exposed files**: a short fixed list of paths (/.git/HEAD, /.env, backups and database dumps, /phpinfo.php,
  /server-status, /.DS_Store). A file is only reported when its content proves it, so sites that answer every address
  with a page aren't flagged. File contents are never stored.
- **CMS and libraries**: WordPress, Drupal, Joomla, jQuery, Bootstrap, AngularJS, Lodash, Moment.js and Vue.js are
  recognised from page markup; visible versions are matched to known vulnerabilities (confirmed), and unknown
  versions only to known-exploited ones (possible).
- **Email security**: SPF, DMARC and DKIM (common selectors) for each authorised domain that receives email, by DNS
  only. A new **Email security** finding type.
- A **Website and email security** card on the client page, and plain-English explanations and fixes in reports.

### 1.3.0 (2026-11-22): Administration as its own section

- The left menu now holds only day-to-day work: Dashboard, Clients, Findings, Reports and Help.
- **Administration** moved to the user drop-down (top right) for admins: Overview, Users, Settings, API, System and
  Audit log. Admin pages have their own left menu, clearly marked, with a "Back to Sentinel" link.
- A new **Administration overview** shows each area with its key status: active users, email and webhook,
  API tokens and events, system health and updates, and recent audit activity.

### 1.2.0 (2026-11-22): command-view dashboards

- The **dashboard** is now a command view: a threat-level gauge (the highest client risk), totals, a 90-day trend,
  every client ranked by risk, the worst open findings, a live activity feed, the attack surface by type of service,
  certificates expiring in the next 30 days, and an operations strip (scanning armed or paused, worker, threat
  feeds, scans running, scan windows, authorisations).
- Every **client page** opens with its own overview console: risk gauge, totals, a scan-window countdown, trend,
  attack surface, recent activity and expiring certificates.
- A simple **risk score** (0-100, higher is worse): 20 per open known-exploited Fail, 10 per other Fail, 2 per
  Warning, capped at 100. The formula is in Help.
- Dashboards **refresh every minute** while visible, from Sentinel's own server only.
- Charts are drawn on the server as SVG with text labels; severity still comes with icons and words.

### 1.1.0 (2026-11-22): console look and new logo

- A new **dark "operations console" look** for the web interface: near-black panels with ember accents, angular
  cards, a subtle grid, uppercase headings in Chakra Petch and data in JetBrains Mono (both bundled locally under
  the SIL Open Font License, so nothing loads from other sites).
- A new **logo**: an original "radar iris" eye in a hexagon, used in the menu, on the sign-in page and as the
  browser icon. Its radar sweep is still for anyone who prefers reduced motion.
- **Dark by default, light per user:** choose under My profile → Appearance.
- Severity still never relies on colour alone, and client reports keep their clean, printable, MSP-branded style.

### 1.0.0 (2026-11-22): first stable release

- **Ready for other MSPs to install:** a release archive with checksums, and an installer for Ubuntu 24.04 and
  Debian 12 (Nginx, PHP-FPM 8.4, MariaDB, Let's Encrypt or self-signed HTTPS, cron, log rotation) with `--upgrade`
  and `--dry-run`.
- **Health check:** Administration → System and `bin/doctor.php` check PHP, the database, migrations, nmap, the
  worker, the feeds, storage, HTTPS, email and updates.
- **Backup and restore:** `bin/backup.php` (database, config and logo; optional passphrase encryption; keeps the
  newest N) and `bin/restore.php` (checks every file against its manifest first; dry run unless `--yes`). The installer sets up daily
  backups.
- **Update check:** once a day the worker asks the releases feed for the latest version; admins can turn it off.
- **Data retention:** choose how many months to keep scan history, resolved findings and reports. The audit log is
  always kept.
- **Documentation** in `docs/`: install, upgrade, configuration, security, backup, operations, API and a user guide.

### 0.10.0 (2026-11-22): API

- A JSON **API** at `/api/v1` for MSP Align and other tools: clients, summaries, assets with open services,
  findings (with history), scans and reports (including the frozen HTML and CSV). Lists are paginated and accept
  `updated_since`. The OpenAPI description is at `/api/v1/openapi.json`.
- **Tokens** are created by admins under Administration → API and shown once. Each token:
  - covers all clients or a chosen list;
  - expires (30 to 365 days) and can be limited to IP addresses or networks;
  - can always read; **triage** and **queue scans** are separate permissions, off unless ticked;
  - stops working if revoked, or if the admin who created it is deactivated or is no longer an admin.
- API scans follow the same rules as the web: scope, pauses and the client's scan window (no override).
  Triage needs a note and is marked with the token's name. Every API change is in the audit log.
- 120 requests a minute per token; repeated failed attempts from one address are blocked for a while.
- **Outbound events**: Sentinel can POST signed JSON when findings open, reopen, escalate, resolve or are triaged,
  when a scan finishes and when a report is created (`X-Sentinel-Signature: t=…,v1=HMAC-SHA256`).

### 0.9.0 (2026-11-22): reports

- Two reports per client, in your branding:
  - **Executive summary** for the client's management: an overall rating (Good, Needs attention or At risk), the
    top 5 risks in plain English ("what it means for you" and "what we're doing"), totals, a trend chart and what
    was checked;
  - **Technical findings** for IT: every open finding grouped by severity and host, with its evidence, CVE, KEV and
    EPSS data, why it matters and how to fix it, plus what was fixed this period and an appendix with scope, scans
    and methods.
- **Accepted risks and false positives** are listed in their own section with their notes, never hidden, and they
  don't count towards the totals.
- **Frozen**: each report is saved exactly as it was created, with a SHA-256, so you can show what a client was
  sent. Technicians and admins create reports; everyone can read them; admins can delete them.
- **Print to PDF** from the browser (A4 or Letter), download a self-contained HTML file, or download the findings as
  **CSV** (formulas are neutralised).
- **Monthly schedule** per client: both reports are created after each month and emailed, attached, to the MSP
  staff you choose for review before forwarding.
- **Branding** under Settings → Report branding: company name, logo (checked and re-encoded), accent colour, footer
  text, paper size, and an optional "Generated by MSP Sentinel" line.
- Severity is never shown by colour alone, and every report states its limits: external checks only, not a PCI ASV
  scan.

### 0.8.0 (2026-11-22): alerts

- **Immediate alerts** when a **Fail** finding is new or comes back. Accepted risks and false positives never alert.
- A **scan summary** (digest) after each scan, and **admin alerts** when a scan or a threat feed fails.
- Three ways to be told:
  - **in-app**: a bell in the header with an unread count, and a Notifications page;
  - **email** over SMTP (STARTTLS or TLS, certificate checked). Each user picks immediate, digest, both or none
    on their profile; up to 5 team addresses get everything;
  - a **webhook** for Teams, Slack or plain JSON. It carries a short summary and a link, never evidence.
- Admins set this up under Settings → Alerts, with test buttons. The SMTP password and webhook address are stored
  encrypted and never shown again.
- Messages go through an outbox with up to 3 tries. The worker and the feeds job send them, so no new cron job is
  needed. Set `app.public_url` in the config so alerts link back to Sentinel.

### 0.7.0 (2026-11-22): findings and triage

- One **findings list** per client, built from everything graded so far: exposed high-risk services,
  certificate problems, exposed admin pages and portals, and vulnerabilities. Only **Fail** and **Warning** items
  become findings; Info items stay in the client panels.
- **Lifecycle**:
  - a finding is **resolved** automatically when a check really sees the problem gone;
  - if the problem comes back, the same finding **reopens** and is marked "reappeared", with its history kept. An
    earlier accepted or false-positive decision is kept when the evidence is unchanged.
- **Triage** (technicians and admins, a note is always required):
  - **accepted risk** stays until the problem goes away;
  - **false positive** reopens by itself if the evidence changes (for example a different version is reported);
  - each finding has a full history, and every decision is in the audit log.
- A **Findings** page across all clients, with filters (client, status, grade, type). There is also a findings card
  at the top of each client page and open Fail/Warning counts on the dashboard.

### 0.6.0 (2026-11-22): vulnerability matching

- Services are matched to CVEs from the product and version they report:
  - when the version is known, NVD decides which CVEs affect that exact version (**confirmed**);
  - when only the product is known, only CISA known-exploited CVEs are shown, marked **product found, version
    unknown**. Never guessed;
  - a Linux distribution build (Ubuntu, Debian, RHEL...) is marked "fix may be backported", never confirmed;
  - only CVEs where NVD marks the product itself as vulnerable are counted.
- **Known exploited (KEV) first**, then critical and high. Each CVE shows its CVSS score, EPSS exploit
  likelihood and ransomware use. Lower severities are counted and can be expanded.
- Grading as agreed: confirmed KEV or critical fails; confirmed high or possible KEV gets a warning.
- **Daily feeds job** (`bin/feeds.php`): CISA KEV catalog, NVD answers (cached 7 days, rate-limited) and FIRST
  EPSS scores. Matching also runs right after each scan. Feed status is on the Settings page. An optional NVD
  API key goes in the config file. NVD's rate limits are respected across processes, and a 403/429 stops
  requests until Retry-After.
- Dashboard tile for confirmed and possible known-exploited vulnerabilities.

### 0.5.0 (2026-11-22): certificates and exposed admin pages

- **TLS certificate checks** after every port scan and once a day (in the scan window): expiry, issuer, self-signed
  or untrusted chain, name match (using in-scope hostnames as SNI), key size, signature algorithm, the negotiated
  protocol, and whether old **TLS 1.0/1.1** is still accepted.
- **Web page detection**: one request for the start page of each open web port (no logins, no path guessing),
  matched against generic signatures:
  - firewall or device admin pages (**Fail**);
  - VPN portals and remote desktop web access (**Warning**);
  - other login pages (**Info**).
- Grading follows the agreed rules: an expired certificate fails; one expiring within 14 days or with weak TLS
  gets a warning. The dashboard counts certificates expired or expiring within 14 days.
- Same safety as port scans: scope, kill switches and window are checked before every connection. Each result
  is logged in the scan log.

### 0.4.0 (2026-11-21): port scanning

- **Scan now** (technicians and admins) and **weekly scans** for every client with an active authorisation.
  Scans run only inside the client's scan window. Admins can run one outside the window by giving a reason,
  which is audited.
- **Gentle by default**: TCP connect scan as an unprivileged user, polite timing, at most 50 packets per second,
  one host at a time, light service/version detection. About 40 default ports, with per-client extras and
  exclusions.
- **Scope is checked before every host.** Hostnames are scanned by their addresses, and only addresses that are
  themselves in an active authorisation. Anything else is skipped and logged.
- Cancel a scan, or pause scanning (client or global), and nmap stops within seconds.
- **Open ports** per client: high-risk services (RDP, SMB, databases, Telnet, VNC...) are marked. There is also
  a **scan log** of every host touched or skipped.
- A queue plus a cron worker (`bin/worker.php`). A web request never runs nmap itself.

### 0.3.0 (2026-11-21): passive target discovery

- **Discover now** on a client (technicians and admins), plus a weekly CLI job (`bin/discover.php`):
  - looks up DNS records (A/AAAA/MX/NS/CNAME) of the domains in scope and a list of common names (www, mail, vpn,
    remote...);
  - checks public certificate logs (crt.sh) and reverse DNS of in-scope addresses.
- It's **passive**: DNS lookups and one public website. Nothing connects to the client's systems. It still
  respects the kill switches and needs an active authorisation.
- **Suggestions, not scope:**
  - only names under the client's own domains are suggested;
  - names at other providers (hosted mail, DNS, CDNs) are listed for information only;
  - addresses reached through an alias at another provider are flagged and left unticked.
- **Approving**: an admin ticks suggestions, and the authorisation form opens with the current scope plus the
  selection. Saving it records the client's approval and replaces the old authorisation.
- Dismissed suggestions stay dismissed. A **Change scope / renew** shortcut pre-fills a replacement authorisation.
- Tests run against a local fake DNS server and a fake crt.sh: no real lookups.

### 0.2.0 (2026-11-21): clients and the "authorised to scan" register

- **Clients** with timezone, scan window, notes and an optional ITFlow client ID. Each client gets a default
  **site**, and admins can add more (with optional ITFlow location IDs). Clients are archived, never deleted.
- **"Authorised to scan" register** (admins only):
  - each record holds who at the client approved scanning (name, role, date), the valid-from and valid-until
    dates (2 years at most), a document reference and the exact scope;
  - scope entries are public IPs, ranges up to /24 (IPv6 /120) and domains (`*.` for subdomains). Private,
    reserved and internal targets are refused;
  - authorisations can't be edited, only revoked with a reason, so the register stays trustworthy as evidence;
  - you're warned when a new entry is already in another client's scope, to catch typos.
- **Kill switches**: pause scanning for one client or for everything. Technicians and admins can pause;
  only admins can resume.
- A **scope check** that every future scan must pass: active authorisation (in the client's timezone), target in
  scope, client not archived or paused, global switch off. It fails closed.
- Dashboard shows clients, active authorisations and authorisations ending within 30 days.

### 0.1.0 (2026-11-21): foundation

- Sign-in with **mandatory two-factor authentication** (any TOTP authenticator app) and one-time recovery codes.
- Roles: **Admin**, **Technician**, **Viewer**.
- User management: add users with temporary passwords, change roles, disable users, reset passwords, reset 2FA.
- **Audit log** of sign-ins, failed sign-ins, user changes and settings changes.
- Settings: product name (white-label) and the source-code link required by the AGPL.
- Security basics on every page:
  - CSRF protection, strict Content Security Policy and no-cache headers
  - session timeouts (30 minutes idle, 12 hours absolute)
  - login throttling
  - 2FA seeds encrypted at rest
- Idempotent database migrations, CLI tools and an end-to-end test suite.
