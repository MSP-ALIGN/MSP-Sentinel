<?php

/**
 * In-app help topics and "What's new" entries.
 *
 * Topics are task-based and short (1.34). Each has a 'section' that groups it on the help page, in this order:
 * 'start' (Start here), 'tasks' (Everyday tasks), 'admin' (Setting up and running Sentinel, for admins) and
 * 'reference' (Reference). Every topic keeps 'title' and 'paragraphs' (a list of strings): the top-bar search
 * (SearchService) reads those two keys. Menu paths are written "Administration → Users".
 *
 * Each release adds an entry to 'releases' (newest first) and updates topics as needed.
 * Trusted text, shipped with the app. It is still escaped when shown.
 */

return [
    'topics' => [
        // ---------------------------------------------------------------- Start here
        [
            'section' => 'start',
            'title' => 'Your first day',
            'paragraphs' => [
                'Sentinel is installed and you have the first admin account. To get from nothing to a first report:',
                '1. Sign in and set up two-factor authentication: scan the QR code with an authenticator app and keep the 10 recovery codes in your password manager.',
                '2. Add a second admin: Administration → Users → Add user. It is your backup if you can\'t sign in, and pen-test engagements are approved by a different admin (unless you turn two-person approval off under Settings → Pen-test engagements).',
                '3. Add a client: Clients → Add client.',
                '4. Record who at the client authorized scanning, and exactly what: open the client and choose Record authorization. Nothing is scanned without it.',
                '5. Scan: click Scan now on the client\'s Overview. The scan runs in the client\'s scan window; until the first scan the client shows "Not scanned yet".',
                '6. Triage: on the client\'s Findings page, give each finding an owner, or accept the risk or mark it a false positive with a note.',
                '7. Report: on the Reports page, create an Executive summary or a Technical findings report for the client, then print it to PDF from your browser.',
            ],
        ],
        [
            'section' => 'start',
            'title' => 'Finding your way',
            'paragraphs' => [
                'The left menu: Dashboard (every client at a glance, ranked by risk), Clients, Findings (across all clients), Pen-test engagements (and any waiting for your approval), Reports, Administration (admins only) and Help.',
                'Open a client and the menu shows that client\'s sections: Overview, Findings, External (Scans and ports, Vulnerabilities, Certificates and web pages, Website and email), Internal (Agents, Devices) and Manage (Authorizations, Discovery, Pen-test engagements, Reports, Compliance). Dashboard, All clients and All findings stay at the top, Help at the bottom. Each page\'s heading is its section, with the client\'s name above it.',
                'Administration (admins) has Overview, Users, Roles, Settings, Integrations, API, System and Audit log. The menu under your name at the top right has My profile, Administration, Help and Sign out.',
                'The search box in the top bar finds clients, findings, hosts, devices, engagements and help topics (see "Searching and filtering"). The bell next to it shows new alerts.',
            ],
        ],

        // ---------------------------------------------------------------- Everyday tasks
        [
            'section' => 'tasks',
            'title' => 'Scanning a client',
            'paragraphs' => [
                'To scan a client: 1. Check it has an active authorization (Manage → Authorizations). 2. Open the client and click Scan now on its Overview (Technician or Admin). 3. Follow progress on Scans & ports.',
                'The scan runs inside the client\'s scan window. Admins can run it outside the window by ticking the box and giving a reason, which is recorded. Every client with an active authorization is also scanned once a week.',
                'One scan checks the open ports, then certificates, web pages, website and email security, and known vulnerabilities. Results appear under External in the client\'s menu; problems become findings. The scan log lists every host Sentinel touched or skipped, and when.',
                'To stop: cancel the scan, or pause scanning for one client (on the client page) or for every client (on the dashboard). Scanning stops within seconds. Technicians and admins can pause; only an admin can resume. Archived clients are never scanned.',
                'Hostnames the client forgot to put in scope: see "Discovering forgotten hostnames". Internal networks: see "On-premises agents".',
            ],
        ],
        [
            'section' => 'tasks',
            'title' => 'Reading and triaging findings',
            'paragraphs' => [
                'A finding is anything Sentinel grades as Fail or Warning: a risky service open to the internet, a certificate problem, an exposed admin page, a vulnerability, a breached account. Info items are not findings; they stay on the client\'s pages.',
                'Open Findings (all clients) or a client\'s Findings. The same problem on several targets of one client is one row ("on 3 targets"); "One row per target" shows them separately. Filter by client, status, grade, type, owner and due date, or type part of a title, target or CVE in Contains.',
                'Open a finding to see its evidence, Why it matters and How to fix, its owner, due date and history.',
                'To decide (Technician or Admin, always with a note): Accepted risk means the client knows and accepts it; it stays accepted until the problem goes away. False positive means it isn\'t really a problem; it reopens by itself if the evidence changes, for example a different version. Reopen undoes either decision. Every decision is in the finding\'s history and the audit log.',
                'To act on findings you pick: switch to One row per target, tick them (or the header box for the whole page), choose the action above the list and click Apply to selected.',
                'To act on a whole group, open its row: assign, accept risk / false positive / reopen with one note, verify fix on each, and (admins) set one due date. Each target stays its own finding: checked, resolved and audited on its own, exactly as if you had clicked each one.',
                'Nobody resolves a finding by hand: it resolves when a check really sees the problem gone, for example a port a complete scan finds closed. A host that wasn\'t scanned keeps its findings, and vulnerability findings wait while new vulnerability data is fetched. A problem that comes back reopens the same finding, marked "Reappeared"; an accepted risk or false positive with the same evidence stays decided.',
            ],
        ],
        [
            'section' => 'tasks',
            'title' => 'Owners, due dates and verify fix',
            'paragraphs' => [
                'To give a finding an owner: open it and pick an active technician or admin, or click Assign to me. The owner gets a notification and an email (unless they chose no emails, or assigned it to themselves). Viewers see owners but cannot change them.',
                'Due dates: 7 days for known-exploited vulnerabilities (CISA KEV), 14 days for other Fails and 30 days for Warnings, from when the finding was first seen or last reopened. Admins change these under Administration → Settings → Due dates, and can set one finding\'s date (with a reason). Accepted risks, false positives and resolved findings are never due. Reopening a decision by hand keeps the original date; a finding that comes back after being resolved gets a new one.',
                'Above the list: Assigned to me, Unassigned, Overdue and Due within 2 days. Each day after 07:00 UTC, owners get one note and one email listing their overdue findings and those due within 2 days; the team addresses and the webhook get a summary per client, including unassigned findings.',
                'To check a fix, click Verify fix. Sentinel rechecks only that finding: one address and port (then its certificate and web checks), or one domain\'s email records. A technician\'s recheck waits for the client\'s scan window (it runs now if the window is open); an admin\'s runs within a minute, even outside the window. It runs only while the target is authorized and scanning is not paused, at most once every 10 minutes per finding, and is logged in the scan log.',
                'The result goes into the history, with a notification: Fixed (rechecked and gone, so resolved), Still present, No longer reachable (nothing answers on the port; the problem itself could not be checked), Already resolved (by another check first) or Not verified (with the reason). Sentinel never says Fixed unless the recheck proved it.',
            ],
        ],
        [
            'section' => 'tasks',
            'title' => 'Searching and filtering',
            'paragraphs' => [
                'The search box in the top bar (the magnifier icon on phones) looks through clients, findings (by title, target or CVE), external hosts (address or name), internal devices (name, DNS name or address), engagements and help topics. Type 2 to 100 characters. Your text is matched literally, anywhere in the field: % and _ are ordinary characters. Findings, hosts and devices of archived clients are left out.',
                'Findings: the Contains filter keeps findings whose title, target or CVE contains your text, together with the other filters.',
                'Audit log (admins): type part of an action, user or detail and click Filter.',
                'Clients, Users, a client\'s Devices, Engagements and this Help page have a filter box that hides what doesn\'t match as you type. Nothing is sent to the server. Help results in the top-bar search open this page with your text already in the box.',
            ],
        ],
        [
            'section' => 'tasks',
            'title' => 'Reports',
            'paragraphs' => [
                'To create a report: Reports in the left menu → Create a report, pick the client, the kind and the period, then Create. Or open the client\'s own Reports page (Manage → Reports). Technicians and admins create reports; everyone can read them.',
                'Executive summary: for the client\'s management, with an overall rating, the top 5 risks in plain English, totals and a trend. Technical findings: for IT, with every open finding, its evidence and how to fix it, what was fixed in the period, and the scope and methods.',
                'To make a PDF: open the report, use your browser\'s Print, then Save as PDF. You can also download it as one HTML file (it works offline) or the findings as CSV for a spreadsheet.',
                'A report is frozen when it is created: it keeps that moment\'s data and branding, so you can always show exactly what a client was sent, and its SHA-256 identifies the exact document. "New" and "fixed" count what changed in the chosen period. Accepted risks and false positives have their own section with their notes, but don\'t count towards the totals or the rating. Each report states its limits: external, non-intrusive checks of the authorized addresses, not a test of internal networks and not a PCI ASV scan. Only admins can delete reports.',
                'Monthly reports (admins): turn them on for a client and enter up to 5 addresses at your MSP. After each calendar month (UTC) both reports are created once and emailed as attachments for review before you forward them; reports over 5 MB are linked instead. A deleted scheduled report is not created again. If creating them fails, admins get a notification and Sentinel retries hourly, up to 5 times. Email must be set up first (Administration → Settings → Alerts).',
                'Branding (admins): Administration → Settings → Report branding sets the company name, logo (PNG or JPEG; checked and re-encoded), accent color, contact details, paper size, and whether the "Generated by MSP Sentinel" line is shown.',
            ],
        ],
        [
            'section' => 'tasks',
            'title' => 'Pen-test engagements',
            'paragraphs' => [
                'An engagement is a time-boxed, deeper test that the client authorizes in writing. What it tests is under "Pen-test tests in detail".',
                'To run one: 1. Open the client → Pen-test engagements → New engagement (Technician or Admin). 2. Enter the name, window (at most 14 days), tests, pace (gentle or normal; all ports needs normal), targets inside the authorized scope, exclusions by address or range, and upload the client\'s signed PDF. 3. Wait for it to be approved (by a second admin, unless two-person approval is turned off). 4. Inside the window, run the external tests (from Sentinel) and the internal tests (through each site\'s agent, 1.27.0 or later). 5. Issue penetration test report.',
                'Approval: a different admin approves, with their password, after checking that the signed document matches the scope. Nothing runs before. The other admins get a notification and a banner on the dashboard, and the Engagements page lists what awaits them. An account the creator created, or whose password or 2FA the creator reset, in the last 30 days cannot approve. With only one admin, add another first, or (an Admin who holds every permission and sees every client) turn two-person approval off under Settings → Pen-test engagements: then whoever creates an engagement may approve it themselves if they may approve engagements, and the page, audit log and report say "single-person approval". Engagements created while the rule was on still need a second person.',
                'Stop engagement (kill switch) ends it for good within a minute. Technicians and admins can stop or cancel an engagement. Demo and archived clients have no New engagement button.',
                'Results: the engagement page lists findings with evidence and fixes. Fails and Warnings also become findings of type "Pen test" (triage, owners, due dates, groups, ITFlow tickets), unless the regular checks already raise the same problem; worth-knowing results stay in the report. For each host and test the newest engagement that ran it decides: a retest that no longer finds a problem resolves its finding; one that did not run that test, or was stopped before that host finished, leaves it open, and open ports from an all-ports test need an all-ports retest. Once the regular scan or the agent has looked again, its result decides. The masked default password stays in the pen-test report. The client\'s services and inventory are not changed. The report is branded and frozen (summary, how findings chain together, scope and authorization, method, findings, systems tested). After fixes, create a retest engagement (This is a retest of) and issue its retest letter: each earlier finding is marked fixed, still open or not retested.',
            ],
        ],
        [
            'section' => 'tasks',
            'title' => '"Are you sure?" prompts',
            'paragraphs' => [
                'Before an action that deletes or changes something for good, contacts a system outside Sentinel, or costs time or quota, Sentinel asks "Are you sure?" and says exactly what will happen.',
                'Examples: pausing or resuming scanning, starting a scan or recheck, decisions on a whole group of findings, revoking an authorization, agent or API token, deleting a report, stopping an engagement, sending a test email or webhook, and updating Sentinel or its agents.',
                'Cancel is selected first. Choose Yes, continue to go ahead. If the dialog can\'t load, your browser\'s own confirmation box is shown instead.',
            ],
        ],
        [
            'section' => 'tasks',
            'title' => 'Alerts and notifications',
            'paragraphs' => [
                'Sentinel tells you straight away when a Fail finding is new or comes back. After each scan it sends a summary of what changed, and admins are told when a scan or a threat feed fails. Accepted risks and false positives never cause alerts.',
                'The bell in the top bar shows unread alerts. Open Notifications to read them, then click Mark all as read.',
                'On My profile, choose which emails you get: immediate alerts, the scan summary, both, or none.',
                'Admins set up email and the webhook under Administration → Settings → Alerts. Email needs a mail server with STARTTLS or TLS (plain connections only to a relay on this server). Up to 5 team addresses get every immediate alert and summary. The webhook posts a short summary and a link to Teams, Slack or any tool that accepts JSON; it must be an https address on the public internet. Use the test buttons to check each one.',
                'The SMTP password and the webhook address are stored encrypted and never shown again; leave the field empty to keep the saved value. Changing the mail server\'s address clears the saved password. Messages that fail are retried up to 3 times, and the last results are listed on the settings page.',
            ],
        ],

        // ---------------------------------------------------------------- Setting up and running Sentinel (admins)
        [
            'section' => 'admin',
            'title' => 'Users and roles',
            'paragraphs' => [
                'To add a user: Administration → Users → Add user. Choose a role (see "Roles and permissions") and give a temporary password. They must change it and set up two-factor authentication when they first sign in.',
                'Resetting someone\'s password or two-factor authentication, and changing their role or turning their access off, ask for your own password first. Each of these signs that user out everywhere straight away.',
                'You cannot change your own role or disable yourself, and the last active admin cannot be removed, so nobody is locked out.',
                'Keep at least two admins: nobody is locked out, and pen-test engagements need a second admin to approve them unless two-person approval is turned off.',
            ],
        ],
        [
            'section' => 'admin',
            'title' => 'Clients and the authorized-to-scan register',
            'old_anchors' => ['clients-and-the-authorised-to-scan-register'],
            'paragraphs' => [
                'Sentinel only scans what a client has authorized. To add a client: Clients → Add client. Then open it, choose Record authorization, and enter who at the client approved it (name, role, date), for which dates, and exactly which addresses and domains.',
                'Scope, one entry per line: public IP addresses (for example 203.0.113.10), ranges up to /24, and domain names. *.client.example includes all subdomains; list client.example as well if the bare domain should be scanned. Private addresses are refused here: internal networks are approved per site on the Agents page.',
                'Refused, because they include other organizations\' names: shared suffixes such as *.co.uk, and wildcards under shared platforms such as *.s3.amazonaws.com. List the client\'s own names there one by one (for example app.azurewebsites.net).',
                'Authorizations cannot be edited: to change the scope or renew, click Change scope / renew on the client\'s Authorizations page. The new one replaces the old one and both stay in the register, so it always shows what was approved and when. Revoke one (with a reason) to stop scanning without a replacement. One lasts at most 2 years, in the client\'s time zone; the dashboard shows those ending within 30 days so you can ask for renewal in time.',
                'Sentinel warns you when an address is already in another client\'s scope: usually a typo that would point scans at the wrong client. Clients added from ITFlow are not scanned until their authorization is recorded.',
            ],
        ],
        [
            'section' => 'admin',
            'title' => 'Discovering forgotten hostnames',
            'paragraphs' => [
                'Discover now on the client\'s Discovery page (Technician or Admin) looks for hostnames and addresses the client probably owns but has not put in scope. It reads DNS records for the domains in scope, tries common names such as www, mail, vpn and remote, searches public certificate logs (crt.sh), and does reverse DNS on in-scope addresses. A weekly job does the same for every client if it has been set up.',
                'It is passive: Sentinel only asks DNS and a public website, never the client\'s systems. It still needs an active authorization and stops while scanning is paused.',
                'Only names under the client\'s own domains are suggested. Names at other companies (a hosted mail service, a DNS provider) are listed under "Names at other providers" for information. Addresses reached through an alias at another provider are marked "Check: maybe third-party" and not ticked by default.',
                'Suggestions are never scanned on their own. To add them: tick them, choose "Add selected to a new authorization" (admins), get the client to approve the additions, enter their details and save. The new authorization replaces the old one.',
                'Dismissed suggestions stay dismissed when discovery runs again; restore them from "Dismissed suggestions".',
            ],
        ],
        [
            'section' => 'admin',
            'title' => 'On-premises agents',
            'paragraphs' => [
                'An agent is a small Linux or Windows machine (or VM) at the client\'s site that finds the devices on the internal network, with their services, certificates and web pages. It only connects out to Sentinel. A full scan runs weekly and a light sweep daily, inside the client\'s scan window (stopped when it closes, continued in the next one); admins can also click Scan now (with a reason).',
                'To add one (admins): 1. On the client\'s Agents page, record the site\'s internal authorization: who approved it, the dates and the private networks (each at most a /16). 2. Prepare a mini-PC or VM on that network: Debian 13, Debian 12 or Ubuntu 24.04, or Windows Server 2022/2025 or Windows 11 (preview); 2 CPU cores, 2 GB memory, 20 GB disk; a VM needs a bridged adapter, not NAT; outbound HTTPS to Sentinel. 3. Click Create an enrollment code (it appears once the authorization is recorded; shown once, valid once for 24 hours). 4. Run the install command shown on the page and follow its checks.',
                'Sentinel signs the authorization and every job; the agent checks both and refuses any target outside the signed networks. Pause on the site stops agent scans within a minute; revoking an agent stops its token at once.',
                'On the Agents page you can also set scan gentleness per site (very gentle, gentle or faster; never beyond nmap\'s normal -T3), how often agents check in, ask for Diagnostics (versions, disk, memory, clock difference, key fingerprint) and Restart.',
                'Updates: Update to x.y.z for one agent, or Update all agents (per client, or under Administration → System). An agent installs only releases signed with the release key it pinned at install, and a root helper checks again. Agents older than 1.22.0 must be upgraded once by hand. The release key (Administration → System) is created once in your browser: the private key downloads as a password-protected file, Sentinel keeps only the public half, and it does not expire. Click Sign this version after each Sentinel update, and paste the expected manifest SHA-256 from the release notes (or from php bin/release-sign.php hash --ref vX.Y.Z on your own computer): your browser signs only if it matches. The root (Windows: SYSTEM) update helper runs from a frozen copy that remote updates never change, so a new release never runs with those rights; a release that changes the helper asks for a one-off manual upgrade. Rotate it with the old key file; Replace it only if the file is lost (agents then need it by hand).',
                'Containers: the agent also runs in Docker (docker/agent/docker-compose.yml: host network, unprivileged, read-only; updated by pulling a new image, so the Agents page shows "Update by pulling image x.y.z" instead of an Update button; NetBIOS name requests are not heard there) and in a Proxmox LXC container (a normal install inside an unprivileged Debian 13 container with nesting on; install/proxmox-agent-ct.sh creates one). Agents show a Docker or LXC badge. Guides: docs/guides/docker-agent.md and proxmox-agent.md.',
                'New Sentinel address: Administration → System → Move agents (with your password). Each agent switches only after the new address signs a challenge with this Sentinel\'s key; nothing secret is sent before. Right after a move it goes back if the new address keeps failing, and while moved it asks its original address every 6 hours, so keep that address working.',
            ],
        ],
        [
            'section' => 'admin',
            'title' => 'Active Directory checks',
            'paragraphs' => [
                'To turn them on (admins, per site, on the client\'s Agents page): enter the domain, the domain controller\'s IP address (inside the site\'s internal authorization), a read-only domain account and its password. The agent then reads the directory at each full scan. Nothing in the directory is changed.',
                'The password never reaches Sentinel in readable form: your browser seals it to that site agent\'s own key (this needs an HTTPS page), Sentinel relays the sealed box and deletes it once the agent confirms (or after 24 hours). To replace it, type a new one; leave the field empty to keep the current one.',
                'Before the first sign-in the agent only fetches the domain controller\'s certificate: check its fingerprint and click Trust this certificate. If the certificate changes, the agent sends nothing until you trust the new one.',
                'The agent remembers the domain controller address it first signed in to for each domain, and never sends the directory password to another address. If the domain controller really moves, delete dc-pins.json in the agent\'s state folder on the agent itself.',
                'Fails: accounts without Kerberos pre-authentication (AS-REP roasting), admin accounts with a service name (Kerberoasting), computers other than domain controllers trusted for unconstrained delegation, and devices heard sending LLMNR/NetBIOS name requests (name poisoning; the agent listens for 2 minutes and never answers). Warnings: other accounts with a service name, more than 5 Domain Admins, admin passwords that never expire, a krbtgt password over a year old, computers without LAPS, LDAP signing not required, admin accounts unused for 90 days. Each finding lists up to 25 names.',
            ],
        ],
        [
            'section' => 'admin',
            'title' => 'Integrations',
            'paragraphs' => [
                'Connect other systems under Administration → Integrations. Sentinel only reads from them, except ITFlow tickets. Changing an integration\'s address clears its saved key: enter the key again for the new address.',
                'ITFlow: every 15 minutes Sentinel adds new ITFlow clients, applies renames, and archives or restores clients archived or unarchived in ITFlow (a client you archived in Sentinel stays archived; changes show in the audit log as itflow-sync). With ticketing on, Sentinel opens, updates and closes ITFlow tickets for findings: see "ITFlow tickets in detail". On ITFlow builds with service boards, new tickets are moved to the board chosen under Integrations (by default the one named Alerts), unassigned so the board\'s own rules pick them up; on stock ITFlow they stay where ITFlow puts them.',
                'Only some ITFlow clients: tick "Only sync ITFlow clients with this tag" under Integrations and tag those clients in ITFlow (default tag Sentinel, any case). Untagged clients are not added, and ones already here are archived (restored when the tag comes back). Tag the clients first: the first sync archives every linked client without the tag. If the tags can\'t be read, no client tag has that name, or no client has it, the sync stops and changes nothing; only client tags count. To leave one client out entirely, tick "Don\'t sync with ITFlow" on its Edit page: no renames, archives, restores, MSP Align linking by ITFlow ID or ITFlow tickets for it, and an ITFlow client of the same name is not added. Tickets already open in ITFlow are no longer followed; when the switch is turned off again, only findings from then on get tickets.',
                'Sign in with Microsoft, set up automatically: under Integrations, enter your password and click Create setup code, then run the PowerShell command shown on any Windows PC and sign in at Microsoft as an Entra admin. The script creates the app registration (sign-in permissions only), adds a 12-month client secret and sends everything to Sentinel with the one-time code; then turn the switch on. Sentinel reminds admins 30 and 7 days before the secret expires: run the script again with a new code to renew it. A run signed in to another tenant than the saved one changes nothing, unless you ticked "Switch to another Microsoft tenant" for the code (that clears every user\'s Microsoft link and turns password sign-in back on for them).',
                'MSP Align: connect it, then link each client on its Compliance page (see "Compliance").',
                'NinjaOne: create an API app with the Monitoring scope and the Client credentials grant, connect it, then link each client to its NinjaOne organization on the client\'s Devices page. Sentinel reads devices, operating systems, antivirus, BitLocker, missing Windows updates and installed software every 6 hours, and changes nothing in NinjaOne. Network devices, phones and devices waiting for approval are left out.',
                'Breach monitoring (XposedOrNot): verify each client domain in your XposedOrNot account (verified domains are domains you have proved you own there, by a DNS record or email), then paste the API key and tick Check weekly. The free key is meant for low-volume use; paid xonAPI+ keys work the same way. Check now runs at most once an hour. See "Breach monitoring details".',
            ],
        ],
        [
            'section' => 'admin',
            'title' => 'API and events',
            'paragraphs' => [
                'Other tools, such as MSP Align, can read Sentinel\'s data through the API at /api/v1. Create tokens under Administration → API (with your password). A token never does more than its creator: it can only triage or queue scans if you may, only covers clients you see, shows breached addresses masked unless you may see them, and is cut down when you lose rights. Outbound events carry every client\'s changes, so only someone who sees every client sets them up. A token is shown once: copy it into the other system straight away and send it as "Authorization: Bearer <token>". The API reference page under Administration → API lists every endpoint, and the OpenAPI description (/api/v1/openapi.json) can be downloaded there.',
                'Each token covers all clients or the ones you choose, expires after 30 to 365 days, and can be limited to certain IP addresses. Every token can read; triage and queueing scans are separate permissions, off unless ticked. API scans follow the web rules (only in scope, never while paused, only in the scan window); API triage needs a note, marked with the token\'s name.',
                'A token acts as the admin who created it and stops working when it is revoked or expires, or that admin is deactivated or no longer an admin. Each token can make 120 requests a minute. Its last use (time and address) shows on the API page; every change made through the API is in the audit log.',
                'Outbound events: Sentinel can POST to an https address when findings open, reopen, become a Fail, resolve or are triaged, when a scan finishes and when a report is created. Check the X-Sentinel-Signature header (t=<unix time>,v1=<HMAC-SHA256 of "time.body" with the signing secret>) and reject old timestamps. The signing secret is shown once; you can create a new one at any time. Undelivered events are retried for about two days, so they may arrive late or out of order: use the event id to skip duplicates.',
                'Behind a reverse proxy, list the proxy under app.trusted_proxies in the config, so the API sees callers\' real addresses (for IP allowlists and rate limits).',
            ],
        ],
        [
            'section' => 'admin',
            'title' => 'System, backups and updates',
            'paragraphs' => [
                'Administration → System shows the health of this install: PHP, the database, migrations, nmap, the scan worker and daily feeds job, storage, disk space, HTTPS, email and updates. Fix anything marked Problem first. On the server, php bin/doctor.php runs the same checks.',
                'Updates: once a day Sentinel asks the releases feed for the latest version (nothing else is sent; you can turn this off). Servers installed with the one-line command also show how many new commits their branch has, the installed commit and the newest one. Update now runs the same update as sudo msp-sentinel-update on the server, backing up first, and shows its progress. Branch code is not signed: it is whatever the repository holds when the update runs, so check the commit first if in doubt.',
                'Backups card (Administration → System): the last runs with result, size and encryption. The health check fails, and admins are alerted once a day, when the last backup failed or the last good one is over 2 days old.',
                'Backups are made on the server with bin/backup.php (daily, if installed with the installer). They contain all client data and the app key, so encrypt any copy that leaves the server. A restore with the config keeps this server\'s own program, folder, trust and update settings. See docs/backup.md.',
                'Data retention: choose how many months to keep finished scan history, resolved findings and reports (0 keeps them forever). Older data is removed once a day and the counts go into the audit log. The audit log itself is always kept.',
                'Demo data: load four made-up clients (findings in every state, an agent and devices, scan history, trends and reports) to try Sentinel or train technicians, and remove them again. Demo clients use *.example names and documentation addresses, show a Demo badge and are never scanned. On the server: php bin/demo.php --load or --remove.',
                'Installing: the one-line install asks seven questions (host name; HTTPS with Let\'s Encrypt, self-signed or behind a reverse proxy; firewall; fail2ban; automatic security updates; backup encryption passphrase; first admin) and shows a summary before changing anything. Behind a reverse proxy, Sentinel accepts plain HTTP only from the proxy\'s address and trusts its X-Forwarded-For and X-Forwarded-Proto headers. install-dev.sh installs a separate development server that follows the develop branch and shows a yellow Development build badge; use a separate host name and made-up clients. See docs/install.md.',
            ],
        ],

        // ---------------------------------------------------------------- Reference
        [
            'section' => 'reference',
            'title' => 'Roles and permissions',
            'paragraphs' => [
                'Each user has one role, and a role is a set of permissions. Everyone can see clients, findings, scans, devices, reports and engagements; permissions decide what a user may change (and a few sensitive views: breached addresses in full, the signed engagement document, the audit log).',
                'Built-in roles (can\'t be changed): Viewer sees everything and changes nothing. Technician also runs scans and discovery, triages, assigns and verifies findings, sees breached addresses, creates reports, runs engagements and pauses scanning. Admin holds every permission.',
                'Clients: a user sees every client, or only a list (Administration → Users → the user → Clients: untick "All clients" and pick them). A limited user sees nothing of other clients: their pages answer "not found", and lists, search, the dashboard, reports, engagements, notifications and alert emails leave them out. You can only give clients you see yourself. Org-wide pages and actions (the kill switch for all scanning, settings, integrations, the System page, the audit log) need every client.',
                'Your own roles: Administration → Roles → New role (or Copy a built-in role), tick the permissions, confirm with your password, then give the role to users on their account page. The "Who can do what" table lists every permission and the roles that hold it.',
                'Never more than you hold: you can only tick permissions you hold, give roles whose permissions you all hold, and change, reset or disable users whose role you could give. You can\'t change your own role, built-in roles never change, and at least one active Admin always stays. Permissions marked "Near full control" (agent releases, the system, the API, integrations, users) reach the whole system: give them only to people you would make Admin. API tokens never do more than the person who made them. Everyone with a changed role is signed out so the change applies at once.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Port scans',
            'paragraphs' => [
                'Scans are gentle: an ordinary TCP connection test, polite timing, at most 50 packets per second, one host at a time. Version detection sends a few standard, harmless protocol probes to open ports so the service can identify itself.',
                'Each client is scanned on a default list of about 40 risky and admin ports. Admins can add or exclude ports on the client\'s edit page.',
                'Before each host, Sentinel checks again that it is in an active authorization, that scanning is not paused and that the window is open. Hostnames are scanned through their addresses, and only addresses that are themselves in scope: if www.client.example points at a server that isn\'t (a hosting company, say), it is skipped and the scan log says why.',
                'Open ports show what the service itself reports (product and version), which can be wrong. High-risk services such as Remote Desktop, file sharing (SMB), databases, Telnet and VNC are marked in red.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Certificates and web pages',
            'paragraphs' => [
                'After each port scan, and once a day inside the scan window, Sentinel connects briefly to each TLS service it found. It reads the certificate (expiry, issuer, whether it is trusted and matches the name, key size) and checks whether old TLS 1.0 or 1.1 is still accepted. Mail services that start TLS later in the connection (STARTTLS on ports 25, 587, 143) are not checked.',
                'It requests the start page of each web port once, without logging in, and recognizes from their wording firewall and device admin pages, hypervisor consoles (VMware, Proxmox, XenServer, Nutanix), out-of-band management (iDRAC, iLO, IPMI), NAS admin pages (Synology, QNAP, TrueNAS and others), VPN portals, remote desktop web access and other login pages.',
                'Fail: an expired certificate, or a firewall, device, hypervisor, out-of-band or NAS admin page reachable from the internet. A product named only in the page text is not flagged.',
                'Warning: a certificate expiring within 14 days, self-signed or untrusted certificates, name mismatches, old TLS and weak keys. VPN portals and remote desktop web access are Warnings too: they are often meant to be reachable, so make sure they are patched and use MFA.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Website and email security',
            'paragraphs' => [
                'With each port scan, and once a day inside the scan window, Sentinel checks every website it found: whether HTTP redirects to HTTPS, whether a login form is served without encryption, the security headers (HSTS, Content-Security-Policy and others), cookie flags and directory listings.',
                'It requests a short, fixed list of files often left on websites by mistake: /.git/HEAD, /.env, common backup and database dump names, /phpinfo.php, /server-status and /.DS_Store. A file is reported only when its content proves it (a real git reference, a zip file), so sites that answer every address with a page are not flagged. The content is never stored.',
                'It recognizes WordPress, Drupal and Joomla and common JavaScript libraries (jQuery, Bootstrap, AngularJS, Lodash, Moment.js, Vue.js) from the page markup. A visible version is matched to known vulnerabilities like any other software; Sentinel never guesses a version.',
                'Email: for each authorized domain that receives email (has MX records), Sentinel checks SPF and DMARC and looks for DKIM under common selectors, by DNS only. Domains without MX (or with a "null MX") are not judged. *.client.example covers only subdomains, so client.example is checked only when listed too. An SPF record that hands over with redirect= is not judged; a subdomain without its own DMARC uses its parent\'s record when the parent is also authorized.',
                'DNS (once a day at most): each of an authorized domain\'s own nameservers is asked for a zone transfer (a nameserver that hands out the whole zone lets anyone list every name; only the first part of the answer is read). Each authorized name, and each in-scope name seen on the client\'s addresses, is checked for subdomain takeover: a CNAME to a cloud service such as Amazon S3, GitHub Pages, Heroku or Azure that no longer exists (the cloud name doesn\'t resolve, or one request gets the provider\'s "no such site" page). Both are Fails. Each third party gets one standard request, only public addresses are contacted, and a check that cannot decide keeps the earlier result.',
                'Fail: a login over HTTP, an exposed .git folder, .env file, backup or phpinfo page, and an SPF record that lets anyone send (+all). Warning: a missing HTTPS redirect, HSTS or Content-Security-Policy, insecure cookies, a directory listing, the server-status page, a .DS_Store file, a missing or weak SPF, and a missing or "p=none" DMARC. Info: other headers, and DKIM not found under a common selector (it may use one Sentinel doesn\'t know).',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Vulnerabilities',
            'paragraphs' => [
                'Sentinel matches each open service to known vulnerabilities (CVEs) from the product and version it reports. When the version is known, the US National Vulnerability Database (NVD) decides which CVEs affect exactly that version: these are "Confirmed". A banner can be wrong or hide backported fixes, so check before you act.',
                'Linux distributions (Ubuntu, Debian, Red Hat and others) often fix vulnerabilities without changing the version. When a banner shows a distribution build, matches are marked "Distribution build: the fix may be backported" instead of "Confirmed": check the distribution\'s security notices.',
                'Only CVEs where NVD lists the product itself as vulnerable are matched, not ones where it is merely the platform. Products still waiting for data, or that couldn\'t be looked up, are named: "no matches" is never claimed for them. When only the product is known, Sentinel shows only vulnerabilities known to be exploited (CISA KEV), marked "Product found, version unknown".',
                'Known-exploited vulnerabilities come first, then critical and high ones, each with its CVSS score and EPSS score (how likely it is to be exploited in the next 30 days). Lower-severity matches are counted and can be expanded.',
                'Fail: a confirmed known-exploited or critical vulnerability. Warning: a confirmed high one, or a known-exploited one on a product whose version is unknown. The data refreshes daily (bin/feeds.php); its status is on Administration → Settings.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Internal devices',
            'paragraphs' => [
                'Devices the agent finds get their operating system and type from the network, without logging in: Windows gives its version and build over SMB; other devices are recognized from service banners and web pages (Linux, NAS, printers, firewalls, hypervisors).',
                'One device per machine: when NinjaOne also reports a machine the agent finds (same address, and the same name or none), the Devices list shows one row and the device page combines both. Admins can split a wrong match, or merge an agent device into a NinjaOne device by hand on its page.',
                'Internal devices come from the on-premises agent and, once connected, from NinjaOne. They are on the client\'s Devices page; a device page lists its open services, installed software with known vulnerabilities, and missing updates. After the agent\'s first scan (the baseline), devices never seen before are announced as new, unless NinjaOne already knows them.',
                'Agent findings: known vulnerabilities in the services found (distribution builds are never "confirmed"), and certificates that are expired, accept old TLS or use a weak key. Self-signed certificates are normal inside a network and are not findings.',
                'Risky internal protocols, checked read-only: SMBv1 enabled, Telnet open and SNMP answering the default "private" community are Fails; SMB signing not required, Remote Desktop without Network Level Authentication, FTP open, SNMP answering "public" and login pages over plain HTTP are Warnings. The SNMP check sends one read request with the default community names.',
                'From NinjaOne: a Windows version without security updates, or antivirus/EDR missing or turned off, is a Fail. Out-of-date antivirus definitions, disk encryption off on a workstation, security updates missing for more than 30 days and failed updates are Warnings. Vulnerable software gets one finding per device and program, graded by its worst CVE.',
                'Only programs in Sentinel\'s software catalog with a clean version number are matched to vulnerabilities; others are listed but not matched. When a program updates before vulnerability data for the new version is available, its findings wait instead of resolving.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Pen-test tests in detail',
            'paragraphs' => [
                'Standard tests: all 65,535 TCP ports, common UDP services (one read-only request each to SNMP, NTP and SSDP), nmap\'s safe service scripts (without vulnerability checks) and read-only anonymous-access checks: FTP, NFS exports, and SMB file shares through an anonymous session with no username (the share list and the number of items in each share\'s top folder; no file is opened, no file names kept). Never password guessing, exploits or anything that changes the systems tested.',
                'Vendor default passwords (optional): needs a second tick confirming the signed authorization explicitly allows it. At most three published vendor defaults per service (FTP, web admin pages with a Basic login, MySQL/MariaDB, PostgreSQL); no username is tried twice on one host, so no account sees more than one failed attempt; 5 seconds apart; stopping at the first success, any lockout, or after 10 minutes per host.',
                'Never tried: Windows services (IIS, WinRM, IIS FTP, pages offering Windows sign-in), SSH, Remote Desktop or directory logins. Running the tests again doesn\'t repeat attempts; a retest tries only the accounts that worked, once each. A working login is closed at once and nothing is read; the report shows the username and the password masked (a•••n).',
                'It also checks whether Redis, MongoDB, Elasticsearch/OpenSearch and Memcached answer without any password. Internal runs of the default-password test need agents 1.29.1 or later.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'ITFlow tickets in detail',
            'paragraphs' => [
                'With ticketing on, each Fail and known-exploited finding opens an internal ITFlow ticket (High, or Urgent when exploited) with what was found, why it matters, how to fix it and a link back. Warnings go into one ticket per client a week when there are new ones; these are informational and not followed. A finding never gets two tickets; the finding page shows its ticket number.',
                'One ticket per issue: the same problem (the same CVE, or the same title) on another target of the same client joins the open ticket with an "also found on" note. A target fixed or decided while others are open gets a note; the ticket is resolved only when all of them are fixed or decided.',
                'Sentinel to ITFlow: when Sentinel no longer sees the problem (or it is marked accepted risk or false positive), the ticket gets a note and is resolved.',
                'ITFlow to Sentinel: when a ticket is resolved or closed in ITFlow while the problem is open, Sentinel checks again. A port or email problem gets a recheck (in the client\'s scan window, with the same limits as Verify fix); a device problem waits for the device\'s next data. Gone: the finding closes. Still there: a resolved ticket is reopened with what Sentinel sees; a closed one (ITFlow can\'t reopen those) is replaced by a new ticket naming the old one. Without a clear answer within 10 days, Sentinel stops waiting and says so on the finding.',
                'A ticket ITFlow refuses (a deleted client, no access) is retried after 1, 2, 4 hours and so on, and the reason shows on the finding; other tickets carry on.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Compliance',
            'paragraphs' => [
                'With MSP Align connected and a client linked on its Compliance page, Sentinel shows that client\'s compliance frameworks. For each control in an area Sentinel checks, it shows the open findings that affect it, "No problems found" with what was checked, or "Not checked yet". Controls Sentinel can\'t see (policies, training, backups) are only counted.',
                '"No problems found" supports a control but does not prove it is met: Sentinel sees only part of what a control asks. Statuses are set in MSP Align; Sentinel never changes them.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Breach monitoring in detail',
            'old_anchors' => ['breach-monitoring-details'],
            'paragraphs' => [
                'Once a week Sentinel asks XposedOrNot which addresses of your verified domains appear in known data breaches. An address goes to the client whose authorization lists its domain (exactly, or under a *. entry); other verified domains are listed on the settings card and ignored.',
                'Each address is one finding: Fail when a breach happened in the last 12 months, Warning when all its breaches are older, with the breach names, dates and what was exposed. Passwords are never stored or shown. Addresses are masked in finding titles, alerts and chat messages, and for viewers; the full address is in the finding\'s details for technicians and admins.',
                'An address no longer listed resolves. A failed check changes nothing and is retried after 6 hours. The client\'s Website and email page lists the breached addresses.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Dashboards and the risk score',
            'paragraphs' => [
                'The dashboard shows every client: the threat level (the highest client risk), totals, a 90-day trend of open problems, clients ranked by risk, the worst open findings, live activity, the attack surface by type of service, certificates expiring in the next 30 days, and a status strip (scanning armed or paused, worker, threat feeds, scans running, scan windows, authorizations). Each client\'s Overview is the same for that client.',
                'The risk score runs from 0 to 100; higher is worse. It adds 20 for each open known-exploited Fail, 10 for each other open Fail and 2 for each open Warning, up to 100. Accepted risks and false positives don\'t count. The level is the same as in reports: At risk (any open Fail), Needs attention (Warnings only) or Good (nothing open). A client shows "Not scanned yet" until its first scan.',
                'Clients are ranked by level first, then by score, so a client with many Warnings never appears above one with a Fail.',
                'Dashboards refresh themselves every minute while the page is open and visible; "Pause live refresh" holds the view still, and refreshes also wait while you are using a panel. Refreshes don\'t count as activity: an unattended screen still signs out after 30 minutes, and refreshing stops after 30 minutes without input. The trend fills in day by day from when Sentinel started recording. Certificates are counted only on services that are still open.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Audit log',
            'paragraphs' => [
                'Administration → Audit log (admins) records sign-ins, failed sign-ins, user and settings changes, decisions on findings, API changes and other actions. Entries cannot be edited or deleted from the web interface, and the audit log is never removed by data retention.',
                'Type part of an action, user or detail in the box and click Filter to narrow it down.',
            ],
        ],
        [
            'section' => 'reference',
            'title' => 'Signing in and two-factor authentication in detail',
            'old_anchors' => ['signing-in-and-2fa-details'],
            'paragraphs' => [
                'Sign in with Microsoft: when an admin has set it up (Administration → Integrations), the sign-in page shows "Sign in with Microsoft" for your Microsoft 365 work account. Link your account once: sign in with your password and code, then My profile → enter your password → Link my Microsoft account (pick your own account: whoever owns it can sign in as you). Only linked accounts can use it (an email address alone is never enough; guests from other directories never can). Sentinel skips its own code only when Microsoft confirms MFA within the last hour. Your password keeps working too unless an admin turned password sign-in off for you.',
                'Every account must use two-factor authentication (2FA). At first sign-in, scan the QR code with an authenticator app and enter the 6-digit code it shows.',
                'You then get 10 recovery codes: keep them in your password manager. Each signs you in once if you lose your phone. My profile creates new codes, which makes the old ones stop working. If you lose both your phone and your codes, ask an admin to reset your 2FA.',
                'You are signed out after 30 minutes without activity, and after 12 hours in any case.',
                'After 5 wrong passwords, sign-in for that account is paused for 15 minutes, even with the right password. If that happens unexpectedly, tell an admin: the audit log shows where the attempts came from.',
            ],
        ],
    ],
    'releases' => [
        [
            'version' => '1.52.0',
            'date' => '2026-11-25',
            'items' => [
                'Ready for more RMMs: each RMM is described in one place, and the Integrations page draws, saves and tests its card from that, so others can be added later without new pages. NinjaOne works as before. A client is linked to one RMM at a time, so machines never come in twice.',
            ],
        ],
        [
            'version' => '1.51.1',
            'date' => '2026-11-25',
            'items' => [
                'Fixes from review: only someone who sees every client can hide the Getting started checklist; old links to renamed help topics still work; the Authorizations page and dashboard do less work.',
            ],
        ],
        [
            'version' => '1.51.0',
            'date' => '2026-11-25',
            'items' => [
                'Easier navigation: inside a client the menu keeps Dashboard, All clients, All findings and Help; each page\'s heading is its section, with the client\'s name above it, and the browser tab reads "Client · Section"; finding and report pages keep their client\'s menu.',
                'A Getting started checklist on the dashboard (for whoever manages settings), Scan now on the client\'s Overview, internal authorizations listed on the Authorizations page, a Roles card on the Administration overview, and New engagement on the engagements list.',
                'One vocabulary (finding, agent host, two-factor authentication, Pen-test engagements, Time zone), named Save buttons, and US spelling throughout. Web addresses, API fields and settings keep their names.',
            ],
        ],
        [
            'version' => '1.50.1',
            'date' => '2026-11-25',
            'items' => [
                'Fixes from review: a MAC several devices share (a router or VPN server) no longer joins them to one NinjaOne device; a contradicting MAC, a name of a device not seen lately, or a range two sites use (even after an authorization lapses) no longer match; upgraded certificate findings keep their decisions; an accepted Warning that becomes a Fail opens again; only open tickets of archived clients get the note.',
            ],
        ],
        [
            'version' => '1.50.0',
            'date' => '2026-11-25',
            'items' => [
                'Agents and NinjaOne devices are matched by MAC address first, then by an address only one site uses and that NinjaOne saw recently, then by a unique name, so shared ranges and stale addresses never join the wrong machines; a MAC on several addresses (a router) no longer merges them; an expiring certificate that expires stays one finding (Warning to Fail) with its owner and ticket; archived clients\' open ITFlow tickets get a note that they are no longer followed.',
            ],
        ],
        [
            'version' => '1.49.1',
            'date' => '2026-11-25',
            'items' => [
                'Fixes from review: only real operating systems limit a CVE (labels like node.js or WordPress, and other vendors\' "IOS", no longer hide CVEs); Linux distributions count as Linux; "not on this platform" is never read as "only on it"; phones with private MAC addresses aren\'t a new device at each rotation; the one-off refresh of vulnerability data is spread over several runs; ticket history no longer says "confirmed fixed" after a non-fix; a newly linked source alerts and tickets as usual from its first sync.',
            ],
        ],
        [
            'version' => '1.49.0',
            'date' => '2026-11-25',
            'items' => [
                'Accurate data: CVEs limited to other platforms (e.g. Chrome on Android) are no longer reported on Windows PCs; offline devices and empty NinjaOne reports no longer close and reopen findings; an address DHCP gives to another machine no longer inherits the old device\'s record; re-linking a client to another NinjaOne organization retires the old devices.',
                'Calmer alerts and tickets: at most 60 immediate alerts per run; no ticket backlog when a client is linked to ITFlow or restored; tickets for problems Sentinel stopped tracking get an honest note and stay open; interrupted tickets are retried; breached addresses masked in tickets.',
            ],
        ],
        [
            'version' => '1.48.1',
            'date' => '2026-11-24',
            'items' => [
                'Time zone fixes: the activity feeds, certificate check times and report dates use your (or the client\'s) time zone too; after a failed Settings save, the "move clients" button names the zone it really uses; time zone names PHP knows by an older alias are accepted.',
            ],
        ],
        [
            'version' => '1.48.0',
            'date' => '2026-11-24',
            'items' => [
                'Your time zone: set it under Administration → Settings → General, and every time in Sentinel is shown in it, labeled (e.g. 13:33 PST). Users can pick their own under My profile. New clients, also from ITFlow, start in it, and a button moves clients still on UTC. Reports show their client\'s time zone. Times are still stored in UTC.',
            ],
        ],
        [
            'version' => '1.47.2',
            'date' => '2026-11-24',
            'items' => [
                'Time zones: Sentinel shows times in the organization\'s time zone (Administration → Settings → General), or your own if you pick one under My profile; each time is labeled (e.g. PST). New clients, also from ITFlow, start in the organization\'s zone, and a button on the Settings page moves clients still on UTC to it. Scan windows follow each client\'s own time zone; reports show their client\'s zone. Times are stored in UTC, so daylight saving never shifts a scan.',
                'Windows agent: scans failed with "Could not start nmap". The agent now starts nmap the Windows way (the right null device and the environment Windows networking needs) and reads its output without blocking, so the kill switch keeps working during a scan. Upgrade the agent (install-agent.ps1 -Upgrade, or a signed remote update).',
            ],
        ],
        [
            'version' => '1.47.1',
            'date' => '2026-11-24',
            'items' => [
                'Engagement approval fixes: turning two-person approval back on wins over a self-approval in progress; every approver is told when it changes, also those limited to some clients; it is only turned off by an explicit choice; the dashboard and Engagements page wording follow the setting; the awaiting list no longer hides engagements you may approve.',
            ],
        ],
        [
            'version' => '1.47.0',
            'date' => '2026-11-24',
            'items' => [
                'Pen-test engagements: two-person approval can be turned off under Settings → Pen-test engagements (an Admin with every client, with their password; approvers are told). The creator may then approve their own engagement, and the page, audit log and report say "single-person approval". On by default; engagements made under the two-person rule keep it.',
            ],
        ],
        [
            'version' => '1.46.1',
            'date' => '2026-11-24',
            'items' => [
                'Sign in with Microsoft setup fixes: a run signed in to another tenant is refused unless the setup code allows switching; switching tenants turns password sign-in back on for everyone whose Microsoft link it clears; saving is all-or-nothing; the command shown works on Windows PowerShell 5.1; the script asks before changing a tenant, keeps the app\'s other web settings, and waits for a new app to be ready.',
            ],
        ],
        [
            'version' => '1.46.0',
            'date' => '2026-11-24',
            'items' => [
                'Sign in with Microsoft sets itself up: Create setup code on the Integrations page, run the PowerShell command it shows, and the script creates the Entra app (sign-in permissions only, auth_time claim, 12-month secret) and sends its details to Sentinel. Nothing to copy; run it again to renew. Admins are reminded before the secret expires.',
            ],
        ],
        [
            'version' => '1.45.3',
            'date' => '2026-11-24',
            'items' => [
                'Windows agent installer: the free nmap has no silent install, so the installer now opens nmap\'s setup window, says to untick Npcap, and waits up to 30 minutes instead of stopping after 5. Without a desktop (an RMM tool running as SYSTEM) it stops at once and says to install nmap first.',
            ],
        ],
        [
            'version' => '1.45.2',
            'date' => '2026-11-24',
            'items' => [
                'Windows agent: the PowerShell installer stopped with a parse error ("Unexpected token \'PHP\'") before doing anything, because of an unclosed string. Fixed; the test suite now checks every PowerShell script\'s quoting.',
            ],
        ],
        [
            'version' => '1.45.1',
            'date' => '2026-11-24',
            'items' => [
                'ITFlow tag filter fixes: the sync also stops, changing nothing, when no client has the tag or ITFlow doesn\'t say which clients have it; only client tags count. A client set to "Don\'t sync with ITFlow" no longer gets a same-named copy, isn\'t linked to MSP Align by ITFlow ID, and gets no backlog of tickets when the switch is turned off again.',
            ],
        ],
        [
            'version' => '1.45.0',
            'date' => '2026-11-24',
            'items' => [
                'ITFlow: sync only the clients with a chosen ITFlow tag (default Sentinel). Untagged clients are not added, and ones already here are archived until the tag comes back. If the tag can\'t be read the sync changes nothing.',
                'A client can be left out of ITFlow: "Don\'t sync with ITFlow" on its Edit page stops renames, archives and ITFlow tickets for it.',
            ],
        ],
        [
            'version' => '1.44.1',
            'date' => '2026-11-24',
            'items' => [
                'ITFlow boards fixes: the Integrations page no longer waits on ITFlow (the board list is read by Test connection, the sync and ticket runs); a ticket found again later is not moved or unassigned if a tech may already have it; a chosen board that ITFlow no longer lists is reported; "Alerts" matches with spaces and picks the first.',
            ],
        ],
        [
            'version' => '1.44.0',
            'date' => '2026-11-24',
            'items' => [
                'ITFlow service boards: on ITFlow builds with boards, Sentinel moves each new ticket to the board chosen under Administration → Integrations (by default the one named Alerts), unassigned so the board picks it up. Stock ITFlow is unaffected; a refused move keeps the ticket on the default board and the run says so.',
            ],
        ],
        [
            'version' => '1.43.2',
            'date' => '2026-11-24',
            'items' => [
                'Linking a Microsoft account needs your password and no existing link; the linked account is named on My profile and you are notified. An admin\'s password or two-factor reset removes the link; unlinking an SSO-only user turns password sign-in back on. Tip: add the auth_time optional claim so Sentinel can skip its code after MFA.',
            ],
        ],
        [
            'version' => '1.43.1',
            'date' => '2026-11-24',
            'items' => [
                'Sign in with Microsoft is safer: each user links their own Microsoft account under My profile while signed in (no more linking by email address); only an Admin who sees every client can change its settings, with their password, and a new tenant clears all links; guests from other directories are refused; Sentinel\'s code is skipped only for MFA within the last hour.',
            ],
        ],
        [
            'version' => '1.43.0',
            'date' => '2026-11-24',
            'items' => [
                'Sign in with Microsoft: your team signs in with their Microsoft 365 work account (Entra ID; set up under Administration → Integrations). Only existing users, linked by email address the first time; Sentinel\'s code is skipped only when Microsoft confirms MFA; passwords stay as a fallback and can be turned off per user (never for the last Admin).',
            ],
        ],
        [
            'version' => '1.42.2',
            'date' => '2026-11-24',
            'items' => [
                'Breached addresses: reports (view, download, CSV, and through the API) and alerts show them masked unless you may see them; masked API keys stay unique.',
                'One MSP Align or ITFlow client per Sentinel client, also for the ITFlow sync and in the database; an old duplicate no longer blocks editing a client.',
                'Backup and feed notices go only to people who see every client; notifications are cleared only when your clients shrink. The user form\'s client choice is laid out properly.',
            ],
        ],
        [
            'version' => '1.42.1',
            'date' => '2026-11-24',
            'items' => [
                'Client lists fixes: org-wide pages and actions (pausing all scanning, settings, integrations, the System page, the audit log) need every client; an MSP Align or ITFlow client links to one Sentinel client only; counts, owners, approvers and notifications on the Findings and Engagements pages stay within your clients; earlier notifications are cleared when your clients are narrowed.',
            ],
        ],
        [
            'version' => '1.42.0',
            'date' => '2026-11-24',
            'items' => [
                'API tokens follow your permissions and clients: a token only covers clients you see (and is cut down when you see fewer), shows breached addresses masked unless you may see them, and can only triage or queue scans if you may. You see and revoke only tokens within your clients; outbound events need someone who sees every client.',
            ],
        ],
        [
            'version' => '1.41.0',
            'date' => '2026-11-24',
            'items' => [
                'Limit a user to some clients: under Administration → Users → Clients, untick "All clients" and pick theirs. They see nothing of other clients (pages, lists, search, dashboard, reports, engagements, notifications and alert emails). Everyone keeps every client on upgrade.',
                'You can only give clients you see yourself; findings can only be given to someone who sees the client; a client a limited user adds becomes theirs.',
            ],
        ],
        [
            'version' => '1.40.1',
            'date' => '2026-11-24',
            'items' => [
                'Roles fixes: API tokens can only triage or start scans if their creator may (and lose those rights when the creator does); one active built-in Admin always stays; checks run again at the moment of saving; the Administration overview and System page show only what you may use; breached addresses on a finding are masked without "See breached addresses"; powerful permissions are marked "Near full control".',
            ],
        ],
        [
            'version' => '1.40.0',
            'date' => '2026-11-24',
            'items' => [
                'Roles and permissions: every action needs one of 27 permissions in 7 groups. Viewer, Technician and Admin stay as built-in roles with exactly the rights they had. Make your own roles under Administration → Roles (or copy a built-in one), and see who can do what in one table.',
                'Never more than you hold: you can only give permissions and roles you hold yourself, and can\'t change, reset or disable a more powerful user. You can\'t change your own role, and someone always holds every permission.',
                'Alerts, assignment and approvals follow permissions: system alerts go to those who manage the system, findings can be given to anyone who may triage, and any second person who may approve engagements can approve.',
            ],
        ],
        [
            'version' => '1.39.1',
            'date' => '2026-11-24',
            'items' => [
                'Pen-test findings: a retest stopped before a host finished, or that skipped a test, no longer resolves findings; open ports from an all-ports test need an all-ports retest; once the regular scan or the agent has looked again, its result decides (no old result comes back after a fix); the masked default password stays in the pen-test report; a long share name with accents no longer stops the client\'s findings from updating.',
            ],
        ],
        [
            'version' => '1.39.0',
            'date' => '2026-11-24',
            'items' => [
                'Pen-test results become findings: each Fail and Warning of an approved engagement is a finding of type "Pen test" with triage, owners, due dates, groups and ITFlow tickets. A retest resolves what it no longer finds; what it did not test stays open. Problems the regular checks already raise are not doubled.',
                'Devices: unlinking NinjaOne, or its organization moving to another client, shows the agent\'s merged devices again at once. A Windows version seen from the network is a Warning (edition unknown), and builds that also ship as long-term editions are not judged. Samba servers are no longer shown as Windows. A device without a host name gets the name its NTLM answer gives and can be matched. A scan without the NTLM answer no longer overwrites the known Windows build.',
                'The device page lists each port once and shows protocol issues from the merged agent device; the device list counts findings faster (migration 0045).',
            ],
        ],
        [
            'version' => '1.38.0',
            'date' => '2026-11-24',
            'items' => [
                'Devices the agent finds get their operating system and type from the network (Windows version over SMB without logging in; banners for Linux, NAS, printers, firewalls). Windows 11 machines show as workstations.',
                'One device per machine: a machine both the agent and NinjaOne report shows as one row with a combined page; admins can split or merge by hand.',
                'Fixes to 1.37: the bulk action panel starts with no action chosen; backups can be marked as made another way (no warning or alert); a backup run stopped by a missing passphrase is recorded.',
            ],
        ],
        [
            'version' => '1.37.0',
            'date' => '2026-11-24',
            'items' => [
                'Backups card on Administration → System (each run: result, size, encryption); the health check and a daily admin alert say when a backup failed or the last good one is over 2 days old.',
                'Pick findings yourself: in One row per target, tick findings and apply one action to them (assign, triage, due date, verify fix).',
                'The Clients list shows each client\'s risk and open findings.',
            ],
        ],
        [
            'version' => '1.36.1',
            'date' => '2026-11-24',
            'items' => [
                'Docker agents: up, pull and logs no longer need SENTINEL_SERVER; a revoked agent stops for good; the enrollment code is hidden while typed. Proxmox LXC without nesting: the agent now starts with the relaxed settings, and the installer checks it started. Smaller fixes to the Proxmox helper and the image workflow.',
            ],
        ],
        [
            'version' => '1.36.0',
            'date' => '2026-11-24',
            'items' => [
                'Agents in Docker: run the agent as an unprivileged, read-only container with host networking (docker/agent/docker-compose.yml). Docker agents are updated by pulling a new image, so the Agents page says "Update by pulling image x.y.z" instead of offering an in-place update.',
                'Agents on Proxmox: the normal installer works in an unprivileged Debian 13 LXC container (it checks systemd\'s sandbox and warns if nesting is off); install/proxmox-agent-ct.sh creates a suitable container. Agents show a Docker or LXC badge.',
            ],
        ],
        [
            'version' => '1.35.1',
            'date' => '2026-11-24',
            'items' => [
                'Windows agents no longer run any of a new release\'s code as SYSTEM during an update (the pre-flight check is the task\'s own). A replaced release key is given to a Linux agent with echo NEWKEY | sudo tee /etc/sentinel-agent/release-key.pub; the installed copy of agent-install.sh refuses --upgrade (use a downloaded release). The protection starts with the update after 1.35: upgrade agents to 1.35 by hand once where that matters. Smaller fixes to logging, clean-up and release hashes.',
            ],
        ],
        [
            'version' => '1.35.0',
            'date' => '2026-11-24',
            'items' => [
                'Agent updates can no longer run new code as root or SYSTEM: the update helper runs from a frozen copy that remote updates never change, and updates no longer rewrite the services. Each agent makes the copy at its next update; nothing to do (on Windows, install-agent.ps1 -Upgrade once if the change can\'t finish on its own).',
                'Sign this version asks for the expected manifest SHA-256 (from the release notes, or php bin/release-sign.php hash --ref vX.Y.Z on your own computer) and signs only if it matches; the hash is kept in the audit log.',
            ],
        ],
        [
            'version' => '1.34.0',
            'date' => '2026-11-24',
            'items' => [
                'Search: a search box in the top bar finds clients, findings (title, target or CVE), hosts, devices, engagements and help. Findings and the audit log have a "Contains" filter; Clients, Users, Devices, Engagements and Help have instant filter boxes.',
                '"Are you sure?" dialogs say what will happen before destructive, outbound or costly actions.',
                'Security audit fixes: creating users and resetting passwords or 2FA, changing roles or access, and creating API tokens ask for your own password; engagement approval refuses accounts linked to the creator; changing an integration\'s address clears its saved key; technicians\' rechecks wait for the scan window; stored secrets are bound to their place; agents send the directory password only to the domain controller they first signed in to; restoring a backup is safer.',
                'Easier workflows: an Engagements page and dashboard banner for approvals, "Why it matters / How to fix" on every finding, reports from the Reports page, clearer first steps, "Not scanned yet" for new clients, an API reference page, and better phone layouts.',
                'Help is reorganized: Start here, Everyday tasks, Setting up, Reference.',
            ],
        ],
        [
            'version' => '1.33.1',
            'date' => '2026-11-24',
            'items' => [
                'Breach monitoring fixes: an answer that would remove most known addresses removes nothing (and says so); only addresses of domains the answer covers are removed; clients with an expired authorization keep theirs; a failed check is retried after 6 hours, and a new key can be checked at once; addresses are masked in finding titles, alerts and chat (and for viewers); archived clients\' breach data is removed.',
            ],
        ],
        [
            'version' => '1.33.0',
            'date' => '2026-11-24',
            'items' => [
                'Breach monitoring: once a week, addresses of your verified domains found in known data breaches (XposedOrNot) become findings for the client whose authorization lists the domain: Fail for a breach in the last 12 months, Warning for older ones. Breach names, dates and what was exposed only; never passwords. Set it up under Administration, Integrations.',
            ],
        ],
        [
            'version' => '1.32.1',
            'date' => '2026-11-24',
            'items' => [
                'Shared ITFlow ticket fixes: a fixed target released by a replacement, or whose ticket lost its leading finding or failed for good, gets a ticket again when it is open; large groups recheck each target once per close instead of looping; no repeated notes after a reopen; per-target notes count against the run limit; known-exploited notes when only other targets are open; the finding page shows the shared ticket\'s state; members are not listed in the weekly Warnings ticket.',
            ],
        ],
        [
            'version' => '1.32.0',
            'date' => '2026-11-24',
            'items' => [
                'ITFlow: one ticket per issue. The same problem on another target of a client joins the open ticket with an "also found on" note; the ticket follows every target, gets a note when one is fixed, is resolved only when all are fixed or decided, and is reopened (or replaced for the targets still open) when one is still there after ITFlow closes it.',
            ],
        ],
        [
            'version' => '1.31.1',
            'date' => '2026-11-24',
            'items' => [
                'Grouped findings fixes: reports group exactly like the list (an issue with Fail and Warning targets is one entry under Fail) and store each finding once; the assignee\'s email says how many findings were assigned; a group\'s due date can be reset to the policy; one finding that can\'t be rechecked no longer stops a bulk verify; due-date filters sort groups by deadline; large groups load faster.',
            ],
        ],
        [
            'version' => '1.31.0',
            'date' => '2026-11-24',
            'items' => [
                'Repeated findings are grouped: the same CVE or problem on several targets of a client is one row in the Findings list, with actions for all of them at once (assign, accept risk / false positive / reopen, verify fix, and due date for admins). Each target stays its own finding. Reports list each problem once with all its targets. Grouped ITFlow tickets follow in the next release.',
            ],
        ],
        [
            'version' => '1.30.1',
            'date' => '2026-11-24',
            'items' => [
                'Share check fixes: a server that refuses the share list (an empty answer with "access denied") is no longer reported as listing its shares; empty drive roots count as readable with 0 items; a count that didn\'t finish says "at least"; long share names are opened correctly; Samba\'s anonymous sessions are labeled anonymous.',
            ],
        ],
        [
            'version' => '1.30.0',
            'date' => '2026-11-24',
            'items' => [
                'Pen-test engagements: the anonymous access test now checks SMB file shares. An anonymous session (no username, nothing to lock) reads the share list and counts the items in each disk share\'s top folder: read only, no file opened, no file names kept. A readable share is a Fail; the share list handed out is a Warning (a Fail from the internet). Internal runs need agents 1.30.0.',
            ],
        ],
        [
            'version' => '1.29.1',
            'date' => '2026-11-23',
            'items' => [
                'Default-password test fixes: no username is ever tried twice on one host (several ports often share one login); Windows services and pages offering Windows sign-in are never tried; re-runs don\'t repeat attempts and a retest re-checks only what worked; a redirect no longer counts as a login; a 10-minute limit per host; more lockout answers recognized.',
            ],
        ],
        [
            'version' => '1.29.0',
            'date' => '2026-11-23',
            'items' => [
                'Pen-test engagements: optional vendor default-password test, only with an explicit authorization tick. At most three published defaults per service (FTP, HTTP Basic admin pages, MySQL/MariaDB, PostgreSQL), each a different account, 5 seconds apart, stopping at any lockout; plus databases open without a password (Redis, MongoDB, Elasticsearch, Memcached). Passwords are only shown masked. External and internal (agents 1.29.0+).',
            ],
        ],
        [
            'version' => '1.28.1',
            'date' => '2026-11-23',
            'items' => [
                'DNS check fixes: zones with a wildcard record are reported as open; a takeover check that can\'t decide keeps the earlier result; only public addresses are contacted; no takeover reports for cloud names nobody else can claim; pauses and scope changes stop the checks within one name, with a 10-minute limit per job; demo clients are never checked. Linux agent updates stop the agent before swapping folders.',
            ],
        ],
        [
            'version' => '1.28.0',
            'date' => '2026-11-23',
            'items' => [
                'Attack-surface checks: open DNS zone transfers (each authorized domain\'s own nameservers, once a day) and subdomain takeover (names pointing at a cloud service that no longer exists) are Fails, shown on the client\'s website card. Hypervisor, out-of-band (iDRAC, iLO, IPMI) and NAS admin pages are recognized, with ports 902, 5000, 5001, 8006 and 9090 added to the default list.',
                'Fix: a Linux agent update stopped half-way (power cut) now repairs itself when the agent starts again.',
            ],
        ],
        [
            'version' => '1.27.1',
            'date' => '2026-11-23',
            'items' => [
                'Pen-test engagement fixes: no SMB share listing (nmap\'s script writes a test file); safe scripts without vulnerability checks; external results are evidence only; all ports need the normal pace; exclusions by address, also left out of the agents\' sweep; the retest letter marks fixed only when the same test ran again.',
            ],
        ],
        [
            'version' => '1.27.0',
            'date' => '2026-11-23',
            'items' => [
                'Pen-test engagements: time-boxed, deeper tests the client signs for (PDF attached), only inside the authorized scope, approved by a different admin, with a kill switch. All TCP ports, common UDP services, safe scripts and anonymous-access checks, externally and through agents (1.27.0+). Ends with a penetration test report and, after fixes, a retest letter.',
            ],
        ],
        [
            'version' => '1.26.2',
            'date' => '2026-11-23',
            'items' => [
                'Windows agent fixes: a fresh install creates and locks its ProgramData folder itself; -Upgrade only trusts folders it made; nmap installs no longer fail on an empty exit code; an interrupted update no longer leaves the service disabled. Agents installed with 1.26.0: run install-agent.ps1 -Upgrade once.',
            ],
        ],
        [
            'version' => '1.26.1',
            'date' => '2026-11-23',
            'items' => [
                'Windows agent fixes: the service has only two privileges (no impersonation); updates run through a launcher outside the code folder so it can be swapped; TLS uses the Windows certificate store; the installer never acts through links or junctions; safer rollback and installer details.',
            ],
        ],
        [
            'version' => '1.26.0',
            'date' => '2026-11-23',
            'items' => [
                'Windows agent (preview): Windows Server 2022/2025 and Windows 11, installed with one PowerShell command shown on the enrollment page; runs as a service under its own low-privilege account; updates from Sentinel through a SYSTEM task that downloads and checks the signed release itself. No Npcap (slower scans) and no name-poisoning check on Windows.',
            ],
        ],
        [
            'version' => '1.25.0',
            'date' => '2026-11-23',
            'items' => [
                'Agent install steps: a How to add an agent guide on the Agents card, and the enrollment page now has the requirements, the install commands for your Sentinel address with copy buttons, a private CA option (SENTINEL_CA for the one-line install), how to check it worked, and troubleshooting. It warns when the site has no internal authorization yet.',
                'Release key fixes: a damaged or wrongly owned pinned key is never treated as none; the System page and bin/release-sign.php sign the same file list, so the hashes match.',
            ],
        ],
        [
            'version' => '1.24.1',
            'date' => '2026-11-23',
            'items' => [
                'Release key fixes: agents given the key at enrollment can be updated; the key is stored authenticated with the app key (make it again if you made one with 1.24.0); only the release\'s own files are signed, with the manifest hash and file list shown before signing; agents follow several rotations; the fingerprint is printed at enrollment.',
            ],
        ],
        [
            'version' => '1.24.0',
            'date' => '2026-11-23',
            'items' => [
                'Release key on Administration, System: created in your browser (the private key downloads as a password-protected file and never reaches Sentinel), versions signed there, agents learn the key from Sentinel, rotation signed by the old key.',
            ],
        ],
        [
            'version' => '1.23.2',
            'date' => '2026-11-23',
            'items' => [
                'Agent moves: "Move complete" (moved agents stay) and "Cancel and recall agents" are separate; agents older than 1.23.1 are never asked to move; moves made by 1.23.0 agents are kept.',
            ],
        ],
        [
            'version' => '1.23.1',
            'date' => '2026-11-23',
            'items' => [
                'Agent moves hardened: no token before the new address proves itself, proofs name the address, a move needs your password, moved agents check with their original address every 6 hours so they can always be recalled, and fallback only right after a move.',
            ],
        ],
        [
            'version' => '1.23.0',
            'date' => '2026-11-23',
            'items' => [
                'Move every agent to a new Sentinel address (and CA) from Administration, System. Each agent switches only after the new address proves it is this Sentinel, and falls back on its own if the new address keeps failing.',
            ],
        ],
        [
            'version' => '1.22.2',
            'date' => '2026-11-23',
            'items' => [
                'Agent updates: repeat updates work (the update request is removed after each one), updating from 1.22.0 works, and a failed update is rolled back more reliably.',
            ],
        ],
        [
            'version' => '1.22.1',
            'date' => '2026-11-23',
            'items' => [
                'Security fix for agent updates: the root update helper no longer touches the agent\'s own folder.',
                'A new agent release is self-checked before it is installed and rolled back if it does not stay running; a stuck update never stops scans.',
            ],
        ],
        [
            'version' => '1.22.0',
            'date' => '2026-11-23',
            'items' => [
                'Update agents from Sentinel (per agent, per client, or all from Administration, System). Agents install only releases signed with the maintainer\'s release key, checked again by a root helper on the appliance.',
                'Upgrade existing agents once by hand to get the update helper.',
            ],
        ],
        [
            'version' => '1.21.1',
            'date' => '2026-11-23',
            'items' => [
                'Restart, Diagnostics and Scan now are no longer lost while an agent is busy; a restart never costs a queued scan.',
                'Gentleness settings corrected: Very gentle now finishes real scans; Faster is labeled as the heavier traffic it is.',
            ],
        ],
        [
            'version' => '1.21.0',
            'date' => '2026-11-23',
            'items' => [
                'Agents managed from the Agents page: scan gentleness and check-in interval per site, a Diagnostics report and a Restart button.',
            ],
        ],
        [
            'version' => '1.20.1',
            'date' => '2026-11-23',
            'items' => [
                'An agent\'s key is pinned: a changed key waits on the Agents page until an admin approves its fingerprint (the agent\'s status command shows it).',
                'Fewer false alarms: NetBIOS node-status queries from inventory tools no longer count as name poisoning, and Domain Admins is found in any language.',
            ],
        ],
        [
            'version' => '1.20.0',
            'date' => '2026-11-23',
            'items' => [
                'Active Directory checks through the on-premises agent: AS-REP roasting, Kerberoasting, unconstrained delegation, Domain Admins, stale admins, never-expiring admin passwords, krbtgt age, LAPS and LDAP signing.',
                'The directory password is sealed in your browser for the site\'s agent: Sentinel only relays it and can never read it. Replace it any time from the Agents page.',
                'The domain controller\'s certificate is trusted once before the agent signs in; a changed certificate gets nothing.',
                'Name poisoning: the agent listens for LLMNR/NetBIOS name requests during full scans (it never answers).',
            ],
        ],
        [
            'version' => '1.19.2',
            'date' => '2026-11-23',
            'items' => [
                'After an unclear answer from ITFlow, Sentinel looks for the ticket from the newest end, so clients with thousands of tickets are checked in a few small reads.',
            ],
        ],
        [
            'version' => '1.19.1',
            'date' => '2026-11-23',
            'items' => [
                'An ITFlow ticket is reopened only on clear evidence: a recheck after it was closed, or new device data, that still sees the problem.',
                'Rechecks after a ticket is closed in ITFlow follow the button\'s limits and wait for the client\'s scan window.',
                'A ticket is given up as gone only after two "not found" answers an hour apart; a problem reopened by hand is followed again.',
            ],
        ],
        [
            'version' => '1.19.0',
            'date' => '2026-11-23',
            'items' => [
                'ITFlow tickets both ways: fixed in Sentinel resolves the ticket; resolved or closed in ITFlow makes Sentinel recheck, then reopen the ticket (or open a new one, if it was closed) when the problem is still there.',
                'One ticket ITFlow refuses no longer stops the others; it is retried later and the reason shows on the finding.',
                'Ticket links go to ITFlow\'s technician view; ITFlow\'s client guest link (with its secret key) is no longer kept.',
                'A ticket whose create call timed out is found again instead of opened twice.',
            ],
        ],
        [
            'version' => '1.18.0',
            'date' => '2026-11-23',
            'items' => [
                'Findings open ITFlow tickets: each Fail and known-exploited problem its own ticket with how to fix it; Warnings in one weekly ticket per client.',
                'The finding page shows its ITFlow ticket.',
            ],
        ],
        [
            'version' => '1.17.0',
            'date' => '2026-11-22',
            'items' => [
                'Clients sync from ITFlow every 15 minutes: new clients, renames and archives (new clients are never scanned until authorized).',
                'Clients are linked to MSP Align automatically by their ITFlow ID.',
            ],
        ],
        [
            'version' => '1.16.0',
            'date' => '2026-11-22',
            'items' => [
                'Compliance page per client: its MSP Align frameworks, with Sentinel findings matched to each control (read-only).',
                'Administration, Integrations: MSP Align address and read-only API key, with Test connection.',
            ],
        ],
        [
            'version' => '1.15.0',
            'date' => '2026-11-22',
            'items' => [
                'Settings in tabs: General, Alerts, Fix due dates, Report branding, Vulnerability data.',
                'Refresh now for vulnerability data, and the first download starts within minutes of installing.',
            ],
        ],
        [
            'version' => '1.14.0',
            'date' => '2026-11-22',
            'items' => [
                'NinjaOne connector (read-only): devices, operating systems, antivirus, BitLocker, missing updates and installed software for each linked client, every 6 hours.',
                'Administration, Integrations: NinjaOne instance, client ID and secret (encrypted), set-up steps and Test connection.',
            ],
        ],
        [
            'version' => '1.13.1',
            'date' => '2026-11-22',
            'items' => [
                'Update now explains the 15-minute wait between updates, and quick repeated clicks no longer switch the update helper off.',
                'An upgrade no longer stops when the update helper is stuck.',
            ],
        ],
        [
            'version' => '1.13.0',
            'date' => '2026-11-22',
            'items' => [
                'A client opens with its own menu on the left (Overview, Findings, External, Internal, Manage), one page per section, instead of one long page.',
            ],
        ],
        [
            'version' => '1.12.1',
            'date' => '2026-11-22',
            'items' => [
                'Update now is one click for admins (no password or 2FA code); the server still backs up first and runs it at most once every 15 minutes.',
            ],
        ],
        [
            'version' => '1.12.0',
            'date' => '2026-11-22',
            'items' => [
                'Update now under Administration, System (password and 2FA code), on servers installed with the one-line command.',
                'Update available: servers that follow a branch see how many new commits it has.',
            ],
        ],
        [
            'version' => '1.11.0',
            'date' => '2026-11-22',
            'items' => [
                'Demo data: four made-up clients with findings, devices, scan history, trends and reports. Load or remove it under Administration, System.',
                'Demo clients are never scanned and carry a Demo badge; removing demo data deletes only demo clients.',
            ],
        ],
        [
            'version' => '1.10.0',
            'date' => '2026-11-22',
            'items' => [
                'One-line install for a development server that follows the develop branch (install-dev.sh), to try changes before production.',
                'Development servers show a Development build badge on every page; Administration, System shows the branch and commit.',
            ],
        ],
        [
            'version' => '1.9.0',
            'date' => '2026-11-22',
            'items' => [
                'Guided install: seven steps and a summary to confirm (host name, HTTPS, firewall, fail2ban, automatic security updates, backup encryption, first admin).',
                'HTTPS with Let\'s Encrypt, self-signed, or behind a reverse proxy (Sentinel accepts plain HTTP from the proxy only).',
                'Server hardening by default: ufw, fail2ban and automatic security updates, each optional.',
            ],
        ],
        [
            'version' => '1.8.0',
            'date' => '2026-11-22',
            'items' => [
                'One-line install on Debian 13 (curl ... install.sh | sudo -E bash), with sudo msp-sentinel-update for upgrades.',
                'One-line install for on-premises agents too (install-agent.sh).',
                'Debian 13 is now the recommended system; Debian 12 and Ubuntu 24.04 still work.',
            ],
        ],
        [
            'version' => '1.7.0',
            'date' => '2026-11-22',
            'items' => [
                'The on-premises agent checks risky internal protocols: SMBv1, SMB signing, Remote Desktop without NLA, Telnet, FTP, default SNMP communities and login pages over plain HTTP.',
                'Each comes with a plain-English explanation and fix in reports.',
            ],
        ],
        [
            'version' => '1.6.0',
            'date' => '2026-11-22',
            'items' => [
                'On-premises agents: internal network scans from a small Linux appliance at the client\'s site, with signed internal authorizations and signed jobs.',
                'Internal devices with open services, certificates and web pages; vulnerable services and certificate problems become findings.',
                'New-device alerts after a site\'s first scan, and a kill switch per site.',
                'Groundwork for NinjaOne: installed software matched to vulnerabilities, unsupported Windows, antivirus, encryption and missing updates (from the NinjaOne connector under Administration, Integrations).',
            ],
        ],
        [
            'version' => '1.5.0',
            'date' => '2026-11-22',
            'items' => [
                'Fix workflow: assign findings to technicians and admins, with a notification and email for the new owner.',
                'Due dates by severity (known-exploited 7 days, Fail 14, Warning 30), set by admins, with overdue and due-soon badges and filters.',
                'Daily reminders: each owner\'s overdue and due-soon findings, and an overdue summary per client for the team.',
                '"Verify fix" rechecks one finding straight away, in scope, and resolves it when the problem is gone.',
            ],
        ],
        [
            'version' => '1.4.0',
            'date' => '2026-11-22',
            'items' => [
                'Website checks: HTTPS and redirects, security headers, cookie flags, directory listings and exposed files (.git, .env, backups, phpinfo), with each scan and daily.',
                'WordPress, Drupal, Joomla and common JavaScript libraries are recognized, and visible versions are matched to known vulnerabilities.',
                'Email security: SPF, DMARC and DKIM for every authorized domain that receives email.',
                'A new "Website and email security" card on the client page, a new Email security finding type, and plain-English fixes in reports.',
            ],
        ],
        [
            'version' => '1.3.0',
            'date' => '2026-11-22',
            'items' => [
                'Administration is now its own section, opened from your name at the top right (admins only).',
                'A new Administration overview shows users, alerts, API, system health and audit activity at a glance.',
                'The left menu keeps only day-to-day work: Dashboard, Clients, Findings, Reports and Help.',
            ],
        ],
        [
            'version' => '1.2.0',
            'date' => '2026-11-22',
            'items' => [
                'Command-view dashboard: threat gauge, client risk grid, 90-day trend, live activity, top exposures, attack surface, certificates and an operations strip.',
                'Every client page opens with its own overview console: risk gauge, totals, scan window countdown, trend, attack surface and recent activity.',
                'Dashboards refresh themselves every minute while the page is open.',
            ],
        ],
        [
            'version' => '1.1.0',
            'date' => '2026-11-22',
            'items' => [
                'New dark console look with ember accents, and a new radar-eye logo.',
                'Dark by default; choose a light look for yourself under My profile, Appearance.',
                'Client reports keep their clean, printable style.',
            ],
        ],
        [
            'version' => '1.0.0',
            'date' => '2026-11-22',
            'items' => [
                'First stable release: a release archive with checksums and an installer for Ubuntu 24.04 and Debian 12 (with --upgrade).',
                'Administration, System: health checks (also bin/doctor.php), version and update check, data retention.',
                'Backups (bin/backup.php, optionally encrypted) and restores (bin/restore.php), plus full guides in docs/.',
            ],
        ],
        [
            'version' => '0.10.0',
            'date' => '2026-11-22',
            'items' => [
                'API at /api/v1 for MSP Align and other tools: clients, assets, findings, scans and reports, with an OpenAPI description.',
                'Admin-created tokens: all or chosen clients, expiry, optional IP allowlist; triage and queueing scans are opt-in.',
                'Signed outbound events when findings change, scans finish and reports are created.',
            ],
        ],
        [
            'version' => '0.9.0',
            'date' => '2026-11-22',
            'items' => [
                'Reports: an Executive summary for management and a Technical findings report for IT, frozen when created, with print to PDF, HTML download and CSV export.',
                'Monthly schedule per client: both reports are emailed to your chosen MSP staff for review.',
                'Report branding: company name, logo, color, footer text and paper size.',
            ],
        ],
        [
            'version' => '0.8.0',
            'date' => '2026-11-22',
            'items' => [
                'Alerts: immediate alerts for new or returning Fail findings, a summary after each scan, and admin alerts when a scan or feed fails.',
                'In-app notifications (the bell in the header), email (each user picks what they get on their profile) and a Teams, Slack or JSON webhook.',
                'Set up under Administration > Settings, Alerts, with test buttons. The SMTP password and webhook address are stored encrypted.',
            ],
        ],
        [
            'version' => '0.7.0',
            'date' => '2026-11-22',
            'items' => [
                'Findings: one list of Fail and Warning items per client, plus a Findings page across all clients with filters.',
                'Automatic resolution when checks see a problem gone; the same finding reopens (marked "Reappeared") if it returns.',
                'Triage with a required note: accepted risk, or false positive (reopens if the evidence changes); full history.',
            ],
        ],
        [
            'version' => '0.6.0',
            'date' => '2026-11-22',
            'items' => [
                'Vulnerability matching against NVD, the CISA known-exploited list and EPSS scores.',
                '"Confirmed" when the version is known; "product found, version unknown" otherwise, with known-exploited issues only.',
                'Known exploited first, then critical and high; daily feeds job with status on the Administration > Settings page.',
            ],
        ],
        [
            'version' => '0.5.0',
            'date' => '2026-11-22',
            'items' => [
                'TLS certificate checks after every port scan and daily: expiry, trust, name match, weak keys, old TLS 1.0/1.1.',
                'Detection of firewall and device admin pages, VPN portals and remote desktop web access on open web ports.',
                'Dashboard count of certificates expired or expiring within 14 days.',
            ],
        ],
        [
            'version' => '0.4.0',
            'date' => '2026-11-21',
            'items' => [
                'Gentle external port scanning, on demand and weekly, inside each client\'s scan window.',
                'Scope checked before every host; hostnames are only scanned through in-scope addresses.',
                'Open ports with high-risk services marked, and a scan log of every host touched or skipped.',
                'Per-client extra and excluded ports; cancel and pause stop scans within seconds.',
            ],
        ],
        [
            'version' => '0.3.0',
            'date' => '2026-11-21',
            'items' => [
                'Passive discovery of hostnames and addresses from DNS, public certificate logs and reverse DNS, on demand and weekly.',
                'Suggestions you approve into a new authorization. Names at other providers are never suggested.',
                'A "Change scope / renew" shortcut that pre-fills a replacement authorization.',
            ],
        ],
        [
            'version' => '0.2.0',
            'date' => '2026-11-21',
            'items' => [
                'Clients and sites, with optional ITFlow IDs, timezone and scan window.',
                'The "authorized to scan" register: who approved scanning, for which dates, and exactly what may be scanned.',
                'Kill switches for one client or for everything: technicians can pause, only admins resume.',
                'Warnings when a scope entry is already in another client\'s scope.',
            ],
        ],
        [
            'version' => '0.1.0',
            'date' => '2026-11-21',
            'items' => [
                'Foundation release: sign-in with mandatory two-factor authentication and recovery codes.',
                'Roles: Admin, Technician and Viewer.',
                'User management, audit log and general settings (product name for white-label, source code link).',
                'No scanning yet. Clients and the "authorized to scan" register come next.',
            ],
        ],
    ],
];
