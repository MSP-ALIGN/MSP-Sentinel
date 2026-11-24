<?php

/**
 * In-app help topics and "What's new" entries.
 * Each release adds an entry to 'releases' (newest first) and updates topics as needed.
 * Trusted text, shipped with the app. It is still escaped when shown.
 */

return [
    'topics' => [
        [
            'title' => 'Signing in and two-factor authentication',
            'paragraphs' => [
                'Every account must use two-factor authentication (2FA). The first time you sign in, scan the QR code with an authenticator app on your phone and enter the 6-digit code it shows.',
                'After setting up 2FA you get 10 recovery codes. Keep them in your password manager. Each one signs you in once if you lose your phone. You can create new codes from My profile. That makes the old ones stop working.',
                'If you lose both your phone and your recovery codes, ask an admin to reset your two-factor authentication.',
                'For your security, you are signed out after 30 minutes without activity, and after 12 hours in any case.',
                'After 5 wrong passwords, sign-in for that account is paused for 15 minutes, even with the right password. This slows down password guessing. If it happens unexpectedly, tell an admin: the audit log shows where the attempts came from.',
            ],
        ],
        [
            'title' => 'Roles',
            'paragraphs' => [
                'Viewer: can see everything but change nothing.',
                'Technician: everything a viewer can do, plus running scans and triaging findings (arriving in later releases).',
                'Admin: everything, including managing users, settings, API tokens and approving which client systems may be scanned.',
            ],
        ],
        [
            'title' => 'Managing users (admins)',
            'paragraphs' => [
                'Add users under Administration > Users. Give each person a temporary password. They must change it and set up 2FA when they first sign in.',
                'Changing a user\'s role, disabling them, resetting their password or resetting their 2FA signs them out everywhere straight away.',
                'You cannot change your own role or disable yourself, and the last active admin cannot be removed. This prevents anyone from being locked out.',
            ],
        ],
        [
            'title' => 'Clients and the "authorised to scan" register',
            'paragraphs' => [
                'Opening a client switches the left menu to that client: Overview, Findings, External (scans and ports, vulnerabilities, certificates and web, website and email), Internal (agents, devices) and Manage (authorisations, discovery, reports). All clients at the top goes back.',
                'Sentinel only ever scans systems a client has authorised. Before anything is scanned for a client, an admin records who at the client approved it (name, role, date), for which dates, and exactly which IP addresses, ranges and domains are covered. Open the client and choose "Record authorisation".',
                'Scope entries: one per line. Public IP addresses (for example 203.0.113.10), ranges up to /24, and domain names. Write *.client-domain.com to include all subdomains; list the bare domain separately if it should be scanned too. Private and internal addresses are refused, because this version only scans from the internet. Shared suffixes such as *.co.uk or *.github.io are refused too, because they belong to many unrelated owners.',
                'Authorisations cannot be edited. If the scope changes, revoke the old authorisation (with a reason) and record a new one. That way the register always shows exactly what was approved and when.',
                'An authorisation is valid for at most 2 years, using dates in the client\'s timezone. The dashboard shows authorisations ending within 30 days, so you can ask the client to renew in time.',
                'If you add an address that is already in another client\'s scope, Sentinel warns you. That is usually a typo that would point scans at the wrong client.',
                'Kill switches: anyone with the Technician or Admin role can pause scanning for one client (on the client page) or for every client (on the dashboard), straight away. Only an admin can resume. Archived clients are never scanned.',
            ],
        ],
        [
            'title' => 'Discovering forgotten hostnames',
            'paragraphs' => [
                '"Discover now" on a client page (Technician or Admin) looks for hostnames and addresses the client probably owns but has not put in scope yet. It reads DNS records for the domains in scope, tries common names such as www, mail, vpn and remote, searches public certificate logs (crt.sh), and does reverse DNS on in-scope addresses. A weekly job does the same for every client if your admin has set it up.',
                'This is passive: Sentinel only asks DNS and a public website. Nothing connects to the client\'s systems. It still needs an active authorisation and stops when scanning is paused.',
                'Only names under the client\'s own domains are suggested. Names that belong to other companies (such as a hosted mail service or a DNS provider) are listed under "Names at other providers" for information, and never suggested. Addresses reached through an alias at another provider are marked "Check: maybe third-party" and are not ticked by default.',
                'Suggestions are never scanned on their own. To add them, an admin ticks them and chooses "Add selected to a new authorisation". The form opens with the current scope plus your selection. Ask the client to approve the additions, enter their details, and save. The new authorisation replaces the old one.',
                'Dismiss suggestions you don\'t want. They stay dismissed when discovery runs again, and you can restore them from the "Dismissed suggestions" list.',
            ],
        ],
        [
            'title' => 'Port scans',
            'paragraphs' => [
                '"Scan now" on a client page (Technician or Admin) queues a port scan. The scan worker runs it inside the client\'s scan window. Admins can run a scan outside the window by ticking the box and giving a reason, which is recorded. Every client with an active authorisation is also scanned once a week.',
                'Scans are gentle: an ordinary TCP connection test, polite timing, at most 50 packets per second, and one host at a time. Version detection sends a few standard, harmless protocol probes to open ports so the service can identify itself. Each client is scanned on a default list of about 40 risky and admin ports. Admins can add or exclude ports on the client\'s edit page.',
                'Before each host, Sentinel checks again that it is in an active authorisation, that scanning is not paused, and that the window is open. Hostnames are scanned through their addresses, and only addresses that are themselves in scope. If www.client.com points at a server that is not in scope (for example a hosting company), it is skipped and the scan log says why.',
                'Cancel a scan or pause scanning at any time: nmap stops within seconds. The scan log on the client page lists every host Sentinel touched or skipped, and when.',
                'Open ports show what the service itself reports (product and version). That can be wrong. High-risk services such as Remote Desktop, file sharing (SMB), databases, Telnet and VNC are marked in red.',
            ],
        ],
        [
            'title' => 'Certificates and exposed admin pages',
            'paragraphs' => [
                'After each port scan, and once a day inside the scan window, Sentinel connects briefly to each TLS service it found. It reads the certificate (expiry, issuer, whether it is trusted and matches the name, key size) and checks whether old TLS 1.0 or 1.1 is still accepted.',
                'It also requests the start page of each web port once, without logging in, and recognises firewall and device admin pages, hypervisor consoles (VMware, Proxmox, XenServer, Nutanix), out-of-band management (iDRAC, iLO, IPMI), NAS admin pages (Synology, QNAP, TrueNAS and others), VPN portals, remote desktop web access and other login pages from their wording. The website checks (see "Website and email security") then request a short fixed list of paths.',
                'Grading: an expired certificate, or a firewall, device, hypervisor, out-of-band or NAS admin page reachable from the internet, is a Fail. A product named only in the page text is not flagged. A certificate expiring within 14 days, self-signed or untrusted certificates, name mismatches, old TLS and weak keys are Warnings. VPN portals and remote desktop web access are Warnings too: they are often meant to be reachable, so make sure they are patched and use MFA.',
                'Mail services that start TLS later in the connection (STARTTLS on ports 25, 587, 143) are not checked yet.',
            ],
        ],
        [
            'title' => 'Website and email security',
            'paragraphs' => [
                'With each port scan, and once a day inside the scan window, Sentinel checks every website it found. It reads the start page and its response headers: whether HTTP redirects to HTTPS, whether a login form is served without encryption, the security headers (HSTS, Content-Security-Policy and others), cookie flags and directory listings.',
                'It requests a short, fixed list of files that are often left on websites by mistake: /.git/HEAD, /.env, common backup and database dump names, /phpinfo.php, /server-status and /.DS_Store. A file is only reported when its content proves it (for example a real git reference or a zip file), so sites that answer every address with a page are not flagged. The content of these files is never stored.',
                'It recognises WordPress, Drupal and Joomla and common JavaScript libraries (jQuery, Bootstrap, AngularJS, Lodash, Moment.js, Vue.js) from the page markup. When a version is visible, it is matched to known vulnerabilities like any other software. Sentinel never guesses a version.',
                'For each domain in the authorisation that receives email (has MX records), Sentinel checks the SPF and DMARC records and looks for DKIM under common selectors, through DNS only. Domains without MX records (or with a "null MX" that refuses email) are not judged. A wildcard entry such as *.client.example covers only subdomains, so client.example itself is checked only when it is listed too. An SPF record that hands over to another with redirect= is not judged, and a subdomain without its own DMARC record uses its parent domain\'s record when the parent is also authorised.',
                'DNS checks (once a day at most): for each authorised domain, Sentinel asks each of the domain\'s own listed nameservers for a zone transfer. A nameserver that hands out the whole zone lets anyone list every name, including internal and forgotten systems; only the first part of the answer is read. Each authorised name (and each in-scope name seen on the client\'s addresses) is also checked for subdomain takeover: a CNAME to a cloud service such as Amazon S3, GitHub Pages, Heroku or Azure that no longer exists, either because the cloud name no longer resolves or because one request to the name gets the provider\'s "no such site" page. Both are Fails. The nameservers and cloud providers are usually third parties; each gets one standard request, and only public addresses are contacted. A check that cannot decide (a DNS failure, no web answer) keeps the earlier result.',
                'Grading: a login over HTTP, an exposed .git folder, .env file, backup or phpinfo page, and an SPF record that allows anyone to send (+all) are Fails. A missing HTTPS redirect, HSTS or Content-Security-Policy, insecure cookies, a directory listing, the server-status page, a .DS_Store file, a missing or weak SPF and a missing or "p=none" DMARC are Warnings. Other headers and DKIM not being found under a common selector are advice only (Info): DKIM may use a selector Sentinel does not know.',
            ],
        ],
        [
            'title' => 'Vulnerabilities',
            'paragraphs' => [
                'Sentinel matches each open service to known vulnerabilities (CVEs) from the product and version the service reports. When the version is known, the US National Vulnerability Database (NVD) decides which CVEs affect exactly that version: these are shown as "Confirmed". The service\'s own banner can be wrong or hide backported fixes, so check before you act.',
                'Linux distributions (Ubuntu, Debian, Red Hat and others) often fix vulnerabilities without changing the version number. When a banner shows a distribution build, matches are marked "Distribution build: the fix may be backported" instead of "Confirmed". Check the distribution\'s security notices.',
                'Only CVEs where NVD lists the product itself as vulnerable are matched, not ones where it is merely the platform another product runs on. If some products are still waiting for data or could not be looked up, the panel says so: "no matches" is never claimed for products that weren\'t checked.',
                'When only the product is known, Sentinel never lists the product\'s whole history. It only shows vulnerabilities that are known to be exploited (from the CISA KEV catalog), marked "Product found, version unknown".',
                'What matters comes first: known-exploited vulnerabilities, then critical and high ones. Each shows its CVSS score and its EPSS score (how likely it is to be exploited in the next 30 days). Lower-severity matches are counted and can be expanded.',
                'Grading: a confirmed known-exploited or critical vulnerability is a Fail. A confirmed high one, or a known-exploited one on a product whose version is unknown, is a Warning.',
                'The data refreshes daily (bin/feeds.php). Its status is on the Administration > Settings page.',
            ],
        ],
        [
            'title' => 'On-premises agents (internal scans)',
            'paragraphs' => [
                'An agent is a small Linux appliance at the client\'s site. It only connects out to Sentinel, finds the devices on the internal network with their open services, certificates and web pages, and reports them. A full scan runs weekly and a light sweep daily, inside the client\'s scan window (stopped when it closes and continued in the next window); admins can also press Scan now (with a reason).',
                'An agent scans only the networks in a signed internal authorisation for its site: who at the client approved it, the dates, and exactly which private networks (each at most a /16). Sentinel signs the authorisation and every job; the agent checks both signatures and refuses any target outside the signed networks.',
                'To add one: record an internal authorisation for the site, prepare a mini-PC or VM on the internal network (Debian 13, Debian 12 or Ubuntu 24.04, or Windows Server 2022/2025 or Windows 11 (preview); 2 CPU cores, 2 GB memory, 20 GB disk; a VM needs a bridged adapter, not NAT; outbound HTTPS to Sentinel), click Create an enrolment code (admins; shown once, valid once for 24 hours), and run the install command shown on that page (it has a copy button and asks for the code). The page also says how to check it worked and what to do if it does not. Pause on the site stops agent scans within a minute; revoking an agent stops its token at once.',
                'New Sentinel address: Administration, System, Move agents (with your password). Each agent switches only after the new address signs a challenge for that address with this Sentinel\'s key (nothing secret is sent before). Right after a move it goes back if the new address keeps failing; while moved it asks its original address every 6 hours, so keep that address working.',
                'Release key (Administration, System): create it once in your browser (the private key downloads as a password-protected file; Sentinel keeps only the public half; it does not expire), then Sign this version after each Sentinel update. Agents learn the key from Sentinel. Rotate it with the old key file; Replace it only if the file is lost (agents then need it by hand).',
                'Updates: Update to x.y.z (per agent), Update all agents (per client, or under Administration, System). The agent installs a release only when it is signed with the maintainer\'s release key it pinned at install; a root helper checks everything again. Agents older than 1.22.0 must be upgraded once by hand.',
                'Managed from the Agents page afterwards (admins): scan gentleness per site (very gentle, gentle or faster nmap timing, never more than nmap\'s normal -T3), how often agents check in, a Diagnostics report (versions, disk, memory, clock difference, key fingerprint) and Restart.',
                'Risky internal protocols, checked read-only: SMBv1 enabled, Telnet open and SNMP answering the default "private" community are Fails; SMB signing not required, Remote Desktop without Network Level Authentication, FTP open, SNMP answering "public" and login pages over plain HTTP are Warnings. The SNMP check sends one read request with the default community names.',
                'Findings: known vulnerabilities in the services found (distribution builds are never "confirmed"), and certificates that are expired, accept old TLS or use a weak key. Self-signed certificates are normal inside a network and not findings. After the first scan (the baseline), devices never seen before are announced as new devices, unless NinjaOne already knows them.',
            ],
        ],
        [
            'title' => 'Active Directory checks',
            'paragraphs' => [
                'On the client\'s Agents page (admins, per site): enter the domain, the domain controller\'s IP address (inside the site\'s internal authorisation), a read-only domain account and its password. The agent then reads the directory at each full scan and reports what attackers look for first. Nothing is changed in the directory.',
                'The password never reaches Sentinel in readable form: your browser seals it to that site agent\'s own key before sending, Sentinel relays the sealed box and deletes it once the agent confirms (or after 24 hours), and the agent keeps it sealed. It needs an HTTPS page. To replace it, type a new one under Change settings or replace the password; leave it empty to keep the current one.',
                'Before the first sign-in the agent only fetches the domain controller\'s certificate; check its fingerprint and click Trust this certificate. If the certificate changes later, the agent sends nothing until you trust the new one.',
                'Fails: accounts without Kerberos pre-authentication (AS-REP roasting), admin accounts with a service name (Kerberoasting), computers other than domain controllers trusted for unconstrained delegation, and devices heard sending LLMNR/NetBIOS name requests (name poisoning; the agent listens for 2 minutes and never answers). Warnings: other accounts with a service name, more than 5 Domain Admins, admin passwords that never expire, a krbtgt password over a year old, computers without LAPS, LDAP signing not required, admin accounts unused for 90 days. Each finding lists up to 25 names.',
            ],
        ],
        [
            'title' => 'Pen-test engagements',
            'paragraphs' => [
                'An engagement is a time-boxed, deeper test the client authorises in writing: all 65,535 TCP ports, common UDP services (one read-only request each to SNMP, NTP and SSDP), nmap\'s safe service scripts (without vulnerability checks) and read-only anonymous-access checks (FTP, NFS exports, and SMB file shares through an anonymous session with no username: the share list and the number of items in each share\'s top folder; no file is opened, no file names kept). Never password guessing, exploits or anything that changes the systems tested.',
                'Vendor default passwords (1.29, optional): needs a second tick confirming that the signed authorisation explicitly allows it. At most three published vendor defaults per service (FTP, web admin pages with a Basic login, MySQL/MariaDB, PostgreSQL), no username is tried twice on one host (so no account sees more than one failed attempt), 5 seconds apart, stopping at the first success, any lockout, or after 10 minutes per host. Windows services (IIS, WinRM, IIS FTP, and pages that offer Windows sign-in) are never tried. Running the tests again doesn\'t repeat the attempts; a retest tries only the accounts that worked, once each. A working login is closed at once and nothing is read; the report shows the username and the password masked (a•••n). It also checks whether Redis, MongoDB, Elasticsearch/OpenSearch and Memcached answer without any password. Never SSH, Windows, Remote Desktop or directory logins. Internal runs need agents 1.29.1 or later.',
                'Create one under the client, Pen-test engagements: name, window (at most 14 days), tests, pace (gentle or normal; all ports need normal), targets inside the authorised scope, exclusions by IP address or range, and the client\'s signed PDF. A different admin approves it with their password; nothing runs before. Stop engagement ends it for good, within a minute.',
                'Run external tests (from Sentinel) and internal tests (through each site\'s agent, version 1.27.0 or later) inside the window. The engagement page lists the findings with evidence and fixes; they do not change the client\'s day-to-day findings or inventory.',
                'Issue penetration test report for a branded, frozen report (summary, how findings chain together, scope and authorisation, method, findings, systems tested). After fixes, create a retest engagement (This is a retest of) and issue its retest letter: each earlier finding marked fixed, still open or not retested.',
            ],
        ],
        [
            'title' => 'Internal devices and NinjaOne',
            'paragraphs' => [
                'Internal devices come from the on-premises agent and, once it is connected, from NinjaOne. Each client page shows them under Internal devices; a device page lists its open services, installed software with known vulnerabilities, and missing updates.',
                'Grading: a Windows version without security updates, or antivirus/EDR missing or turned off, is a Fail. Antivirus definitions out of date, disk encryption off on a workstation, security updates missing for more than 30 days, and updates that failed are Warnings. Vulnerable software gets one finding per device and program, graded by its worst CVE.',
                'Only programs in Sentinel\'s software catalogue are matched to vulnerabilities, and only with a clean version number; other programs are listed but not matched. When a program updates before vulnerability data for the new version is available, its findings wait instead of resolving.',
                'NinjaOne: an admin connects it under Administration, Integrations (an API app with the Monitoring scope and the Client credentials grant), then links each client to its NinjaOne organisation on the client\'s Devices page. Sentinel reads devices, operating systems, antivirus, BitLocker, missing Windows updates and installed software every 6 hours. It only reads: nothing is changed in NinjaOne. Network devices, phones and devices waiting for approval are left out.',
            ],
        ],
        [
            'title' => 'Fix workflow: owners, due dates and verify fix',
            'paragraphs' => [
                'Every open finding has a due date: 7 days for known-exploited vulnerabilities (CISA KEV), 14 days for other Fail findings and 30 days for Warnings, counted from when it was first seen or last reopened. Admins can change these days under Administration > Settings > Due dates, and can set a different date on one finding (with a reason). Accepted risks, false positives and resolved findings are never due.',
                'Technicians and admins can assign a finding to an active technician or admin, or take it with "Assign to me". Viewers see who owns what but cannot change it. The new owner gets a notification and an email (unless they chose no emails, or assigned it to themselves). Every change is in the finding\'s history and the audit log.',
                'Use the buttons above the findings list for "Assigned to me", "Unassigned", "Overdue" and "Due within 2 days", or the Owner and Due filters.',
                'Once a day after 07:00 UTC, each owner gets one note and one email listing their overdue findings and those due within 2 days. The team addresses (and the webhook) get a summary of overdue findings per client, including unassigned ones.',
                '"Verify fix" rechecks only that finding, straight away and also outside the scan window: one address and port (a port scan of just that port, then its certificate and web checks), or one domain\'s email records by DNS. It runs only while the target is in an active authorisation and scanning is not paused, respects the kill switch, is logged in the scan log, and can be used once every 10 minutes per finding. It runs within a minute, or after a scan that is already running. The result is in the history and you get a notification: Fixed (rechecked and gone, so resolved), Still present, No longer reachable (nothing answers on the port any more, so the finding no longer applies, but the problem itself could not be checked), Already resolved (by another check first), or Not verified (with the reason, for example the check failed or vulnerability data is still being fetched). Sentinel never says Fixed unless this recheck proved it.',
                'Reopening an accepted risk or false positive by hand keeps the original due date: only admins move due dates. A finding that comes back after being resolved starts a new deadline.',
            ],
        ],
        [
            'title' => 'ITFlow',
            'paragraphs' => [
                'With ITFlow connected (Administration, Integrations), Sentinel adds new ITFlow clients every 15 minutes, applies renames, and archives or restores clients when they are archived or unarchived in ITFlow. A client added from ITFlow is not scanned until its written authorisation is recorded. A client you archived yourself in Sentinel stays archived. Changes appear in the audit log as itflow-sync.',
                'With tickets turned on, each Fail and known-exploited finding opens its own internal ITFlow ticket (High, or Urgent when exploited) with what was found, why it matters and how to fix it, and a link back. Warnings go into one ticket per client a week when there are new ones. A finding never gets two tickets; the finding page shows its ticket number.',
                'One ticket per issue (1.32): the same problem on another target of the same client (the same CVE, or the same title) joins the open ticket with an "also found on" note instead of a ticket of its own. The ticket follows every target: a target fixed or decided while others are open gets a note, the ticket is resolved only when all of them are fixed or decided, and when it is closed in ITFlow every open target is rechecked; any still there reopens it (or a new ticket is opened for the targets still open).',
                'Status goes both ways. When Sentinel no longer sees the problem (or it is marked accepted risk or false positive), the ticket gets a note and is resolved in ITFlow. When a ticket is resolved or closed in ITFlow while the problem is open, Sentinel checks again: a port or email problem gets a recheck (in the client\'s scan window, with the same limits as the button), a device problem waits for the device\'s next data. Only a recheck or new device data that still sees the problem counts as still there. Gone: the finding closes. Still there: a resolved ticket is reopened with what Sentinel sees; a closed one (ITFlow cannot reopen those) is replaced by a new ticket naming the old one. Without a clear answer within 10 days Sentinel stops waiting and says so on the finding.',
                'A ticket ITFlow refuses (a deleted client, no access) is retried after 1, 2, 4 hours and so on, and the reason shows on the finding; the other tickets carry on. Weekly Warnings tickets are informational and are not followed.',
            ],
        ],
        [
            'title' => 'Compliance (MSP Align)',
            'paragraphs' => [
                'With MSP Align connected (Administration, Integrations) and a client linked on its Compliance page, Sentinel shows that client\'s compliance frameworks from MSP Align. For each control in an area Sentinel checks it shows the open findings that affect it, or "No problems found" with what was checked, or "Not checked yet". Controls Sentinel can\'t see (policies, training, backups) are only counted.',
                '"No problems found" supports a control but does not prove it is met: Sentinel sees only part of what a control asks for. Statuses are set in MSP Align; Sentinel never changes them.',
            ],
        ],
        [
            'title' => 'Findings and triage',
            'paragraphs' => [
                'Findings bring together everything Sentinel grades as Fail or Warning for a client: high-risk services open to the internet, certificate problems, exposed admin pages and portals, and vulnerabilities. Info items are not findings; they stay visible in the client panels.',
                'A finding resolves by itself when a check really sees the problem gone, for example a port that a complete scan finds closed. A host that simply wasn\'t scanned keeps its findings. If a resolved problem comes back, the same finding reopens and is marked "Reappeared", with its whole history. If it had been accepted or marked as a false positive and the evidence is the same, that decision is kept. While a service\'s new vulnerability data is still being fetched, its vulnerability findings are not resolved.',
                'Technicians and admins can triage a finding, always with a note. "Accepted risk" means the client knows and accepts it; it stays accepted until the problem goes away. "False positive" means it isn\'t really a problem; it reopens automatically if the evidence changes, for example if a different version is reported. You can also reopen a finding to undo a decision. Resolving is never done by hand: only checks resolve findings.',
                'The Findings page lists findings across all clients, with filters for client, status, grade and type. Each decision appears in the finding\'s history and in the audit log.',
                'Repeated problems are grouped (1.31): the same CVE, or the same problem, on several targets of one client is one row ("on 3 targets"). Open the row to see each target and act on all of them at once: assign, accept risk / false positive / reopen with one note, verify fix on each, and (admins) one due date. Every target stays its own finding: checked, rechecked, resolved and audited on its own, exactly as if you had clicked each one. "One row per target" shows the old list. Reports list each problem once with all its targets.',
            ],
        ],
        [
            'title' => 'System, backups and updates (admins)',
            'paragraphs' => [
                'Administration, System shows the health of this install: PHP, the database, migrations, nmap, whether the scan worker and the daily feeds job are running, storage, disk space, HTTPS, email and updates. Fix anything marked Problem first. The server administrator can run the same checks with php bin/doctor.php.',
                'Once a day Sentinel asks the releases feed for the latest version (nothing else is sent) and shows it here when a newer one exists. You can turn this off. Servers installed with the one-line command also show how many new commits their branch has. Admins can click Update now: a small service on the server then runs the same update as sudo msp-sentinel-update, backing up first, and the page shows its progress. Otherwise upgrades are done on the server (sudo msp-sentinel-update, or install.sh --upgrade), which makes a backup first.',
                'Demo data: under Demo data, admins can load four made-up clients (with findings in every state, an on-premises agent and devices, scan history, trends and reports) to try Sentinel out or train technicians, and remove them again. Demo clients use *.example names and documentation addresses, show a Demo badge and are never scanned. Removing deletes only demo clients and what belongs to them. On the server: php bin/demo.php --load or --remove.',
                'Data retention: choose how many months to keep finished scan history, resolved findings and reports. 0 keeps them forever. Older data is removed once a day and the counts are written to the audit log. The audit log itself is always kept.',
                'Backups are made on the server with bin/backup.php (daily, if Sentinel was installed with the installer). They contain all client data and the app key, so encrypt any copy that leaves the server. See docs/backup.md.',
                'Installing: the one-line install asks seven questions step by step (host name; HTTPS with Let\'s Encrypt, self-signed or behind a reverse proxy; firewall; fail2ban; automatic security updates; backup encryption passphrase; first admin) and shows a summary before it changes anything. Behind a reverse proxy, Sentinel only accepts plain HTTP from the proxy\'s address and trusts its X-Forwarded-For and X-Forwarded-Proto headers. See docs/install.md.',
                'Development server: install-dev.sh installs a separate server that follows the develop branch, so changes can be tested before they reach production. It shows a yellow Development build badge on every page, and sudo msp-sentinel-update keeps it on develop. Use a separate host name and made-up test clients.',
            ],
        ],
        [
            'title' => 'API and events',
            'paragraphs' => [
                'Other tools, such as MSP Align, can read Sentinel\'s data through the API at /api/v1. Admins create tokens under Administration, API. A token is shown once: copy it into the other system straight away. Send it as "Authorization: Bearer <token>". The full description is at /api/v1/openapi.json.',
                'Each token covers all clients or only the ones you choose, expires after 30 to 365 days, and can be limited to certain IP addresses. Every token can read. Triage and queueing scans are separate permissions, off unless you tick them. Scans queued through the API follow the same rules as in the web interface: only in scope, never while paused, and only in the client\'s scan window. Triage through the API needs a note, which is marked with the token\'s name.',
                'A token acts as the admin who created it and stops working if it is revoked, expires, or that admin is deactivated or is no longer an admin. Each token can make 120 requests a minute. Its last use (time and address) is shown on the API page, and every change made through the API is in the audit log.',
                'Outbound events: Sentinel can POST to an https address when findings open, reopen, become a Fail, resolve or are triaged, when a scan finishes and when a report is created. Each request is signed: check the X-Sentinel-Signature header (t=<unix time>,v1=<HMAC-SHA256 of "time.body" with the signing secret>) and reject old timestamps. The signing secret is shown once; you can create a new one at any time. Events that cannot be delivered are retried for about two days, so they may arrive late or out of order: use the event id to skip duplicates.',
                'If Sentinel runs behind a reverse proxy, list the proxy under app.trusted_proxies in the config, so the API sees callers\' real addresses (for IP allowlists and rate limits).',
            ],
        ],
        [
            'title' => 'Dashboards and the risk score',
            'paragraphs' => [
                'The dashboard is a command view of every client: the threat level (the highest client risk), totals, a 90-day trend of open problems, every client ranked by risk, the worst open findings, live activity, the attack surface by type of service, certificates expiring in the next 30 days, and a status strip (scanning armed or paused, worker, threat feeds, scans running, scan windows, authorisations). Each client page opens with the same kind of overview for that client.',
                'The risk score runs from 0 to 100; higher is worse. It adds 20 for each open known-exploited Fail finding, 10 for each other open Fail, and 2 for each open Warning, up to 100. Accepted risks and false positives do not count. The level next to it is the same as in reports: At risk (any open Fail), Needs attention (Warnings only) or Good (nothing open).',
                'Clients are ranked by level first (At risk, then Needs attention, then Good) and then by score, so a client with many Warnings never appears above one with a Fail.',
                'Dashboards update themselves every minute while the page is open and visible. Use "Pause updates" to hold the view still; updates also wait while you are using a panel. These updates do not count as activity: an unattended screen still signs out after 30 minutes, and updates stop after 30 minutes without input. The trend chart fills in day by day from when Sentinel started recording. Certificates are counted only on services that are still open.',
            ],
        ],
        [
            'title' => 'Reports',
            'paragraphs' => [
                'Open a client and use the Reports card to create a report. The Executive summary is written for the client\'s management: an overall rating, the top 5 risks in plain English, totals and a trend. The Technical findings report is for IT: every open finding with its evidence, how to fix it, what was fixed this period, and the scope and methods. Technicians and admins create reports; everyone can read them.',
                'Accepted risks and false positives are listed in their own section with their notes. They are never hidden, but they do not count towards the totals or the rating.',
                'A report is frozen when it is created: it keeps the data and the branding of that moment and never changes, so you can always show exactly what a client was sent. Its SHA-256 identifies the exact document. Only admins can delete reports.',
                'To make a PDF, open the report and use your browser\'s Print, then "Save as PDF". You can also download the report as a single HTML file (it works offline) or the findings as CSV for a spreadsheet.',
                'Admins can turn on monthly reports for a client and enter up to 5 addresses at your MSP. After each month ends (calendar months, UTC), both reports for that month are created once and emailed to those addresses as attachments, for review before you forward them. Reports over 5 MB are not attached; the email then points to them in Sentinel. Deleting a scheduled report does not create it again. If creating them fails, admins get a notification and Sentinel retries hourly, up to 5 times. Email must be set up under Administration > Settings, Alerts.',
                'A report shows the status at the moment it is created; "new" and "fixed" count what changed during the chosen period.',
                'Admins set the report branding under Administration > Settings, Report branding: company name, logo (PNG or JPEG; it is checked and re-encoded), accent colour, contact details, paper size, and whether the "Generated by MSP Sentinel" line is shown.',
                'Every report states its limits: these are external, non-intrusive checks of the authorised addresses, they do not test internal networks, and they are not a PCI ASV scan.',
            ],
        ],
        [
            'title' => 'Alerts and notifications',
            'paragraphs' => [
                'Sentinel tells you straight away when a Fail finding is new or comes back. After each scan it sends a summary of what changed, and admins are told when a scan or a threat feed fails. Accepted risks and false positives never cause alerts.',
                'Every alert appears under the bell in the header. Open the Notifications page to see them; opening it marks them read. On your profile, choose which emails you get: immediate alerts, the scan summary, both, or none.',
                'Admins set up email and the webhook under Administration > Settings, Alerts. Email needs a mail server with STARTTLS or TLS (plain connections are only allowed to a relay on this server). Up to 5 team addresses get every immediate alert and summary. The webhook posts a short summary and a link to Teams, Slack or any tool that accepts JSON; it must be an https address on the public internet. Use the test buttons to check each one.',
                'The SMTP password and the webhook address are stored encrypted and are never shown again; leave the field empty to keep the saved value. Messages that fail are retried up to 3 times, and the last results are listed on the settings page.',
            ],
        ],
        [
            'title' => 'Audit log',
            'paragraphs' => [
                'Admins can see a record of sign-ins, failed sign-ins, user changes and settings changes under Administration > Audit log (open Administration from your name at the top right). Entries cannot be edited or deleted from the web interface.',
            ],
        ],
    ],
    'releases' => [
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
                'Share check fixes: a server that refuses the share list (an empty answer with "access denied") is no longer reported as listing its shares; empty drive roots count as readable with 0 items; a count that didn\'t finish says "at least"; long share names are opened correctly; Samba\'s anonymous sessions are labelled anonymous.',
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
                'Default-password test fixes: no username is ever tried twice on one host (several ports often share one login); Windows services and pages offering Windows sign-in are never tried; re-runs don\'t repeat attempts and a retest re-checks only what worked; a redirect no longer counts as a login; a 10-minute limit per host; more lockout answers recognised.',
            ],
        ],
        [
            'version' => '1.29.0',
            'date' => '2026-11-23',
            'items' => [
                'Pen-test engagements: optional vendor default-password test, only with an explicit authorisation tick. At most three published defaults per service (FTP, HTTP Basic admin pages, MySQL/MariaDB, PostgreSQL), each a different account, 5 seconds apart, stopping at any lockout; plus databases open without a password (Redis, MongoDB, Elasticsearch, Memcached). Passwords are only shown masked. External and internal (agents 1.29.0+).',
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
                'Attack-surface checks: open DNS zone transfers (each authorised domain\'s own nameservers, once a day) and subdomain takeover (names pointing at a cloud service that no longer exists) are Fails, shown on the client\'s website card. Hypervisor, out-of-band (iDRAC, iLO, IPMI) and NAS admin pages are recognised, with ports 902, 5000, 5001, 8006 and 9090 added to the default list.',
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
                'Pen-test engagements: time-boxed, deeper tests the client signs for (PDF attached), only inside the authorised scope, approved by a different admin, with a kill switch. All TCP ports, common UDP services, safe scripts and anonymous-access checks, externally and through agents (1.27.0+). Ends with a penetration test report and, after fixes, a retest letter.',
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
                'Windows agent (preview): Windows Server 2022/2025 and Windows 11, installed with one PowerShell command shown on the enrolment page; runs as a service under its own low-privilege account; updates from Sentinel through a SYSTEM task that downloads and checks the signed release itself. No Npcap (slower scans) and no name-poisoning check on Windows.',
            ],
        ],
        [
            'version' => '1.25.0',
            'date' => '2026-11-23',
            'items' => [
                'Agent install steps: a How to add an agent guide on the Agents card, and the enrolment page now has the requirements, the install commands for your Sentinel address with copy buttons, a private CA option (SENTINEL_CA for the one-line install), how to check it worked, and troubleshooting. It warns when the site has no internal authorisation yet.',
                'Release key fixes: a damaged or wrongly owned pinned key is never treated as none; the System page and bin/release-sign.php sign the same file list, so the hashes match.',
            ],
        ],
        [
            'version' => '1.24.1',
            'date' => '2026-11-23',
            'items' => [
                'Release key fixes: agents given the key at enrolment can be updated; the key is stored authenticated with the app key (make it again if you made one with 1.24.0); only the release\'s own files are signed, with the manifest hash and file list shown before signing; agents follow several rotations; the fingerprint is printed at enrolment.',
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
                'Gentleness settings corrected: Very gentle now finishes real scans; Faster is labelled as the heavier traffic it is.',
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
                'Clients sync from ITFlow every 15 minutes: new clients, renames and archives (new clients are never scanned until authorised).',
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
                'On-premises agents: internal network scans from a small Linux appliance at the client\'s site, with signed internal authorisations and signed jobs.',
                'Internal devices with open services, certificates and web pages; vulnerable services and certificate problems become findings.',
                'New-device alerts after a site\'s first scan, and a kill switch per site.',
                'Groundwork for NinjaOne: installed software matched to vulnerabilities, unsupported Windows, antivirus, encryption and missing updates (the connector follows in a later release).',
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
                'WordPress, Drupal, Joomla and common JavaScript libraries are recognised, and visible versions are matched to known vulnerabilities.',
                'Email security: SPF, DMARC and DKIM for every authorised domain that receives email.',
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
                'Report branding: company name, logo, colour, footer text and paper size.',
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
                'Suggestions you approve into a new authorisation. Names at other providers are never suggested.',
                'A "Change scope / renew" shortcut that pre-fills a replacement authorisation.',
            ],
        ],
        [
            'version' => '0.2.0',
            'date' => '2026-11-21',
            'items' => [
                'Clients and sites, with optional ITFlow IDs, timezone and scan window.',
                'The "authorised to scan" register: who approved scanning, for which dates, and exactly what may be scanned.',
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
                'No scanning yet. Clients and the "authorised to scan" register come next.',
            ],
        ],
    ],
];
