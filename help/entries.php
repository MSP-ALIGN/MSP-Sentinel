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
                'It also requests the start page of each web port once, without logging in or guessing paths, and recognises firewall and device admin pages, VPN portals, remote desktop web access and other login pages from their wording.',
                'Grading: an expired certificate, or a firewall or device admin page reachable from the internet, is a Fail. A certificate expiring within 14 days, self-signed or untrusted certificates, name mismatches, old TLS and weak keys are Warnings. VPN portals and remote desktop web access are Warnings too: they are often meant to be reachable, so make sure they are patched and use MFA.',
                'Mail services that start TLS later in the connection (STARTTLS on ports 25, 587, 143) are not checked yet.',
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
                'The data refreshes daily (bin/feeds.php). Its status is on the Settings page.',
            ],
        ],
        [
            'title' => 'Findings and triage',
            'paragraphs' => [
                'Findings bring together everything Sentinel grades as Fail or Warning for a client: high-risk services open to the internet, certificate problems, exposed admin pages and portals, and vulnerabilities. Info items are not findings; they stay visible in the client panels.',
                'A finding resolves by itself when a check really sees the problem gone, for example a port that a complete scan finds closed. A host that simply wasn\'t scanned keeps its findings. If a resolved problem comes back, the same finding reopens and is marked "Reappeared", with its whole history. If it had been accepted or marked as a false positive and the evidence is the same, that decision is kept. While a service\'s new vulnerability data is still being fetched, its vulnerability findings are not resolved.',
                'Technicians and admins can triage a finding, always with a note. "Accepted risk" means the client knows and accepts it; it stays accepted until the problem goes away. "False positive" means it isn\'t really a problem; it reopens automatically if the evidence changes, for example if a different version is reported. You can also reopen a finding to undo a decision. Resolving is never done by hand: only checks resolve findings.',
                'The Findings page lists findings across all clients, with filters for client, status, grade and type. Each decision appears in the finding\'s history and in the audit log.',
            ],
        ],
        [
            'title' => 'System, backups and updates (admins)',
            'paragraphs' => [
                'Administration, System shows the health of this install: PHP, the database, migrations, nmap, whether the scan worker and the daily feeds job are running, storage, disk space, HTTPS, email and updates. Fix anything marked Problem first. The server administrator can run the same checks with php bin/doctor.php.',
                'Once a day Sentinel asks the releases feed for the latest version (nothing else is sent) and shows it here when a newer one exists. You can turn this off. Upgrades are done on the server (install.sh --upgrade), which makes a backup first.',
                'Data retention: choose how many months to keep finished scan history, resolved findings and reports. 0 keeps them forever. Older data is removed once a day and the counts are written to the audit log. The audit log itself is always kept.',
                'Backups are made on the server with bin/backup.php (daily, if Sentinel was installed with the installer). They contain all client data and the app key, so encrypt any copy that leaves the server. See docs/backup.md.',
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
                'Admins can turn on monthly reports for a client and enter up to 5 addresses at your MSP. After each month ends (calendar months, UTC), both reports for that month are created once and emailed to those addresses as attachments, for review before you forward them. Reports over 5 MB are not attached; the email then points to them in Sentinel. Deleting a scheduled report does not create it again. If creating them fails, admins get a notification and Sentinel retries hourly, up to 5 times. Email must be set up under Settings, Alerts.',
                'A report shows the status at the moment it is created; "new" and "fixed" count what changed during the chosen period.',
                'Admins set the report branding under Settings, Report branding: company name, logo (PNG or JPEG; it is checked and re-encoded), accent colour, contact details, paper size, and whether the "Generated by MSP Sentinel" line is shown.',
                'Every report states its limits: these are external, non-intrusive checks of the authorised addresses, they do not test internal networks, and they are not a PCI ASV scan.',
            ],
        ],
        [
            'title' => 'Alerts and notifications',
            'paragraphs' => [
                'Sentinel tells you straight away when a Fail finding is new or comes back. After each scan it sends a summary of what changed, and admins are told when a scan or a threat feed fails. Accepted risks and false positives never cause alerts.',
                'Every alert appears under the bell in the header. Open the Notifications page to see them; opening it marks them read. On your profile, choose which emails you get: immediate alerts, the scan summary, both, or none.',
                'Admins set up email and the webhook under Settings, Alerts. Email needs a mail server with STARTTLS or TLS (plain connections are only allowed to a relay on this server). Up to 5 team addresses get every immediate alert and summary. The webhook posts a short summary and a link to Teams, Slack or any tool that accepts JSON; it must be an https address on the public internet. Use the test buttons to check each one.',
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
                'Set up under Settings, Alerts, with test buttons. The SMTP password and webhook address are stored encrypted.',
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
                'Known exploited first, then critical and high; daily feeds job with status on the Settings page.',
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
