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
            'title' => 'Audit log',
            'paragraphs' => [
                'Admins can see a record of sign-ins, failed sign-ins, user changes and settings changes under Administration > Audit log. Entries cannot be edited or deleted from the web interface.',
            ],
        ],
    ],
    'releases' => [
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
