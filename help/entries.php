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
            'title' => 'Audit log',
            'paragraphs' => [
                'Admins can see a record of sign-ins, failed sign-ins, user changes and settings changes under Administration > Audit log. Entries cannot be edited or deleted from the web interface.',
            ],
        ],
    ],
    'releases' => [
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
