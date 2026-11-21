<?php

/**
 * MSP Sentinel configuration.
 *
 * Copy this file to config/config.php and fill in your values.
 * config/config.php holds secrets: keep it readable only by the web server
 * user and never commit it (it is in .gitignore).
 */

return [
    // 32 random bytes, base64. Generate with: php bin/generate-key.php
    // It encrypts secrets at rest (2FA seeds etc.). Back it up: if it's lost, users must enrol 2FA again.
    'app_key' => '',

    'db' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'msp_sentinel',
        'user' => 'msp_sentinel',
        'pass' => '',
    ],

    'app' => [
        // Set when Sentinel is served from a sub-folder, e.g. '/sentinel'. Leave empty at the web root.
        'base_path' => '',
        // Always mark the session cookie Secure. Keep true in production (HTTPS).
        'force_secure_cookies' => true,
        // IPs of reverse proxies whose X-Forwarded-For / X-Forwarded-Proto headers are trusted.
        'trusted_proxies' => [],
        // Interface language (lang/<code>.php). English is the only one shipped so far.
        'locale' => 'en',
    ],

    // Passive discovery (DNS lookups and certificate logs).
    'dns' => [
        // IP of the DNS resolver to ask. Empty = the first nameserver in /etc/resolv.conf.
        'resolver' => '',
        'port' => 53,
        'timeout' => 2.0,
    ],
    'crtsh' => [
        // Certificate Transparency search via crt.sh (free, public). Set false to turn it off.
        'enabled' => true,
        'base_url' => 'https://crt.sh',
        'timeout' => 30,
    ],
    'discovery' => [
        // Seconds a "Discover now" click may take before it stops (the weekly job has no limit).
        'manual_budget' => 25,
        // Pause between crt.sh requests, to be gentle with a free public service.
        'crtsh_delay' => 1.0,
    ],
];
