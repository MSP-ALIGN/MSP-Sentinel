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
        // The address users open Sentinel at, e.g. 'https://sentinel.msp.example'. Used for links in alert
        // emails and webhooks; leave empty and alerts are sent without links.
        'public_url' => '',
    ],

    // Update check: once a day the worker asks this releases feed for the latest version (nothing else is sent).
    // Turn it off under Administration > System. Point it at your own mirror if you prefer.
    'updates' => [
        'url' => 'https://api.github.com/repos/msp-align/msp-sentinel/releases/latest',
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
    // Port scanning. nmap is NOT bundled (its licence is the NPSL): install it with your package manager.
    'scanner' => [
        'nmap_path' => '/usr/bin/nmap',
        // Seconds one host may take before nmap is stopped.
        'host_timeout' => 1500,
    ],

    // TLS checks. Leave ca_file empty to use the system trust store. Set it to a PEM file with extra CAs
    // (e.g. an internal CA): they are ADDED to the system store, not used instead of it.
    'tls' => [
        'ca_file' => '',
    ],

    // Vulnerability data (public feeds). The NVD API key is optional but makes NVD queries ~10x faster.
    // Request one free at https://nvd.nist.gov/developers/request-an-api-key. Keep it here, never in the database.
    'nvd' => [
        'api_key' => '',
        'base_url' => 'https://services.nvd.nist.gov',
        'max_queries_per_run' => 500,
    ],
    'kev' => [
        'url' => 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    ],
    'epss' => [
        'base_url' => 'https://api.first.org',
    ],

    'discovery' => [
        // Seconds a "Discover now" click may take before it stops (the weekly job has no limit).
        'manual_budget' => 25,
        // Pause between crt.sh requests, to be gentle with a free public service.
        'crtsh_delay' => 1.0,
    ],
];
