# Configuration reference

Settings that need a server administrator live in `config/config.php` (a PHP file returning an array; start from
`config/config.example.php`). Settings an admin changes in the web interface (alerts, branding, retention, API) live
in the database and are described in the in-app Help.

Keep `config/config.php` private (mode 0640, owned by root with the app's group) and back it up: its `app_key`
cannot be recovered. Set the path in the `SENTINEL_CONFIG` environment variable to keep it somewhere else.

| Key | Default | What it does |
|---|---|---|
| `app_key` | (none) | 32 random bytes, base64 (`php bin/generate-key.php`). Encrypts 2FA seeds and saved secrets (SMTP password, webhook addresses, event secret) and keys the API token hashes. **If it changes, 2FA, saved secrets and API tokens stop working.** |
| `db.host`, `db.port`, `db.name`, `db.user`, `db.pass` | `127.0.0.1`, 3306, `msp_sentinel`, `msp_sentinel`, | MariaDB connection. `localhost` uses the local socket. |
| `app.base_path` | `''` | Set when Sentinel is served from a sub-folder, e.g. `/sentinel`. |
| `app.force_secure_cookies` | `true` | Always mark the session cookie Secure. Keep `true` in production. |
| `app.trusted_proxies` | `[]` | Reverse-proxy addresses whose `X-Forwarded-For`/`-Proto` headers are believed. Needed for correct client addresses (sign-in throttling, API allowlists and rate limits). |
| `app.locale` | `en` | Interface language (`lang/<code>.php`). |
| `app.public_url` | `''` | The address users open, e.g. `https://sentinel.msp.example`. Used for links in emails and webhooks. |
| `updates.url` | GitHub releases API | Feed for the daily update check. Only a version number is read from it. |
| `dns.resolver`, `dns.port`, `dns.timeout` | first resolver in `/etc/resolv.conf`, 53, 2.0 | DNS server for passive discovery and for resolving scan targets. |
| `crtsh.enabled`, `crtsh.base_url`, `crtsh.timeout` | `true`, `https://crt.sh`, 30 | Certificate Transparency search for discovery. |
| `scanner.nmap_path` | `/usr/bin/nmap` | nmap binary. nmap is not bundled (NPSL licence). |
| `scanner.host_timeout` | 1500 | Seconds one host may take before nmap stops. |
| `tls.ca_file` | `''` | Extra CA certificates (PEM) for certificate checks and SMTP, **added** to the system store. |
| `nvd.api_key` | `''` | Optional NVD API key (free); makes lookups about ten times faster. |
| `nvd.base_url`, `nvd.max_queries_per_run` | NVD, 500 | NVD API and how many lookups one feeds run may make. |
| `kev.url` | CISA feed | CISA Known Exploited Vulnerabilities catalog. |
| `epss.base_url` | `https://api.first.org` | FIRST EPSS scores. |
| `discovery.manual_budget` | 25 | Seconds a "Discover now" click may take. |
| `discovery.crtsh_delay` | 1.0 | Pause between crt.sh requests. |

## Environment variables

| Variable | Used by | What it does |
|---|---|---|
| `SENTINEL_CONFIG` | everything | Path of the config file. |
| `SENTINEL_BACKUP_PASSPHRASE` | `bin/backup.php --encrypt`, `bin/restore.php` | Backup passphrase (at least 12 characters) for unattended runs. |
| `SENTINEL_ALLOW_ROOT` | `bin/worker.php` | Lets the worker run as root. **Don't**, except in throwaway test containers. |

## Never in production

`testing.allow_documentation_ranges` exists only for the test suite. It must not be set on a real install.
