# Security and hardening

Sentinel holds a map of your clients' weak spots. Treat the server like a domain controller: few people, strong
sign-in, patched, backed up.

## What Sentinel does for you

- **Authorized targets only:** every scan target is checked against an active, approved authorization at the moment
  of scanning, and there is a global kill switch. Scans are gentle (TCP connect, rate-limited, in the scan window)
  and logged.
- **Sign-in:** mandatory TOTP two-factor authentication, recovery codes stored as keyed hashes, throttling, session
  revocation, three roles (viewer, technician, admin). Every POST is CSRF-checked; every page sends a strict
  Content Security Policy and escapes all output.
- **Secrets:** SMTP password, webhook addresses and the event signing secret are encrypted with libsodium using the
  app key. API tokens and recovery codes are stored only as keyed hashes. Secrets are never shown again after they
  are saved.
- **Outbound requests:** alert and event webhooks must be https on public addresses, are pinned to the checked
  address and never follow redirects (against SSRF). SMTP verifies certificates; plain SMTP only to a local relay.
- **API:** bearer tokens only (no cookies), limited to chosen clients, expiring, optional IP allowlist, rate-limited;
  writes are opt-in and audited.
- **Reports:** frozen with a SHA-256, served with a policy that allows no scripts.
- **On-premises agents:** outbound-only; scan only networks in a signed internal authorization (Ed25519, key derived
  from the app key, never stored in the database); every job signed and checked by the agent (scope, expiry, replay);
  tokens and enrollment codes stored only as keyed hashes; unprivileged, hardened service; revocable. See
  [`agent.md`](agent.md).
- **Audit log:** sign-ins, changes, triage, scans, API writes and retention runs. It is never pruned.

## Your checklist

1. **HTTPS only**, with a trusted certificate (`--certbot`, or your own). Keep `app.force_secure_cookies` true.
2. **Limit who can reach the web interface:** a firewall or VPN in front of it if you can; at least restrict SSH.
   For an IP allowlist on the web interface, add `allow`/`deny` lines at the top of the HTTPS `server` block in
   `/etc/nginx/sites-available/msp-sentinel` (server level, so they cover every location), then
   `sudo nginx -t && sudo systemctl reload nginx`. Remember that API clients and event receivers outside the list
   are blocked too:

   ```nginx
   allow 203.0.113.0/24;   # your office
   allow 198.51.100.7;     # MSP Align server
   deny all;
   ```
3. **Patch the server** (`unattended-upgrades`) and upgrade Sentinel when the System page says so.
4. **Admins:** as few as possible; give technicians and viewers their own accounts. Remove leavers the same day
   (deactivating a user also ends their API tokens).
5. **Config file:** mode 0640, owned by root with the app's group. The health check warns if anyone can read it.
6. **Backups:** encrypt them (`--encrypt`) and copy them off the server; keep the passphrase and the app key in
   your password vault, separately from the backups. Test a restore now and then.
7. **API tokens:** one per integration, only the clients it needs, write permissions only if needed, an IP
   allowlist where possible, the shortest practical expiry. Revoke unused ones.
8. **Reverse proxy:** list it in `app.trusted_proxies`, or sign-in throttling and API limits see only the proxy.
9. **Mail:** use STARTTLS or TLS with authentication; keep the team address list short.
10. **Run the worker as the `sentinel` user**, never root (it refuses unless forced).
11. **Watch the health check** (Administration → System or `bin/doctor.php`) and the logs in `/var/log/msp-sentinel/`.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
