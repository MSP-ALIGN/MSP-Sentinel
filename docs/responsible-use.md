# Responsible use

Sentinel scans systems on the internet. Scanning without permission can be illegal, and laws differ by country.

- **Only scan what you are authorised to scan.** Get written permission from each client (see the
  [sample form](authorisation-form.md)), and from hosting or cloud providers where their terms require it.
  Record every approval in Sentinel's register: Sentinel refuses to touch anything outside an active authorisation.
- **Stay gentle.** The defaults (TCP connect scans, low rates, a scan window, the start page plus a short fixed list
  of about ten paths per web service, email records by DNS only) are chosen to avoid disruption. Don't raise them without the client's agreement.
- **Protect the results.** Findings are a map of weaknesses: limit who can see them, use 2FA, encrypt backups.
- **Be honest.** Present "possible" vulnerabilities as possible. Never present Sentinel's results as a penetration
  test or a PCI ASV scan.
- **Stop when asked.** Use the kill switch if a client reports a problem during a scan.

The software is provided under the AGPL-3.0 without warranty; you are responsible for how you use it.
