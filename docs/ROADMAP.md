# MSP Sentinel: roadmap to a full security suite

Status: **draft**. The details of each phase are agreed with the owner before that phase is built.

Sentinel is built for **any MSP**, not only ours. Each MSP self-hosts its own copy and owns its data. Reports can be
fully white-labelled.

The goal is one self-hosted product that covers an MSP client's security from three angles:

| Angle | Question it answers | Phase |
|---|---|---|
| **External** | What can an attacker on the internet see and reach? | 1.x |
| **Internal** | What is exposed or vulnerable inside the client's network? | 2.x |
| **Testing** | Can the weaknesses actually be used, and how far could an attacker get? | 3.x |

All three feed one findings list per client, one alert system, one set of reports and one API for MSP Align.
Each finding records its **source** (external, internal, authenticated, or pen test).

---

## Phase 1: external exposure (v1.0 to v1.x)

**v1.0** (see `DESIGN.md`):
- external port and service scan
- admin and VPN page detection
- TLS certificate checks
- DNS and crt.sh discovery
- NVD, KEV and EPSS matching
- findings and triage
- alerts by email, webhook and in-app
- **reports: Executive Summary and Technical Findings** (print-ready HTML/PDF, MSP branding)
- the Align API

**v1.x follow-ups:**
- ITFlow: automatic tickets for new FAIL findings, and asset matching
- More reports: Change/Trend report, Compliance Evidence Pack, scheduled monthly email delivery
- Nuclei, limited to safe detection templates, to identify products better
- Optional monthly top-1000 port sweep inside the client's scan window
- Remote scanner node, so scans run from an IP other than the web server
- SSO (OIDC, including Entra ID) alongside local logins with 2FA
- **Email and domain security:** SPF, DKIM, DMARC, MTA-STS and DNSSEC checks, plus domain expiry warnings
- **Lookalike domains:** detects newly registered domains that imitate a client's domain
- **Subdomain takeover:** DNS records that still point at deleted cloud resources
- **Web exposure basics** (safe checks only): missing security headers, exposed `.git` and `.env` files, directory
  listing, outdated CMS
- **Fix workflow:**
  - assign findings to people
  - due dates by severity, for example KEV within 7 days, critical within 14, high within 30 (configurable)
  - overdue alerts
  - a **"verify fix"** button that rescans just that one item
- **MSP-wide risk dashboard:** ranks all clients by risk (KEV + EPSS + exposure), so you can see who needs attention
  first

## Phase 2: internal scanning with the Sentinel Agent (v2.x)

A small **collector** installed at each client site. It can see inside the network, which an outside scan can't.

**How it works (safe by design):**
- **Outbound only.** The agent connects out to Sentinel over HTTPS. The client's firewall needs no inbound rules.
- **Enrolment:** an admin creates a one-time enrolment code for a site. The agent then exchanges it for its own key.
  Each agent can be revoked on its own.
- **Signed jobs.** Sentinel signs every job, and the signed job includes its scope. The agent checks the signature
  and the scope itself before scanning. Even a compromised Sentinel database can't make an agent scan outside its
  approved site scope.
- The agent returns results only. It never takes arbitrary commands, and it has no remote shell.
- Each site gets its own rate limits, scan window and kill switch.

**What it does, in steps:**
1. **v2.0, discovery and unauthenticated scan:**
   - finds live hosts and their open ports and services
   - internal certificates
   - legacy and risky protocols: SMBv1, SMB signing off, Telnet, cleartext admin, SNMP with default communities
   - CVE matching with the same confirmed/possible rules as v1
2. **v2.1, asset inventory:**
   - new-device alerts ("unknown device joined the network")
   - matches devices to ITFlow assets
   - feeds Align's lifecycle data
3. **v2.2, authenticated scans** (optional, per site):
   - logs in with read-only credentials (Windows over WinRM, Linux and network devices over SSH)
   - reads exact patch levels and installed software, so most CVE findings become **confirmed**
   - credentials are encrypted at rest and never shown again after they're saved
4. **v2.3, optional deep-scan engine:** Greenbone/OpenVAS as an add-on for full vulnerability scans. It runs as a
   separate program, and its license is checked before we package it.
5. **Internal reports:** internal findings are added to the existing reports. Adds a network inventory report and a
   patch-status report (from authenticated scans).
6. **Hardening checks through the agent:** checks devices against public baselines, such as host firewall off,
   disk encryption off, too many local admins, or outdated OS builds.
7. **Microsoft 365 / Entra ID checks:**
   - read-only API access, with the narrowest permissions possible
   - detects misconfigurations: MFA gaps, legacy authentication still allowed, risky external sharing, mail
     forwarding to outside addresses
   - Align keeps *reporting* on M365. Sentinel only *detects* problems.
8. **Breach / leaked credentials:** alerts when accounts on a client's domain appear in breach data. The data source
   and its terms still need choosing. Sentinel stores only the account and the breach name, never passwords.
9. **Firewall config review:** upload a firewall config export and get a check for risky rules (any-any rules,
   admin access from the internet, unused rules). It needs no live access. Uploaded files are treated as untrusted
   and parsed safely.
10. **Later candidates:** Active Directory hygiene checks (stale accounts, risky delegation, weak password policy),
    and Wi-Fi exposure.

## Phase 3: penetration testing (v3.x)

Until this phase ships, Sentinel is called **vulnerability scanning**, never pen testing.

**Engagements come first. Nothing runs without one.** Each engagement records:
- the client, and a **signed authorisation document** (uploaded, plus the signer's name and role and the date)
- an exact scope (IPs, domains and sites), plus explicit exclusions
- a time window. Testing outside it is refused.
- a **second person** who approves the engagement before it can start (two-person rule)
- the allowed test types, chosen from a fixed list
- a **kill switch** that stops every running test for the engagement immediately, on the server and on the agents
- a full audit trail: who started what, when, against which target, and the result

**Steps, from least to most risky:**
1. **v3.0, safe checks:**
   - default credentials against a short, vetted list, with lockout-aware limits
   - weak TLS
   - exposed admin interfaces
   - anonymous access (FTP, SMB shares, SNMP)
2. **v3.1, guided testing:**
   - password-policy testing within strict, lockout-safe limits
   - intrusive templates that are allowed only inside an engagement
   - internal tests through the agent
3. **v3.2, controlled exploitation:**
   - only vetted modules, only inside an approved engagement and window
   - each module is labelled with its risk (for example "may crash the service") and needs explicit opt-in
4. **Pen-test report:** an executive summary, the engagement scope and authorisation, a methodology section, attack
   paths, findings with evidence (screenshots and request/response excerpts with secrets redacted), the fixes, and a
   **retest workflow** that issues a retest letter once fixes are verified.

5. **Phishing simulation (v3.x, later):**
   - campaigns only inside an approved engagement, with a written sign-off from the client
   - no collection of real passwords: the landing page records the click or submit only, and never stores what was
     typed
   - training pages after each click, and results reported by department, not used to name and shame individuals
   - the legal and HR points are checked before this is built

Pen-test results never replace an independent third-party test where a regulator or insurer requires one. Sentinel
helps prepare for that test and track the fixes.

---

## Reports across the suite

One report engine serves every phase, so all reports look and read the same.

| Report | Audience | Phase |
|---|---|---|
| Executive Summary | Client owner / management | v1.0 |
| Technical Findings | Technicians | v1.0 |
| Change / Trend | MSP and client, monthly | v1.x |
| Compliance Evidence Pack | Auditors, cyber-insurance | v1.x |
| Network Inventory and Patch Status | Technicians, Align lifecycle | v2.x |
| Penetration Test Report and Retest Letter | Client, auditors | v3.x |

Each report is a frozen snapshot that never changes after it's issued, carries the MSP's branding, prints cleanly,
and never shows severity by colour alone.

## Built into v1.0 now, so later phases don't need a rewrite

These cost little in v1.0 and avoid redesigning later:

1. **Scanner nodes:** v1.0's local worker is registered as scanner node #1. Jobs are assigned to a node, so later
   the remote scanner and agents are simply more nodes.
2. **Findings carry `source`**, plus an optional `site_id` and `engagement_id` (left empty in v1.0).
3. **Clients have sites:** each client gets one default site in v1.0, ready for agents later.
4. **Jobs are self-contained:** each job carries its target list and its scope, so it can be signed later without
   changing the job format.
5. **A global and per-client kill switch** exists from v1.0. It pauses all scanning straight away.

## Parked ideas (not planned yet)

- Client portal: read-only logins for client contacts to see their own reports
- SIEM / syslog (CEF) export of findings
- Multi-MSP hosting (multi-tenancy). Deliberately left out: each MSP self-hosts.

## Principles for every phase

- Authorised targets only. Scope is checked when the job is scheduled and again right before the scan.
- Gentle by default, run only inside each client's scan window.
- Honest findings: show the "last checked" date, keep confirmed and possible separate, and never guess.
- Prefer mature open-source engines, and check each one's license before bundling anything.
- Self-hosted. The MSP owns its data.
