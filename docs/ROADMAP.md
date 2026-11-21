# MSP Sentinel: roadmap to a full security suite

Status: **draft**. The details of each phase are agreed with the owner before that phase is built.

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
- the Align API

**v1.x follow-ups:**
- ITFlow: automatic tickets for new FAIL findings, and asset matching
- Client-friendly reports (PDF/HTML), plus a monthly summary per client
- Nuclei, limited to safe detection templates, to identify products better
- Optional monthly top-1000 port sweep inside the client's scan window
- Email security posture: SPF, DKIM, DMARC, MTA-STS
- Remote scanner node, so scans run from an IP other than the web server

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
5. **Later candidates:** Active Directory hygiene checks (stale accounts, risky delegation, weak password policy),
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
4. **Reports:** an executive summary, technical findings with evidence, the fixes, and a retest workflow.

Pen-test results never replace an independent third-party test where a regulator or insurer requires one. Sentinel
helps prepare for that test and track the fixes.

---

## Built into v1.0 now, so later phases don't need a rewrite

These cost little in v1.0 and avoid redesigning later:

1. **Scanner nodes:** v1.0's local worker is registered as scanner node #1. Jobs are assigned to a node, so later
   the remote scanner and agents are simply more nodes.
2. **Findings carry `source`**, plus an optional `site_id` and `engagement_id` (left empty in v1.0).
3. **Clients have sites:** each client gets one default site in v1.0, ready for agents later.
4. **Jobs are self-contained:** each job carries its target list and its scope, so it can be signed later without
   changing the job format.
5. **A global and per-client kill switch** exists from v1.0. It pauses all scanning straight away.

## Principles for every phase

- Authorised targets only. Scope is checked when the job is scheduled and again right before the scan.
- Gentle by default, run only inside each client's scan window.
- Honest findings: show the "last checked" date, keep confirmed and possible separate, and never guess.
- Prefer mature open-source engines, and check each one's license before bundling anything.
- Self-hosted. The MSP owns its data.
