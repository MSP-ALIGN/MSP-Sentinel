# User guide

A short tour for technicians and viewers. The in-app **Help** page has more detail on every screen.

## Roles

| Role | Can |
|---|---|
| Viewer | See clients, findings, scans and reports |
| Technician | Also run discovery, queue and cancel scans, triage findings, create reports, pause scanning |
| Admin | Also manage users, clients and authorisations, settings, alerts, branding, API tokens and the System page; resume scanning; delete reports |

## A client's pages

Open a client from **Clients** and the left menu switches to that client: **Overview** (risk, trend, details, scanning
and sites), **Findings**, then **External** (scans and ports, vulnerabilities, certificates and web pages, website and
email), **Internal** (agents, devices) and **Manage** (authorisations, discovery, reports). Each is its own page with
its own address, so you can bookmark or share a link to, say, a client's devices. **All clients** at the top takes you
back. The client's forms (edit, new authorisation, agent enrolment, a device) keep the same menu.

## A client from start to finish

1. **Add the client** (admin): name, time zone and a scan window (when scans may run, in the client's time).
2. **Record the authorisation** (admin): who approved scanning, when, until when, and exactly which addresses and
   names. Sentinel only ever touches what is listed here, and only while it is valid.
3. **Discover** (optional): Sentinel suggests forgotten hostnames from DNS and certificate logs. An admin adds the
   ones that belong to the client to a new authorisation.
4. **Scan**: queue a scan, or let the weekly schedule do it. Scans are gentle and run in the scan window.
5. **Findings**: everything graded Fail or Warning becomes a finding. Fix it, or **triage** it with a note:
   - **accepted risk** (the client knows and accepts it);
   - **false positive** (it isn't really a problem; it reopens if the evidence changes).

   Findings resolve by themselves when a check no longer sees the problem.

   **Fix them on time:** assign each finding to a technician (or "Assign to me"). Every open finding has a due date
   (known-exploited 7 days, Fail 14, Warning 30; admins can change these). Owners get a daily reminder of overdue and
   due-soon findings. After fixing something, press **Verify fix** to recheck just that finding straight away.
6. **Alerts**: new and returning Fail findings are announced straight away (bell, email, Teams or Slack); a summary
   follows each scan. Choose your emails on your profile.
7. **Reports**: create an Executive summary for management and a Technical findings report for IT (Reports card on
   the client's **Reports** page). Print to PDF from the browser. Reports are frozen: they never change after they are made.

## NinjaOne

Sentinel can read each client's computers from NinjaOne. It only reads; it never changes anything in NinjaOne.

1. In NinjaOne, go to **Administration → Apps → API → Client App IDs** and click **Add client app**:
   - Application platform: **API Services (machine-to-machine)**; name: MSP Sentinel.
   - Scopes: **Monitoring** only. Allowed grant types: **Client credentials**.
   - Save, and copy the client ID and client secret (NinjaOne shows the secret once).
2. In Sentinel, go to **Administration → Integrations**. Enter the instance (the address you sign in to NinjaOne at,
   for example `app.ninjarmm.com` or `eu.ninjarmm.com`), the client ID and the secret. Tick **Sync linked clients**,
   save, and click **Test connection**.
3. On each client's **Devices** page, click **Link to an organisation** and pick its NinjaOne organisation. Use
   **Sync now** for a first look; after that it syncs every 6 hours.

What comes over: computers (Windows, macOS and Linux workstations and servers) that are approved in NinjaOne, with
their operating system, antivirus, BitLocker on the system drive, missing and failed Windows updates, and installed
software. Network devices, phones and devices waiting for approval are left out. Anything NinjaOne doesn't report
stays unknown and is never a finding. If a sync fails part-way, nothing is changed and the next sync tries again.

The Sentinel server needs outbound HTTPS to your NinjaOne instance.

## On-premises agents

For a client's internal network, install an agent at the site (see [`agent.md`](agent.md)): record an internal
authorisation for the site, create an enrolment code, and run the agent installer with it. Internal devices, their
services and certificates then appear on the client's **Devices** and **Agents** pages, with findings and new-device alerts.

## Website and email checks

With each scan and once a day, Sentinel checks every website it found (HTTPS, headers, cookies, a short fixed list of
commonly exposed files, and the CMS and libraries it can see) and the SPF, DMARC and DKIM records of every authorised
domain that receives email. Results are on the client's **Website & email** page. Exposed files are
only reported when their content proves it, and their content is never stored. Email checks use DNS only.

## Grades

- **Fail:** fix now. For example: Remote Desktop or a database open to the internet, an expired certificate, an
  exposed firewall admin page, a login page without HTTPS, an exposed .git folder, .env file or backup, an SPF
  record that lets anyone send email as the domain, or a confirmed critical or known-exploited vulnerability.
- **Warning:** fix soon. For example: a certificate expiring within 14 days, old TLS versions, an exposed VPN portal,
  a website without an HTTPS redirect, HSTS or Content-Security-Policy, insecure cookies, missing SPF or DMARC (or
  DMARC set to p=none), or a confirmed high-severity vulnerability.
- **Info:** shown on the client's pages, not a finding.

Vulnerabilities say whether they are **confirmed** for the exact version or only **possible** (version unknown, or a
distribution build that may already carry the fix). Sentinel never guesses a version.

## What Sentinel is not

It checks your clients' networks gently and honestly: from the outside, and inside where an on-premises agent is
installed. It does not log in to systems, guess passwords (apart from the optional read of default SNMP community
names by agents) or exploit anything. It is not a penetration test, and it is **not a PCI ASV scan**.
