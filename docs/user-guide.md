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

## ITFlow

ITFlow is the list of clients (see [ROADMAP-itflow.md](ROADMAP-itflow.md) for where this is going: tickets from
findings, closed from ITFlow). Today Sentinel keeps its clients in step with ITFlow:

1. In ITFlow, add an agent named MSP Sentinel with a role that can read clients and access to all clients. Then go to
   **Admin → API Keys**, create a key for that agent (with an expiry date) and copy it.
2. In Sentinel, go to **Administration → Integrations → ITFlow**: enter ITFlow's address and the key, tick **Sync
   clients from ITFlow**, save, and click **Test connection**, then **Sync now**.

Every 15 minutes after that:

- A new ITFlow client is added to Sentinel with its ITFlow ID. **It is not scanned** until someone records its
  written authorisation, like any other client.
- An active Sentinel client with the same name (capitals and accents ignored) and no ITFlow ID is linked instead of
  duplicated. If the name is taken by another client, the new one is called "Name (ITFlow #id)" until the name is
  free.
- A rename in ITFlow is applied in Sentinel.
- A client archived in ITFlow is archived in Sentinel (scanning stops, history is kept); unarchiving it in ITFlow
  restores it. A client you archived or restored yourself in Sentinel is left as you set it from then on. (Restoring
  a client in Sentinel while it is still archived in ITFlow works too; archive and unarchive it in ITFlow if you want
  the sync to follow ITFlow again.)
- Clients that disappear from ITFlow's answer are left alone, and demo clients are never touched.
- With MSP Align connected and ITFlow as MSP Align's PSA, a client is also linked to its MSP Align client
  automatically when MSP Align has the same ITFlow ID (its PSA ID). An ITFlow ID found on two MSP Align clients is
  not linked.

Every change shows in the audit log as "itflow-sync".

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

## Compliance from MSP Align

If you use MSP Align for compliance, each client's **Compliance** page in Sentinel shows the frameworks assigned to
it in MSP Align (CIS, NIST CSF, HIPAA, CMMC, ISO 27001, PCI DSS, SOC 2, cyber insurance, your own...) and, for every
control in an area Sentinel checks, what Sentinel found. Sentinel only reads: control statuses stay in MSP Align.

1. In MSP Align, go to **Settings → API**, turn the API on, and create a key named MSP Sentinel with
   **clients:read** and **compliance:read** only (it can be limited to some clients).
2. In Sentinel, go to **Administration → Integrations → MSP Align**: enter MSP Align's address and the key, tick
   **Show compliance from MSP Align**, save, and click **Test connection**.
3. On a client's **Compliance** page, an admin links it to its MSP Align client (the same name is suggested first).

How findings meet controls: MSP Align tags every control with "crosswalk tags" shared across frameworks (for
example `net_firewall`, `email_auth`, `ep_malware`, `vuln_patch_os`). Sentinel maps each kind of finding to those
tags, so one mapping works for every framework. Each control then shows one of:

- **Open problems**: Sentinel findings in that area, with links to them.
- **No problems found**: Sentinel checked that area for this client in the last 30 days (it says how and when:
  external scan of internet-facing services, email records, NinjaOne device inventory, internal scan) and nothing is
  open. It supports the control; it doesn't prove it. Areas a check can't really judge are never "found fine": an
  external scan can't see MFA, internal patching or hardening, and antivirus isn't EDR.
- **Not checked yet**: the control is in an area Sentinel covers, but there's no data yet (for example no NinjaOne
  link for device controls).

Controls about things Sentinel can't see (policies, training, backups, physical security) are counted, not listed.
MSP Align is read at most once an hour per client; **Read again** reads it now.

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
