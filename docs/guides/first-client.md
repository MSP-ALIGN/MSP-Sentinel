# Your first client

Add a client, record what they authorised you to scan, and run the first scan.

## Before you start

- You need the **admin** role to add clients and record authorisations. Technicians can scan and run discovery.
- Have the client's written approval to hand: who approved it, their role, the dates, and the exact addresses and
  domains. The [authorisation form](../authorisation-form.md) is a template you can send them.

## Add the client

1. Go to **Clients** and click **Add client**.
2. Enter the **client name**.
3. Pick the **client time zone**. The scan window and the authorisation dates use it.
4. Set the **scan window** (from and to, in the client's time), for example 22:00 to 06:00. Scheduled scans only run
   inside it.
5. Optionally add extra ports to scan, ports never to scan, notes, or the ITFlow client ID. Save.

Opening a client switches the left menu to that client: **Overview**, **Findings**, **External** (scans and ports,
vulnerabilities, certificates and web, website and email), **Internal** (agents, devices) and **Manage**
(authorisations, discovery, reports). **All clients** at the top takes you back.

## Record the authorisation

1. On the client's page, click **Record authorisation**.
2. Enter who at the client approved scanning (name and role), the date they approved it, and the dates it is valid
   (at most 2 years). Add a document reference if you keep the signed form elsewhere.
3. In **Scope**, enter one entry per line:
   - single public IP addresses, for example `203.0.113.10`;
   - public ranges up to a /24, written as the network address, for example `198.51.100.0/24`;
   - domain names, for example `client.example`;
   - `*.client.example` to cover every subdomain (list `client.example` as well if the bare domain should be scanned).
4. Tick the box confirming the client gave this authorisation, and click **Record authorisation**.

What is refused here:

- **Private and internal addresses** (10.x, 172.16-31.x, 192.168.x and similar). This register is for scans from the
  internet. Internal networks are approved per site on the Agents page: see [On-premises agents](agents.md).
- **Wildcards under shared platforms or public suffixes**, such as `*.s3.amazonaws.com`, `*.github.io` or `*.co.uk`:
  they belong to many unrelated owners.

If an entry is already in another client's scope, Sentinel warns you: it is usually a typo.

## Discover forgotten hostnames (optional)

1. Open the client's **Discovery** page (under Manage) and click **Discover now**.
2. Sentinel reads DNS and public certificate logs and suggests names under the client's own domains. Nothing connects
   to the client's systems.
3. An admin ticks the ones that belong to the client and clicks **Add selected to a new authorisation**. Ask the client
   to approve the additions, then save: the new authorisation replaces the old one.

Dismiss suggestions you don't want; they stay dismissed.

## Scan

1. Open the client's **Scans** page (under External) and click **Scan now**. The scan starts when the client's scan
   window opens, or within a minute or two if it is open now.
2. Admins can tick **Run outside the window** and give a reason (it is written to the audit log).
3. Or do nothing: the weekly scan runs by itself in the scan window.

The client's **Overview** shows **Not scanned yet** until the first scan finishes. Then it shows the risk score
(0 to 100, higher is worse), open findings and the attack surface.

## Good to know

- Authorisations can't be edited. If the scope changes, record a new one that replaces the old one, or revoke it with
  a reason. The register always shows exactly what was approved and when.
- The dashboard lists authorisations ending within 30 days, so you can ask the client to renew in time.
- A client added from ITFlow is not scanned until you record its authorisation, like any other.
- **Pause** on the client page stops its scans at once (technicians and admins). Only admins resume.
- Scans are gentle: slow TCP connect scans with nmap, rate-limited, and only of what is in scope today.
- Next: [read and triage the findings](findings.md).
