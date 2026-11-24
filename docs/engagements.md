# Pen-test engagements (1.27)

An engagement is a time-boxed, deeper test that a client authorises in writing. It ends with a penetration test
report and, after the fixes, a retest letter. Day-to-day scanning stays gentle; only an approved engagement tests
harder, and only inside its window.

## What an engagement may do

Chosen per engagement, from a fixed list:

| Test | What it does |
|---|---|
| All 65,535 TCP ports | Instead of the usual port list. Finds services on unusual ports. |
| Common UDP services | One read-only request each: SNMP's default communities, NTP (an ordinary time request), SSDP/UPnP discovery. |
| nmap's "safe" scripts | Details of each service. Excluded: vulnerability checks (some send attack-like requests), and anything that broadcasts, contacts third parties, guesses passwords, may crash a service, exploits, fuzzes or checks for malware. |
| Anonymous access | Anonymous FTP login (lists the top folder), NFS exports, and SMB file shares (1.30). Read only. For SMB, Sentinel's own check signs in anonymously, with no username, so no account can be locked. It reads the share list, then opens each disk share's top folder for listing only and counts the items in it: it never opens a file, never goes into a subfolder and never writes. Only share names and counts are kept, never file names. (nmap's share script isn't used: it writes and deletes a test file in every share.) Agents need version 1.30.0 for the SMB part. |
| Vendor default passwords (1.29) | Needs a second tick: the signed authorisation must allow it explicitly (annex P3). At most three published vendor defaults per service, on FTP, web admin pages that ask for a Basic login, MySQL/MariaDB and PostgreSQL. No username is ever tried twice on one host (whatever the port or service), so no account sees more than one failed attempt. Attempts on a host run one at a time, 5 seconds apart, and stop at the first success, at any lockout or block, or after 10 minutes per host. Windows services are never tried: IIS, WinRM/HTTP.sys and IIS FTP are skipped, and so is any web page that also offers Windows sign-in (Negotiate/NTLM), because its Basic login checks directory accounts. Running the tests again in the same engagement doesn't try again (the earlier result stands); a retest tries only the accounts that worked before, once each. A device reachable both from the internet and inside the network is tested from both sides (different addresses): list it in one place only if that matters. A login that works is closed at once; nothing is read. Also checks, without guessing, whether Redis, MongoDB, Elasticsearch/OpenSearch and Memcached answer with no password at all. Only services the port scan found are tried, so tick all ports to cover unusual ports. Agents need version 1.29.1. |

Pace, per engagement: gentle (the same as day-to-day scans) or normal (nmap `-T3`, at most 200 packets a second).
Nothing faster exists. All 65,535 ports need the normal pace: at the gentle pace one host would take about 7 hours.

**Never done:**

- password guessing (beyond the short vendor default list, only when that test is chosen);
- SSH, Windows, Remote Desktop, WinRM or directory logins (lockout risk);
- exploits;
- denial of service;
- anything that writes to or changes the systems tested.

## The rules

- **Inside the authorised scope only.** External targets must already be in the client's active "authorised to scan"
  scope, and internal ranges inside the site's active internal authorisation. This is checked when the engagement is
  created (for today and the window's last day), and again live for every host while it is tested. An engagement adds
  consent to test harder; it never widens what may be tested.
- **Exclusions are never touched.** They are given as IP addresses or ranges (not names): fragile or third-party
  systems. Agents leave them out of the discovery sweep too.
- **The client's signed authorisation** is attached as a PDF when the engagement is created. Sentinel keeps it as a
  download (never shown in the browser) and records its SHA-256 in the report. A template is in
  [authorisation-form.md](authorisation-form.md#annex-penetration-test-engagement).
- **Two people (by default).** A technician or admin creates it; a different admin approves it, with their password.
  Nothing runs before approval. An Admin who holds every permission and sees every client can turn this off under
  **Administration → Settings → Pen-test engagements** (with their own password; everyone who may approve is told).
  With it off, the creator may approve their own engagement if their role may approve engagements, still with their
  password and still before anything runs, and the engagement page, audit log and pen-test report say
  "single-person approval". A technician who can't approve still needs someone who can. Each engagement keeps the rule
  in force when it was created: one created under the two-person rule always needs a second person, and one created
  while it was off needs a second person again once the rule is back on.
- **A window of at most 14 days.** Nothing runs outside it.
- **Kill switch.** **Stop engagement** (technicians and admins, with a reason) ends it for good. Sentinel's own tests
  stop within seconds; a UDP check already sent finishes first. Agents stop at their next check-in (within a minute),
  and also on their own at the window's end, even if they can't reach Sentinel. The global and per-client pause
  switches stop engagements too.
- **Checked all the way.** Every host is checked right before and while it is tested: the engagement must be active,
  the host must be a target and not excluded, and it must be in the live authorised scope. Agents check the signed
  job again.
- **Everything is audited:** created, approved, started, stopped, cancelled, report issued.

## How to run one

1. **Client → Pen-test engagements → New engagement.** Enter:
   - the name and the window;
   - the tests and the pace;
   - the targets and any exclusions;
   - the signed PDF, who signed it, their role and the date.
2. **Approval.** Another admin opens it, checks that the PDF matches, and clicks **Approve** with their password.
3. **Run the tests.** In the window, click **Run external tests** (from Sentinel) and/or **Run internal tests**
   (through each site's agent; agents need version 1.27.0 or later). External tests run in slices: after 20 minutes,
   a slice ends when its current host is done, and the rest continues as a new job, so other clients' scans get their
   turn.
4. **Read the results.** The engagement page lists the findings, with evidence and how to fix them. Since 1.39 the
   Fails and Warnings also become findings (type **Pen test**) with the usual triage, owners, due dates, groups and
   ITFlow tickets; the engagement page keeps the raw results, and the client's services, certificates and device
   inventory are not changed. A result the regular checks already raise isn't doubled. For each host and test, the
   newest engagement that ran it decides, so a retest resolves what it no longer finds and leaves alone what it
   didn't test.
5. **Issue penetration test report.** The report is a frozen copy with your branding. It contains:
   - a summary and rating;
   - how the findings chain together;
   - scope and authorisation;
   - the method, and what was never done;
   - every finding with its evidence and fix;
   - the systems tested;
   - the limitations.

   It can be downloaded as HTML (print to PDF) or as a CSV of the findings.

## Retests

When the client has fixed things, create a new engagement and choose **This is a retest of** the earlier one. It has
its own signed authorisation and window. Run its tests and click **Issue retest letter**. Each Fail and Warning of the
earlier report is then marked:

- **fixed**: the finding is gone, its host was tested to the end, and the retest ran the same test (for open ports:
  all ports again, or the same port list as before);
- **still open**;
- **not retested**: anything else (the host wasn't tested again, or wasn't tested to the end, or that test didn't run
  this time).

## Findings

| Severity | Findings |
|---|---|
| **Fail** | A file share readable without a password; the share list handed out to anyone from the internet; a vendor default password that works (the evidence shows the username; the password only masked, like a•••n); a database open without a password; anonymous FTP login; SMBv1; NFS exports open to everyone; SNMP's default "private" community; SNMP "public" from the internet; Telnet; high-risk services (RDP, SMB, databases, WinRM and others) reachable from the internet |
| **Warning** | The share list handed out to anyone inside the network; Memcached open without a password inside the network; SMB signing not required; NFS exports listed to anyone; SNMP "public" inside the network; plain FTP; VNC; UPnP/SSDP answering from the internet |
| **Info** | Other services found, NTP, a service that signalled a lockout during the default-password test (testing stopped there) |

## Limits

- **No UDP port scan.** nmap runs unprivileged (TCP connect scans), as in day-to-day scanning. Common UDP services are
  checked with Sentinel's own read-only probes instead.
- **SMB servers or shares that require encryption** (Windows "EncryptData" or "RejectUnencryptedAccess") show as
  refused or not readable: the share check doesn't encrypt. It can miss an open share there; it never invents one.
- **No breached-credential checks yet.** These are next on the [security roadmap](ROADMAP-security.md). Zone
  transfers and subdomain takeover are checked every day for every client (1.28), not only in engagements.
- **Not a replacement for an independent test.** Where a regulator or insurer requires an independent third-party
  penetration test, this doesn't replace it; it helps prepare and track the fixes.
