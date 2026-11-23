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
| Anonymous access | Anonymous FTP login (lists the top folder) and NFS exports. Read only. SMB share listing isn't included: nmap's script for it writes and deletes a test file in every share. |

Pace, per engagement: gentle (the same as day-to-day scans) or normal (nmap `-T3`, at most 200 packets a second).
Nothing faster exists. All 65,535 ports need the normal pace: at the gentle pace one host would take about 7 hours.

**Never done:**

- password guessing;
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
- **Two people.** A technician or admin creates it; a different admin approves it, with their password. Nothing runs
  before approval.
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
4. **Read the results.** The engagement page lists the findings, with evidence and how to fix them. The results are
   evidence only: they don't change the client's day-to-day findings or device inventory.
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
| **Fail** | Anonymous FTP login; SMBv1; NFS exports open to everyone; SNMP's default "private" community; SNMP "public" from the internet; Telnet; high-risk services (RDP, SMB, databases, WinRM and others) reachable from the internet |
| **Warning** | SMB signing not required; NFS exports listed to anyone; SNMP "public" inside the network; plain FTP; VNC; UPnP/SSDP answering from the internet |
| **Info** | Other services found, NTP |

## Limits

- **No UDP port scan.** nmap runs unprivileged (TCP connect scans), as in day-to-day scanning. Common UDP services are
  checked with Sentinel's own read-only probes instead.
- **No subdomain takeover, zone transfer or breached-credential checks yet.** These are next on the
  [security roadmap](ROADMAP-security.md).
- **Not a replacement for an independent test.** Where a regulator or insurer requires an independent third-party
  penetration test, this doesn't replace it; it helps prepare and track the fixes.
