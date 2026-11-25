# Findings

Read what Sentinel found, decide what to do with each finding, and get it fixed on time.

## Before you start

- Everyone can read findings. **Technicians and admins** triage, assign and verify fixes. Only **admins** change
  due dates.

## Read the findings

1. Open **Findings** in the menu for every client, or a client's own **Findings** page.
2. Each finding is graded:
   - **Fail**: fix now. For example Remote Desktop or a database open to the internet, an expired certificate, an
     exposed firewall or NAS admin page, an exposed `.git` folder or `.env` file, an SPF record that lets anyone send
     as the domain, an open DNS zone transfer, a name that can be taken over, or a confirmed critical or
     known-exploited vulnerability.
   - **Warning**: fix soon. For example a certificate expiring within 14 days, old TLS versions, an exposed VPN
     portal, missing HSTS or Content-Security-Policy, missing SPF or DMARC, or a confirmed high-severity
     vulnerability.
   - A certificate that expires soon and then expires stays **one finding**: it moves from Warning to Fail, keeping
     its owner, history and ticket. If the Warning was accepted or marked a false positive, it opens again as a Fail
     with a new deadline: the decision was about the Warning.
   - **Info** items are shown on the client's pages but are not findings.
3. Use the filters (client, status, grade, type, owner, due) and the quick links **Assigned to me**, **Overdue** and
   **Due soon**. To find one finding by text, see [Search](search.md).
4. Open a finding. Its page shows the evidence, **Why it matters** and **How to fix**, the owner and due date, and the
   full history.

Vulnerabilities say whether they are **confirmed** for the exact version or only **possible** (version unknown, or a
distribution build that may already carry the fix). Sentinel never guesses a version.

## Where findings come from

- **Scans** of the authorized addresses: open services, certificates, exposed admin pages and portals, and
  vulnerabilities in the versions found.
- **Website and email checks**, with each scan and once a day: HTTPS, headers, cookies, a short list of commonly
  exposed files (reported only when their content proves it, and never stored), CMS and library versions, and SPF,
  DMARC and DKIM by DNS. Results are on the client's **Website & email** page.
- **DNS checks**, once a day: zone transfers from the domain's own nameservers, and names pointing at a cloud service
  that no longer exists (subdomain takeover). Both are Fails.
- **Pen-test engagements**: the Fails and Warnings of an approved engagement (type **Pen test**). A retest that runs
  the same test on the same host and no longer finds the problem resolves them. See
  [Pen-test engagements](engagements.md#pen-test-findings).
- **Agents and NinjaOne** for internal devices, and **breach monitoring** for breached accounts: see
  [On-premises agents](agents.md) and [Integrations](integrations.md).

## Work on a group at once

The same problem on several targets of one client (one CVE on three servers, a missing header on two sites) is one
row, "on 3 targets". **One row per target** switches back to the plain list.

1. Open the row to see each target.
2. Act on all of them at once: assign, accept the risk or mark false positive (one note for all), reopen, or verify
   the fix on each. Admins can also set one due date.

Each target is still its own finding: it is checked, rechecked, resolved and audited on its own.

**Pick findings yourself:** in **One row per target**, tick the findings you want (or the box in the header for the
whole page), choose an action above the list (assign, accept risk / false positive / reopen, due date for admins,
verify fix) and click **Apply to selected**. Up to 500 at once; each is checked and audited on its own.

## Triage a finding

1. On the finding (or a group), choose a decision and write a note:
   - **Accept risk**: the client knows and accepts it. It stays accepted until the problem goes away.
   - **False positive**: it isn't really a problem. It reopens by itself if the evidence changes.
2. Save. To undo a decision, **Reopen** the finding.

You never resolve a finding by hand. A finding resolves when a check really sees the problem gone; a host that simply
wasn't scanned keeps its findings. A problem that comes back reopens the same finding, marked "Reappeared".

## Assign an owner and a due date

1. On the finding, pick an owner (an active technician or admin), or click **Assign to me**. The owner gets a
   notification and an email.
2. Every open finding has a due date: 7 days for known-exploited vulnerabilities, 14 for other Fails, 30 for
   Warnings. Admins change these days under **Administration → Settings → Due dates**, or set a different date on one
   finding with a reason.

Owners get one daily reminder of their overdue findings and those due within 2 days.

## Verify a fix

1. After fixing something, open the finding and click **Verify fix**.
2. Sentinel rechecks just that target: one address and port, or one domain's email records.
   - An **admin's** recheck runs straight away, even outside the scan window.
   - A **technician's** recheck waits for the client's scan window (it runs now if the window is open).
3. The result appears in the history, and you get a notification: Fixed, Still present, No longer reachable, Already
   resolved, or Not verified (with the reason).

## Good to know

- A recheck only runs while the target is in an active authorization and scanning isn't paused, at most once every 10
  minutes per finding.
- Accepted risks and false positives never cause alerts and don't count towards the risk score or report totals;
  reports list them in their own section with their notes.
- Every decision is in the finding's history and the audit log.
- With ITFlow tickets turned on, Fail findings also become tickets: see [Integrations](integrations.md#itflow).
