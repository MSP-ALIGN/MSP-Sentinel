# User guide

A short tour for technicians and viewers. The in-app **Help** page has more detail on every screen.

## Roles

| Role | Can |
|---|---|
| Viewer | See clients, findings, scans and reports |
| Technician | Also run discovery, queue and cancel scans, triage findings, create reports, pause scanning |
| Admin | Also manage users, clients and authorisations, settings, alerts, branding, API tokens and the System page; resume scanning; delete reports |

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
6. **Alerts**: new and returning Fail findings are announced straight away (bell, email, Teams or Slack); a summary
   follows each scan. Choose your emails on your profile.
7. **Reports**: create an Executive summary for management and a Technical findings report for IT (Reports card on
   the client page). Print to PDF from the browser. Reports are frozen: they never change after they are made.

## Grades

- **Fail:** fix now. For example: Remote Desktop or a database open to the internet, an expired certificate, an
  exposed firewall admin page, or a confirmed critical or known-exploited vulnerability.
- **Warning:** fix soon. For example: a certificate expiring within 14 days, old TLS versions, an exposed VPN portal,
  or a confirmed high-severity vulnerability.
- **Info:** shown on the client page, not a finding.

Vulnerabilities say whether they are **confirmed** for the exact version or only **possible** (version unknown, or a
distribution build that may already carry the fix). Sentinel never guesses a version.

## What Sentinel is not

It checks the outside of your clients' networks gently and honestly. It is not a full penetration test, it does
not test internal networks (that comes with the agent in version 2), and it is **not a PCI ASV scan**.
