# Pen-test engagements

Run a deeper, time-boxed test that the client signed for, and give them a penetration test report and, after the
fixes, a retest letter. Every test, rule and finding is described in the [engagement reference](../engagements.md).

## Before you start

- The client must have an active authorisation covering the targets (and, for internal tests, the site an internal
  authorisation and an agent on version 1.27.0 or later). An engagement never widens what may be tested.
- You need the client's **signed authorisation as a PDF** (at most 10 MB) naming the targets, tests, window and who
  may run them. The [authorisation form](../authorisation-form.md#annex-penetration-test-engagement) has an annex for it.
- You need **two admins**: a different admin approves each engagement.

## Create the engagement

1. Open the client, then **Pen-test engagements** → **New engagement** (technicians and admins).
2. Enter the name and the **window** (at most 14 days).
3. Choose the **tests**: all 65,535 TCP ports, common UDP services, nmap's safe service scripts, anonymous access
   (FTP, NFS, SMB shares, read only), and optionally vendor default passwords (a second tick confirms the signed
   form explicitly allows it).
4. Choose the **pace**: gentle (like day-to-day scans) or normal. All ports need the normal pace.
5. Enter the targets and any exclusions (IP addresses or ranges that must never be touched).
6. Attach the signed PDF, who signed it, their role and the date, tick the confirmation, and save.

## Get it approved

1. The admins get a notification. Those who may approve it also see a banner on the dashboard, and the
   **Engagements** page in the sidebar lists the engagements awaiting their approval first.
2. A **different admin** opens it, downloads the signed document, checks it matches the scope, and clicks
   **Approve** with their own password.
3. Nothing runs before approval, and nothing runs outside the window.

## Run the tests

1. Inside the window, open the engagement.
2. Click **Run external tests** (from Sentinel) and/or **Run internal tests** (through each site's agent).
3. Read the results on the engagement page: each finding with its evidence and how to fix it. They are evidence only
   and don't change the client's day-to-day findings.

## Stop it (kill switch)

1. Click **Stop engagement (kill switch)** and give a reason (technicians and admins).
2. It ends for good. Sentinel's tests stop within seconds; agents stop at their next check-in, within a minute.

Pausing all scanning, or the client, stops engagements too. Before approval, **Cancel engagement** withdraws it.

## Issue the report and the retest letter

1. When the tests are done, click **Issue penetration test report**. It is a frozen, branded report (summary, how the
   findings chain together, scope and authorisation, method, findings, systems tested, limitations). Download it as
   HTML (print to PDF) or the findings as CSV.
2. After the client has fixed things, create a new engagement and choose **This is a retest of** the earlier one. It
   needs its own signed PDF, window and approval.
3. Run its tests and click **Issue retest letter**. Each earlier finding is marked **fixed**, **still open** or
   **not retested**.

## Good to know

- **Who can approve:** any admin except the creator, and except an account the creator created, or whose password or
  two-factor authentication the creator reset, in the last 30 days.
- Never done: password guessing beyond the short vendor default list, SSH, Windows or Remote Desktop logins,
  exploits, denial of service, or anything that changes the systems tested.
- Every step is audited: created, approved, started, stopped, cancelled, report issued.
- Where a regulator or insurer requires an independent third-party test, an engagement doesn't replace it.
