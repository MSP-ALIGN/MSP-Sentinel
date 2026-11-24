# Reports

Create a branded report for a client, save it as a PDF, or export the findings as CSV.

## Before you start

- **Technicians and admins** create reports. Everyone can open and download them. Only admins delete reports, turn
  on monthly reports and set the branding.
- Set your branding once (admins): **Administration → Settings → Report branding**: company name, logo, accent colour,
  contact details and paper size.

## Create a report

1. Either open **Reports** in the menu and use **Create a report** (pick the **Client**), or open the client's own
   **Reports** page (under Manage).
2. Choose the **Report**:
   - **Executive summary (for management)**: an overall rating, the top 5 risks in plain English, totals and a trend.
   - **Technical findings (for IT)**: every open finding with its evidence and how to fix it, what was fixed in the
     period, and the scope and methods.
   - or both at once.
3. Choose the **Period**: last 30 days, last calendar month or last 90 days. "New" and "fixed" count what changed in
   that period; everything else shows the state when the report is created.
4. Click **Create**. The report opens.

## Save it as a PDF or CSV

1. On the report's page, click **Open report (print to PDF from the browser)**.
2. Use your browser's **Print**, then **Save as PDF**.
3. Or click **Download HTML** for a single file that works offline, or **Download findings (CSV)** for a spreadsheet.

## Turn on monthly reports

1. An admin opens the client's **Reports** page.
2. Tick the box to create both reports each month, enter up to 5 addresses at your MSP, and click **Save**.
3. After each calendar month ends (UTC), both reports for that month are created once and emailed to those addresses
   as attachments, for you to review before you forward them to the client.

## Good to know

- A report is **frozen**: it keeps the data and the branding of the moment it was made and never changes. Its SHA-256
  identifies the exact document, so you can always show what a client was sent.
- The report groups findings like the Findings list: each problem once, with all its targets.
- Accepted risks and false positives are listed in their own section with their notes; they don't count towards the
  totals or the rating.
- Monthly reports need email set up: see [Alerts](alerts.md). Reports over 5 MB are not attached; the email links to
  them instead. If creating them fails, admins get a notification and Sentinel retries hourly, up to 5 times.
- Every report states its limits: these are non-intrusive checks of the authorised targets, and not a PCI ASV scan.
- Pen-test reports and retest letters are made from an engagement: see [Pen-test engagements](engagements.md).
- The API can fetch reports and their CSV: see [API](../api.md).
