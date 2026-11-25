# Alerts

Get told about new problems by email, in Teams or Slack, and in the app, and remind owners of findings that are due.

## Before you start

- Admins set up email and the webhook. Each user chooses their own emails.
- Set `app.public_url` in `config/config.php` (for example `https://sentinel.msp.example`) so messages can link back
  to Sentinel. See [Configuration](../configuration.md).

## Set up email (admins)

1. Go to **Administration → Settings → Alerts**.
2. Tick **Send email alerts**. Enter the mail server, port and connection (STARTTLS, usually port 587, or TLS, usually
   465; a plain connection only to a relay on this server), the user name and password if needed, and the sender
   address.
3. Optionally add up to 5 **team addresses**: they get every immediate alert and every scan summary.
4. Click **Save alert settings**, then **Send test email to me**.

## Set up Teams or Slack (admins)

1. On the same page, tick **Post alerts to a webhook**.
2. Paste the webhook address (it must be https and on the public internet) and choose the format: Microsoft Teams
   (Workflows), Slack or generic JSON.
3. Save, then click **Send test webhook message**.

Only alert summaries and links are sent, never scan details.

## Choose your own emails

1. Open **My profile** (from your name at the top right).
2. Under **Email alerts**, choose: new Fail findings immediately, a summary after each scan, both, or no emails
   (in-app notifications only). Save.

## Read notifications in the app

1. Every alert appears under the bell in the header.
2. Open **Notifications** to see the latest ones. Click **Mark all as read** when you have seen them; just opening the
   page doesn't mark them read.

## What you are told about

- **Straight away:** a Fail finding that is new or comes back; a finding assigned to you; a pen-test engagement
  awaiting approval (admins); a failed scan or threat feed (admins).
- **After each scan:** a summary of what changed.
- **Daily fix reminders:** once a day after 07:00 UTC, each owner gets one note and one email listing their overdue
  findings and those due within 2 days. The team addresses and the webhook get a summary of overdue findings per
  client, including unassigned ones.

## Good to know

- Accepted risks and false positives never cause alerts.
- **No floods.** One run sends at most 60 immediate Fail alerts across all clients (for example after new
  vulnerability data), then one "alerts paused" notice; the rest are on the Findings page and in each client's
  summary.
- The SMTP password and the webhook address are stored encrypted and never shown again. Leave the field empty to keep
  the saved value, or tick **Remove the saved password** / **Remove the saved address**.
- **Changing the mail server clears the saved SMTP password.** Enter it again for the new server.
- Messages that fail are retried up to 3 times. **Recent deliveries** on the settings page shows the last results and
  any error.
- Demo clients never send alerts.
