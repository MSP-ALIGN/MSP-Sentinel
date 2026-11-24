# Integrations

Connect Sentinel to ITFlow, MSP Align, NinjaOne and breach monitoring, and send its data to other tools. All of
these are set up by an **admin** under **Administration → Integrations**.

## Before you start

- Every key you enter is stored encrypted and never shown again. Leave a key field empty to keep the saved key.
- **Changing an integration's address clears its saved key.** Enter the key again for the new address.
- Use **Test connection** after saving to check each one.

## ITFlow

Keeps Sentinel's clients in step with ITFlow and puts security work on the ITFlow ticket board.

1. In ITFlow, add an agent named MSP Sentinel with a role that can read clients and work tickets (the Support module
   at write level), with access to all clients. Under **Admin → API Keys**, create a key for it (with an expiry date).
2. In Sentinel, under **ITFlow**, enter ITFlow's address and the key, tick **Sync clients from ITFlow**, save, then
   click **Test connection** and **Sync now**.
3. To open tickets, tick **Open ITFlow tickets for findings** and save. **Also open tickets for existing Fail
   findings** catches up on findings from before (20 at a time).

What happens next:

- **Clients**, every 15 minutes: new ITFlow clients are added (not scanned until you record their authorisation),
  renames are applied, and archiving in ITFlow archives in Sentinel. A client with the same name is linked, not
  duplicated. A client you archived or restored yourself in Sentinel is left as you set it.
- **Tickets**: Sentinel opens an internal ticket for each Fail and known-exploited finding (High, or Urgent when
  exploited), with what was found, why it matters, how to fix it and a link back. The same problem on other targets
  of the client joins the open ticket. Warnings go into one ticket per client a week, when there are new ones.
- **Both ways**, every 5 minutes: when Sentinel no longer sees a problem (or it is accepted or marked false positive),
  it adds a note and resolves the ticket. When a ticket is resolved or closed in ITFlow while the problem is open,
  Sentinel rechecks it: gone closes the finding; still there reopens the ticket (or opens a new one, since ITFlow
  can't reopen a closed ticket). Without a clear answer within 10 days, Sentinel stops waiting and says so on the
  finding.
- A ticket ITFlow refuses is retried later and the reason shows on the finding. Every change is in the audit log as
  "itflow-sync" and in the finding's history.

## MSP Align (compliance)

Shows each client's compliance frameworks from MSP Align, with what Sentinel found for each control. Sentinel only
reads; control statuses stay in MSP Align.

1. In MSP Align, under **Settings → API**, turn the API on and create a key named MSP Sentinel with
   **clients:read** and **compliance:read** only.
2. In Sentinel, under **MSP Align**, enter MSP Align's address and the key, tick **Show compliance from MSP Align**,
   save, and click **Test connection**.
3. On a client's **Compliance** page, link it to its MSP Align client.

Each control in an area Sentinel checks shows **Open problems** (with links), **No problems found** (checked in the
last 30 days; it supports the control but doesn't prove it) or **Not checked yet**. With ITFlow as MSP Align's PSA,
clients are linked automatically by their ITFlow ID.

## NinjaOne (devices)

Reads each client's computers from NinjaOne every 6 hours. It never changes anything in NinjaOne.

1. In NinjaOne, under **Administration → Apps → API → Client App IDs**, add a client app: platform **API Services
   (machine-to-machine)**, scope **Monitoring** only, grant type **Client credentials**. Copy the client ID and secret.
2. In Sentinel, under **NinjaOne**, enter the instance (the address you sign in at, for example `eu.ninjarmm.com`),
   the client ID and the secret. Tick **Sync linked clients**, save, and click **Test connection**.
3. On each client's **Devices** page, click **Link to an organisation** and pick its NinjaOne organisation.

What comes over: approved computers with their operating system, antivirus, disk encryption, missing and failed
Windows updates, and installed software (matched to known vulnerabilities). Anything NinjaOne doesn't report stays
unknown and is never a finding.

## Breach monitoring

Finds your clients' email addresses in known data breaches, once a week, using XposedOrNot.

1. Sign in to your XposedOrNot account and **verify each client domain** there (you prove you control it).
   "Verified domains" are the domains you have proved you own in that account.
2. In Sentinel, under **Breach monitoring**, paste the API key and tick **Check weekly**. **Check now** runs at most
   once an hour.

Each address becomes one finding for the client whose authorisation lists its domain: **Fail** if a breach happened
in the last 12 months, **Warning** if all its breaches are older. Passwords are never stored or shown. Addresses are
masked in titles and alerts (`j***@client.example`). Verified domains in no client's register are listed and ignored.

## Sign in with Microsoft

Your team signs in with their Microsoft 365 work account (Entra ID). Set-up steps and how accounts are matched:
[Users and security](users-and-security.md#sign-in-with-microsoft).

## API and outbound events

- Admins create API tokens under **Administration → API** (your own password is needed). **API reference** on that
  page lists every endpoint and offers the OpenAPI JSON to download.
- Under **Administration → API → Outbound events**, Sentinel can send signed events to an https address when findings
  change, a scan finishes or a report is created.
- Details, endpoints and how to check signatures: [API](../api.md).

## Good to know

- A failed sync or check changes nothing; the next run tries again.
- The Sentinel server needs outbound HTTPS to each service you connect.
- XposedOrNot's free key is meant for low-volume use; paid xonAPI+ keys work the same way.
