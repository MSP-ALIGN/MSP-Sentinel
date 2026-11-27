# Users and security

Sign in safely, add and manage the people who use Sentinel, and see who did what.

## Roles and permissions

Each user has one **role**, and a role is a set of **permissions**. Everyone can see clients, findings, scans,
devices, reports and engagements; permissions decide what a user may *change*, plus a few more sensitive views
(breached addresses in full, the signed engagement document, the audit log).

Three roles are built in and can't be changed:

| Role | Can |
|---|---|
| **Viewer** | See everything. Changes nothing. |
| **Technician** | Also run scans and discovery, triage, assign and verify findings, see breached addresses, create reports, run engagements, pause scanning. |
| **Admin** | Every permission: users and roles, clients and authorizations, settings, integrations, the API, agents, approving engagements, the System page, resuming scanning. |

### Make your own role

1. Go to **Administration → Roles** and click **New role**, or **Copy** a built-in role to start from it.
2. Name it (for example "Lead technician"), tick its permissions and enter your own password.
3. Give it to users on their account page (**Administration → Users**).

The **Who can do what** table on the Roles page lists every permission and which role holds it.

**Never more than you hold.** You can only tick permissions you hold yourself, give roles whose permissions you all
hold, and change, reset or disable users whose role you could give. So someone allowed to manage users can't make
anyone (or themselves, through a role) more powerful than they are, and can't take over a more powerful account.
You can't change your own role. Built-in roles never change. At least one active **Admin** always stays (only the
built-in Admin counts: it also gets every permission a later release adds). When a role changes, everyone with it is signed out so the change applies at once.

Some permissions come close to full control and are marked **Near full control** on the Roles page: managing agent
releases (signed releases run on every agent), the system, the API, integrations and users. Give them only to people
you would make Admin. API tokens never do more than the person who made them: a token can only triage or start scans
if its creator may, and loses those rights when its creator does.

## Limit a user to some clients

By default a user sees every client. To limit someone to the clients they look after:

1. Open the user under **Administration → Users**.
2. Under **Clients**, untick **All clients** and pick their clients. Enter your own password and save.

They then see nothing of other clients: those clients' pages and findings answer "not found", and lists, search, the
dashboard, reports, engagements, notifications and alert emails leave them out. Findings of a client can only be
given to someone who sees it. A client a limited user adds becomes one of theirs.

- You can only give clients you see yourself, and only manage users whose clients you all see.
- Org-wide pages and actions work only for users who see every client: the kill switch for all scanning, settings,
  integrations, the System page and the audit log. A limited user can still manage users, roles and API tokens
  within their own clients.
- One MSP Align client and one ITFlow client can each be linked to only one Sentinel client.
- When someone's clients are narrowed, their earlier notifications are cleared.
- Reports, alerts and emails show breached addresses masked to anyone without **See breached addresses** (in a
  report every email address is then masked, as reports are frozen copies).
- The last active Admin who sees every client can't be limited, demoted or disabled.

## Sign in and two-factor authentication

1. The first time you sign in, change the temporary password if asked.
2. Scan the QR code with an authenticator app on your phone and enter the 6-digit code. Two-factor authentication is
   required for every account.
3. Save the 10 **recovery codes** in your password manager. Each one signs you in once if you lose your phone.
4. To get new codes, open **My profile** and create new recovery codes (with your password); the old ones stop working.

Lost both your phone and your recovery codes? Ask an admin to reset your two-factor authentication.

## Time zone

Sentinel stores and compares every time in UTC, so daylight-saving changes never shift a scan. It shows times in
your time zone, each labeled (for example `2026-11-24 13:33 PST`):

- **The organization's time zone:** under **Administration → Settings → General** (admins). New clients start in it,
  also those added from ITFlow. If clients are still on UTC, the Settings page lists them with a button that moves
  them to your time zone; their scan window times stay the same numbers, now read in that time zone. It needs Manage
  settings and Edit clients, and the change is in the audit log.
- **Your own:** under **My profile → Time zone**, for someone who works elsewhere. Leave it empty to use the
  organization's.
- **Scan windows** always follow each client's own time zone (on the client's Edit page).
- **Reports** show times in their client's time zone.

## Sign in with Microsoft

Your team can sign in with their Microsoft 365 work account (Microsoft Entra ID). ITFlow itself can't act as a
sign-in provider, so Sentinel signs in against the same Microsoft tenant your team already uses.

**Set it up automatically** (1.63; an Admin who sees every client, with their own password):

1. Set Sentinel's public address in the config file (`app.public_url`, for example `https://sentinel.msp.example`).
2. Under **Administration → Integrations → Sign in with Microsoft**, enter your password and click **Connect to
   Microsoft 365**.
3. Sentinel shows a short code and a link to microsoft.com/devicelogin. Open the link (in any browser), enter the
   code and sign in as an Entra admin who can register apps and grant consent (Global Administrator, Application
   Administrator or Cloud Application Administrator). Accept the permissions: they are used only for this setup.
4. The Integrations page checks by itself every few seconds. Once you have signed in, Sentinel creates the app
   registration **MSP Sentinel (your address)** in your tenant: single tenant, Sentinel's redirect address, sign-in
   permissions only (openid, profile, email, granted for the organization), the optional claim **auth_time**, and a
   client secret valid for 24 months. It saves the IDs and the secret itself; the secret is never shown.
5. Link your own Microsoft account under **My profile** and test it, then tick **Show "Sign in with Microsoft"** and
   save. Recommended: in Entra Conditional Access, require MFA for this app.

Sentinel's server must be able to reach `login.microsoftonline.com` and `graph.microsoft.com`. Sign-in with a code
uses Microsoft's own app for Microsoft Graph command-line tools (the one Microsoft Graph PowerShell uses). If your
tenant blocks sign-in with a code through Conditional Access, set the app up by hand (below).

**Another tenant.** Once a tenant is saved, you must sign in to that same tenant, so signing in to the wrong one
(common for an MSP with several) changes nothing in it or in Sentinel. To really switch tenants, tick **Switch to
another Microsoft tenant** before connecting: every user's Microsoft link is cleared, and password sign-in is turned
back on for anyone who had it off, so nobody is locked out.

**Renewing the secret.** The card shows when the secret expires, and Sentinel reminds admins 30 days and 7 days
before (in-app and by email) and when it has expired, also while sign-in is switched off. Click **Connect to
Microsoft 365** again: Sentinel finds the app it made before, adds a new secret, saves it, and removes its older
secrets. Password sign-in keeps working throughout.

**Or set it up by hand:**

1. Set Sentinel's public address in the config file (`app.public_url`, for example `https://sentinel.msp.example`).
2. In the Microsoft Entra admin center, go to **App registrations → New registration**. Name it (e.g. MSP Sentinel),
   choose **Accounts in this organizational directory only**, and add the redirect URI (platform **Web**)
   `https://<your Sentinel address>/login/sso/callback`. The exact address is shown on the Integrations page.
3. Under **Certificates & secrets**, create a client secret and copy its **Value**. From **Overview**, copy the
   **Directory (tenant) ID** and **Application (client) ID**.
4. In Sentinel, go to **Administration → Integrations → Sign in with Microsoft**, enter the three values and tick
   **Show "Sign in with Microsoft"**. (A secret typed in by hand has no expiry reminder.)
5. Recommended: in Entra Conditional Access, require MFA for this app, and under the app registration's **Token
   configuration** add the optional claim **auth_time** (ID token). Sentinel skips its own code only when it can
   see that MFA happened in the last hour; without auth_time it always asks for its code (the server log says so).

**How it works:**

- **Each user links their own account once.** Sign in with your password and Sentinel's code, open **My profile**,
  enter your password and click **Link my Microsoft account**; Microsoft asks you to sign in to prove it is yours.
  Pick your own account: whoever owns the linked account can sign in as you. The linked account's name shows on My
  profile, and you get a notification when one is linked. An existing link must be unlinked before linking another. Only linked accounts
  can use Microsoft sign-in: an email address alone is never enough, guests from other directories never can, and no
  account is ever created. Roles and clients stay managed in Sentinel.
- **Two-factor.** By default Sentinel skips its own 6-digit code only when Microsoft's sign-in token confirms MFA
  within the last hour, and asks for it otherwise, as after a password. Microsoft often doesn't report MFA in that
  token, so the code is usually still asked. If Entra requires MFA for this app (Conditional Access or Security
  defaults), an Admin can tick **Microsoft sign-in replaces Sentinel's 2FA code** (1.64): every Microsoft sign-in
  then goes straight in, and is recorded in the audit log. Sentinel can't see how someone signed in at Microsoft, so
  only turn it on when Entra enforces MFA. Password sign-ins always need Sentinel's code. Users who only ever sign in
  with Microsoft never set up Sentinel's code; if you turn the switch off later, they are asked to set it up at their
  next sign-in (the Users page shows who hasn't).
- **Passwords stay as a fallback.** An admin can turn **Password sign-in allowed** off for a user (SSO only).
  At least one active Admin who sees every client always keeps it, so a Microsoft outage can't lock you out.
- **Unlink** a Microsoft account on the user's page (this also turns password sign-in back on) or under My profile;
  link it again from My profile. An admin's password or two-factor reset also removes the link.
- Changing the tenant clears every link.
- Every sign-in, link and failure is in the audit log.

## Add a user

1. An admin goes to **Administration → Users** and clicks **Add user**.
2. Enter the username, name, email address and role, and a temporary password.
3. Give the person the temporary password. At first sign-in they must change it and set up two-factor
   authentication.

Add a second admin early: nobody gets locked out, and pen-test engagements need a second person who may approve
them (unless an Admin turns two-person approval off under **Settings → Pen-test engagements**).

## Change a user, reset a password or two-factor

1. An admin opens the user under **Administration → Users**.
2. To change their **role** or whether the account is **active**, or to **reset their password** or **reset their
   two-factor authentication**, enter **your own password** to confirm.
3. The user is signed out everywhere straight away.

You can't change your own role or disable yourself, and the last active Admin can't be demoted or disabled. A user whose role has permissions you don't hold is shown read-only.

## Create an API token

1. Someone with **Manage the API** goes to **Administration → API**.
2. Name the token, choose its clients, expiry (30 to 365 days), optional IP limits and permissions (read always;
   triage and queue scans only if ticked), and enter **your own password**.
3. Copy the token now: it is shown once. Details: [API](../api.md).

A token never does more than the person who made it:

- **Permissions:** it can only triage findings or queue scans if you hold **Triage findings** or **Run scans and
  discovery**, and loses them when you do.
- **Clients:** it can only cover clients you see ("All clients" only if you see every client). If you later see fewer
  clients, the token is cut down to yours straight away.
- **Breached addresses:** they come back masked unless you may see them in full (findings, notes, and report HTML
  and CSV, where every email address is masked). A masked finding's `key` keeps a short hash; use `id` to match
  findings.
- **The token list:** you see and revoke only tokens whose clients you all see.
- **Outbound events:** they carry every client's changes, so only someone who sees every client can set them up.

## "Are you sure?" confirmations

Before an action that deletes or revokes something, sends something out, starts work or costs something, Sentinel
shows a dialog saying exactly what will happen. **Cancel** stops; **Yes, continue** goes ahead. For example:

- deleting a report, revoking an authorization, an agent or an API token;
- sending a test email, webhook message or event;
- starting a scan, an internal scan or a recheck (verify fix);
- approving, stopping or canceling an engagement;
- Update now, loading or removing demo data, saving retention periods.

## Audit log

1. Admins open **Administration → Audit log**.
2. It lists sign-ins and failed sign-ins, user and settings changes, authorizations, scans, triage and API writes,
   with the user and IP address. Type in the filter box to narrow it down (see [Search](search.md)).

Entries can't be edited or deleted from the web interface, and data retention never removes them.

## Good to know

- You are signed out after 30 minutes without activity, and after 12 hours in any case.
- After 5 wrong passwords, sign-in for that account pauses for 15 minutes. The audit log shows where the attempts came
  from.
- Wrong passwords in confirmations are limited too (5 in 15 minutes) and written to the audit log.
- Choose dark or light under **My profile → Appearance**.
- Hardening the server itself: see [Security](../security.md).
