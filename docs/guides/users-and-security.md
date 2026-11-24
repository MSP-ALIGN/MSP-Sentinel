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
| **Admin** | Every permission: users and roles, clients and authorisations, settings, integrations, the API, agents, approving engagements, the System page, resuming scanning. |

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
- When someone's clients are narrowed to a list, their earlier notifications are cleared.
- The last active Admin who sees every client can't be limited, demoted or disabled.

## Sign in and two-factor authentication

1. The first time you sign in, change the temporary password if asked.
2. Scan the QR code with an authenticator app on your phone and enter the 6-digit code. Two-factor authentication is
   required for every account.
3. Save the 10 **recovery codes** in your password manager. Each one signs you in once if you lose your phone.
4. To get new codes, open **My profile** and create new recovery codes (with your password); the old ones stop working.

Lost both your phone and your recovery codes? Ask an admin to reset your two-factor authentication.

## Add a user

1. An admin goes to **Administration → Users** and clicks **Add user**.
2. Enter the username, name, email address and role, and a temporary password.
3. Give the person the temporary password. At first sign-in they must change it and set up two-factor
   authentication.

Add a second admin early: nobody gets locked out, and pen-test engagements need a second person who may approve
them.

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
- **Breached addresses:** they come back masked unless you may see them in full.
- **The token list:** you see and revoke only tokens whose clients you all see.
- **Outbound events:** they carry every client's changes, so only someone who sees every client can set them up.

## "Are you sure?" confirmations

Before an action that deletes or revokes something, sends something out, starts work or costs something, Sentinel
shows a dialog saying exactly what will happen. **Cancel** stops; **Yes, continue** goes ahead. For example:

- deleting a report, revoking an authorisation, an agent or an API token;
- sending a test email, webhook message or event;
- starting a scan, an internal scan or a recheck (verify fix);
- approving, stopping or cancelling an engagement;
- Update now, loading or removing demo data, saving retention periods.

## Audit log

1. Admins open **Administration → Audit log**.
2. It lists sign-ins and failed sign-ins, user and settings changes, authorisations, scans, triage and API writes,
   with the user and IP address. Type in the filter box to narrow it down (see [Search](search.md)).

Entries can't be edited or deleted from the web interface, and data retention never removes them.

## Good to know

- You are signed out after 30 minutes without activity, and after 12 hours in any case.
- After 5 wrong passwords, sign-in for that account pauses for 15 minutes. The audit log shows where the attempts came
  from.
- Wrong passwords in confirmations are limited too (5 in 15 minutes) and written to the audit log.
- Choose dark or light under **My profile → Appearance**.
- Hardening the server itself: see [Security](../security.md).
