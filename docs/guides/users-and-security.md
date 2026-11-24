# Users and security

Sign in safely, add and manage the people who use Sentinel, and see who did what.

## Roles

| Role | Can |
|---|---|
| **Viewer** | See clients, findings, scans and reports. Changes nothing. |
| **Technician** | Also run scans and discovery, triage and assign findings, verify fixes, create reports and engagements, pause scanning. |
| **Admin** | Everything: users, clients and authorisations, settings, integrations, API tokens, approving engagements, the System page, resuming scanning. |

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

Add a second admin early: nobody gets locked out, and pen-test engagements need a second admin to approve them.

## Change a user, reset a password or two-factor

1. An admin opens the user under **Administration → Users**.
2. To change their **role** or whether the account is **active**, or to **reset their password** or **reset their
   two-factor authentication**, enter **your own password** to confirm.
3. The user is signed out everywhere straight away.

You can't change your own role or disable yourself, and the last active admin can't be removed.

## Create an API token

1. An admin goes to **Administration → API**.
2. Name the token, choose its clients, expiry (30 to 365 days), optional IP limits and permissions (read always;
   triage and queue scans only if ticked), and enter **your own password**.
3. Copy the token now: it is shown once. Details: [API](../api.md).

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
