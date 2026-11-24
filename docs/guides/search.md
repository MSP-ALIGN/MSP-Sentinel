# Search

Find a client, a finding, a host, a device or a help topic quickly.

## Search everything from the top bar

1. Type in the search box at the top of every page (on a phone, tap the magnifying glass).
2. Enter at least 2 characters (up to 100) and press Enter.
3. The results are grouped:
   - **Clients**, by name (archived clients are marked);
   - **Findings**, by title, target or CVE ID, for example `CVE-2024-` or `vpn.client.example`;
   - **Scanned hosts**, by address or host name, for example `203.0.113.10`;
   - **Devices** (internal), by name, DNS name or address, for example `10.20.0.15`;
   - **Engagements**, by name;
   - **Help** topics, with a short snippet. The link opens Help already filtered to your words.
4. Click a result to open it.

## Filter the findings list

1. Open **Findings**.
2. Type in **Contains** to match a title, target or CVE, then click **Filter**.
3. Combine it with the other filters: client, status, grade, type, owner and due.

The filters stay in the page address, so you can bookmark or share a filtered list. On a phone, the filters fold
away behind a **Filters** button.

## Filter the audit log

1. Admins open **Administration → Audit log**.
2. Type in the filter box: it matches the action, the user, the target type or the details, for example
   `authorisation` or a username.
3. Click **Filter**. **Clear** shows everything again.

## Filter a list as you type

These lists have a filter box that hides non-matching rows as you type:

- **Clients** (by name);
- **Users**;
- a client's **Devices** (by name, address or problem);
- **Engagements** (by name or client);
- **Help** (it shows how many topics match).

## Good to know

- Search matches your text literally, anywhere in the field, ignoring case. `%` and `_` are ordinary characters,
  not wildcards.
- Each group shows at most 25 results (10 for Help). Make the text longer to narrow it down.
- Findings, hosts and devices of archived clients are left out of the search.
- Breached email addresses are found only by their masked form (`j***@client.example`); the full address stays in the
  finding's details.
- The instant filter boxes only hide rows already on the page. Nothing is sent to the server.
