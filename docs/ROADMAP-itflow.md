# Roadmap: ITFlow, MSP Align and Sentinel working together

Agreed 2026-11-22. Each tool keeps one job:

| Tool | Job |
|---|---|
| **ITFlow** | System of record for clients, contacts and assets; alerts and ticketing (the alert board). |
| **MSP Align** | IT planning, compliance and the end-user dashboard. |
| **MSP Sentinel** | The security platform: external and internal scanning, NinjaOne inventory, real-time security auditing. |

The **ITFlow client ID** is the shared key: Sentinel stores it on each client, and MSP Align already stores it as
`psa_id`, so the three can be matched without anyone linking by hand.

## What ITFlow's API offers (checked in ITFlow's source, current version)

- `X-API-Key` header; keys are tied to an ITFlow user and follow that user's role and client access.
- Clients: read (paged with `limit`/`offset`, archived ones included with `client_archived_at`), create, update,
  archive, unarchive.
- Tickets: create (also from ticket templates), read, update, resolve, close, reopen; ticket replies.
- No webhooks: Sentinel polls ITFlow for changes (only the clients list and the tickets Sentinel opened).

## Phase 1: ITFlow connection and client sync (1.17.0, done)

- Administration → Integrations → ITFlow: address, API key (encrypted), Test connection, Sync now.
- Every 15 minutes Sentinel reads ITFlow's clients:
  - A new ITFlow client becomes a Sentinel client with its ITFlow ID. It is **not scanned** until someone records
    its written authorisation (the authorised-to-scan rule never changes).
  - An existing Sentinel client with the same name and no ITFlow ID is linked instead of duplicated.
  - A name change in ITFlow is applied in Sentinel.
  - Archived in ITFlow → archived in Sentinel (scanning stops, history kept); unarchived in ITFlow → restored, but
    only if it was the sync that archived it.
  - Demo clients are never touched.
- MSP Align is linked automatically: an unlinked Sentinel client whose ITFlow ID matches an MSP Align client's
  `psa_id` gets that MSP Align client.

## Phase 2: tickets from findings (1.18.0, done)

- Each Fail (and anything known-exploited) opens its own ITFlow ticket at once; Warnings are grouped into one weekly
  ticket per client.
- A ticket holds what was found, where, the evidence, why it matters, how to fix it step by step (the report
  guidance), the due date and a link to the finding in Sentinel.
- One ticket per problem (never duplicated); a finding that becomes known-exploited adds an internal note. A Warning
  that becomes a Fail gets its own ticket as a Fail.
- Tickets are internal (ITFlow doesn't email the client). Turning tickets on only covers findings from then on; an
  admin can open tickets for the existing Fails with one button. At most 20 tickets per run, every 5 minutes.

## Phase 3: two-way status (1.19.0, done)

- Fixed in Sentinel (a later check no longer sees it), or marked accepted risk / false positive → an internal note
  and the ITFlow ticket is resolved.
- Resolved or closed in ITFlow → Sentinel runs Verify fix at once (device findings: with the device's next data):
  gone → the finding closes; still there → a resolved ticket is reopened with what Sentinel still sees, and a closed
  one (ITFlow can't reopen closed tickets) is replaced by a new ticket that names the old one.
- A problem that comes back after its ticket was resolved reopens it (or replaces it).
- Sentinel polls the status of the tickets it opened every 5 minutes, up to 50 a run (ITFlow has no webhooks).
- From the 1.18.0 review: a refused ticket no longer stops the others (retried with a growing delay); a timed-out
  create is found again by its marker instead of opened twice; links go to ITFlow's technician view, never the
  client guest link.

## Not planned: Huntress and DNSFilter

Decided 2026-11-23: not for now. Their events (Huntress incidents, DNSFilter blocks) don't fit Sentinel: a block is
the tool already doing its job, the volume is high, and there is nothing to fix or recheck; both tools already alert
on what matters. If this is picked up again, the better fit is coverage checks: devices Sentinel knows (NinjaOne, the
agent) that have no Huntress agent or DNS protection, as findings that close themselves when the agent appears.
