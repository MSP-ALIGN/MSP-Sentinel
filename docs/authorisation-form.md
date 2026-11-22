# Sample: authorisation for external security scanning

*A starting point only. It is not legal advice: have it checked for your country and your contracts. Replace
everything in [brackets]. Keep the signed copy; record its reference in Sentinel's "authorised to scan" register.*

---

**Between:** [MSP name] ("the Provider") and [Client legal name] ("the Client").

**1. What the Client authorises.** The Client authorises the Provider to run automated, non-intrusive security
checks from the internet against the systems listed below, using MSP Sentinel, between [start date] and
[end date].

**2. In scope** (only these; anything not listed is out of scope):

| Type | Value | Notes |
|---|---|---|
| IP address | [203.0.113.10] | [Main office firewall] |
| IP range | [198.51.100.0/28] | [Hosting range] |
| Host name | [www.client.example] | [Website, hosted by: …] |

The Client confirms it owns these systems, or has written permission from their owner (for example a hosting
provider or cloud provider) to have them tested.

**3. What the checks do.** Discovery of public host names (DNS and certificate logs); TCP port scans at a low rate;
checks of TLS certificates and settings; one request to the first page of each web service; matching of reported
software versions against public vulnerability databases. **No** password guessing, exploitation, denial-of-service
or attempts to access data.

**4. When.** Scans run only in this window: [22:00–06:00], [time zone]. The Provider may pause any scan at any time.

**5. Contacts.** Client technical contact for incidents during scans: [name, phone, email]. Provider contact:
[name, phone, email]. Either side can stop scanning immediately by contacting the other.

**6. Results.** Findings are confidential, stored on the Provider's own server, and shared only with the Client
and the people named here: [names]. The Provider will keep them for [period] and then delete them.

**7. Limits.** These checks reduce risk but cannot find every problem. They are not a penetration test and not a
PCI ASV scan.

Signed for the Client: ______________________ Name / role: ______________ Date: ________

Signed for the Provider: ____________________ Name / role: ______________ Date: ________
