# Sample: authorisation for security scanning

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
checks of TLS certificates and settings; the first page of each web service and a short fixed list of commonly
exposed files (such as `/.env` or `/.git/HEAD`), whose content is never kept; reading the domains' email security
records (SPF, DMARC, DKIM) from public DNS; matching of reported software versions against public vulnerability
databases. **No** password guessing, exploitation, denial-of-service or attempts to access data.

**4. When.** Scans run only in this window: [22:00–06:00], [time zone]. The Provider may pause any scan at any time.

**5. Contacts.** Client technical contact for incidents during scans: [name, phone, email]. Provider contact:
[name, phone, email]. Either side can stop scanning immediately by contacting the other.

**6. Results.** Findings are confidential, stored on the Provider's own server, and shared only with the Client
and the people named here: [names]. The Provider will keep them for [period] and then delete them.

**7. Limits.** These checks reduce risk but cannot find every problem. They are not a penetration test and not a
PCI ASV scan.

Signed for the Client: ______________________ Name / role: ______________ Date: ________

Signed for the Provider: ____________________ Name / role: ______________ Date: ________

---

## Annex: internal networks (only if an on-premises agent is installed)

**A1. Site and networks.** The Client authorises scanning of these internal networks at [site name, address] by a
small scanning device ("agent") installed by the Provider:

| Network | Description |
|---|---|
| [10.20.0.0/24] | [Office LAN] |
| [192.168.10.0/24] | [Servers] |

**A2. What the agent does.** It finds devices on these networks; scans their TCP ports at a low rate; checks TLS
certificates and the first page of web services; checks for risky protocols by reading the protocol's own answer
(SMBv1, SMB signing, Remote Desktop without Network Level Authentication, Telnet, FTP); [and sends one read request
with the well-known default SNMP community names "public" and "private" to find devices that still use them].
**No** logins, exploitation or attempts to access data. The agent only connects out to the Provider's server.

**A3. When.** Scheduled scans run only in the window in section 4; the Provider may start a scan outside it only
with a reason and will tell the Client technical contact.

Signed for the Client: ______________________ Name / role: ______________ Date: ________

