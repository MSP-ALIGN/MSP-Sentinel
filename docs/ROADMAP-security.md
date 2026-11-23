# Roadmap: penetration-test and security suite

Agreed 2026-11-23. Sentinel answers "could an attacker get in?". MSP Align already covers whether a client's settings
and tools are in place (Microsoft 365 and Google Workspace security, Huntress and DNSFilter coverage, security
training), and ITFlow tracks domain and certificate expiry, so Sentinel doesn't repeat those.

## 1. Active Directory weaknesses (1.20.0, done)

Through the on-premises agent with a read-only domain account: AS-REP roasting, Kerberoasting, unconstrained
delegation, Domain Admins, stale admins, never-expiring admin passwords, krbtgt age, LAPS, LDAP signing, and
LLMNR/NetBIOS name poisoning (listen only). The password is sealed in the browser for the agent; Sentinel can never
read it. See [agent.md](agent.md#active-directory-checks-120).

## 2. Pen-test engagement mode (next)

A time-boxed, deeper scan an admin explicitly authorises in the client's written authorisation: all TCP ports, the
common UDP ports and nmap's safe service scripts, ending with a pen-test style report (executive summary, how the
findings chain together, retest results). Day-to-day scanning stays gentle.

## 3. External attack surface additions

Subdomain takeover (DNS names pointing at unclaimed cloud services), open DNS zone transfers, and exposed management
interfaces (firewall, switch and hypervisor admin pages).

## 4. Breached credentials

Client email addresses found in known breaches, through a breach-lookup service with a paid API key.
