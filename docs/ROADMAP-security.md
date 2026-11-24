# Roadmap: penetration-test and security suite

Agreed 2026-11-23. Sentinel answers "could an attacker get in?". MSP Align already covers whether a client's settings
and tools are in place (Microsoft 365 and Google Workspace security, Huntress and DNSFilter coverage, security
training), and ITFlow tracks domain and certificate expiry, so Sentinel doesn't repeat those.

## 1. Active Directory weaknesses (1.20.0, done)

Through the on-premises agent with a read-only domain account: AS-REP roasting, Kerberoasting, unconstrained
delegation, Domain Admins, stale admins, never-expiring admin passwords, krbtgt age, LAPS, LDAP signing, and
LLMNR/NetBIOS name poisoning (listen only). The password is sealed in the browser for the agent; Sentinel can never
read it. See [agent.md](agent.md#active-directory-checks-120).

## 2. Pen-test engagement mode (1.27.0, done)

Time-boxed, deeper tests the client authorises in writing and a second admin approves:

- all TCP ports;
- common UDP services;
- nmap's safe scripts;
- anonymous-access checks (FTP, NFS and, from 1.30, SMB file shares through an anonymous session).

They run externally from Sentinel and internally through the agents. Each engagement ends with a penetration test
report (summary, how the findings chain together, evidence) and, after fixes, a retest letter. Day-to-day scanning
stays gentle. See [engagements.md](engagements.md).

Default credentials (1.29.0, done): at most three published vendor defaults per service (FTP, HTTP Basic, MySQL/MariaDB,
PostgreSQL), each a different account and spaced, stopping at any lockout; plus databases open without a password.
Needs an explicit tick for the signed authorisation.

## 3. External attack surface additions (1.28.0, done)

Subdomain takeover (DNS names pointing at unclaimed cloud services) and open DNS zone transfers, asked only of each
authorised domain's own nameservers. Hypervisor, out-of-band (iDRAC, iLO, IPMI) and NAS admin pages are recognised,
with their ports in the default list. See the user guide, "Website and email security".

## 4. Breached credentials (1.33.0, done)

Addresses of the client's verified domains found in known data breaches, through XposedOrNot (free key; paid
xonAPI+ keys for commercial volume work the same way). A breach in the last 12 months is a Fail, older ones a Warning;
checked weekly. Have I Been Pwned has the widest coverage but needs a paid key; it can be added as a second provider.
