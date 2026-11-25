# Security policy

MSP Sentinel holds sensitive information about MSP clients' systems, so we take its own security seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's "Report a vulnerability" button (Security tab → Advisories) on this repository.
Please include:

- the affected version (shown in the page footer, or in the `VERSION` file)
- steps to reproduce, and the impact you expect
- whether you have shared it with anyone else

We aim to acknowledge reports within 5 working days, and we'll keep you updated until a fix is released. We're happy
to credit you in the release notes unless you'd rather stay anonymous.

## Scope

In scope: the MSP Sentinel code in this repository. Out of scope: vulnerabilities in third-party components (please
report those upstream, but tell us if Sentinel is affected), and problems that need an already-compromised server or
admin account.

Only test against your own installation. Never test against someone else's Sentinel installation or any system you
are not authorized to test.

## Release signing

Each release's `SHA256SUMS` is signed by the maintainers (`SHA256SUMS.asc`). The signing key's fingerprint is
published here with the first signed release:

- Release key fingerprint: *(to be added by the maintainers when 1.0.0 is signed)*

## Supported versions

Security fixes are released for the latest 1.x version. Upgrade to it (see `docs/upgrade.md`) to stay covered.
