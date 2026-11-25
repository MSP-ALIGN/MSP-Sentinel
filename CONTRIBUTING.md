# Contributing

Thanks for helping. A few rules keep MSP Sentinel safe and easy to maintain.

## Ground rules

- **Security problems:** never in a public issue. See [SECURITY.md](SECURITY.md).
- **No real client data** anywhere: code, tests, fixtures, screenshots, issues. Use made-up names, `*.example`
  domains and the documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
- **Tests never touch real hosts.** Every outside service has a mock on 127.0.0.1.
- **Stable over clever:** plain PHP, no framework, no Composer dependencies.

## Code

- Every PHP class and function has a docblock: what it does, what input is untrusted, and its security assumptions.
- Every route checks authentication and roles first; every POST is CSRF-checked by the kernel; everything in views
  is escaped with `e()`.
- Migrations are idempotent (they check before changing anything) and can run twice.
- Add an end-to-end test for each feature: `php tests/run.php`.

## Commits and pull requests

- Sign off every commit (Developer Certificate of Origin): `git commit -s`. This certifies that you wrote the change
  or have the right to submit it under the project's license (AGPL-3.0).
- Keep commits focused, with a message that says why. Never commit secrets, tokens or `config/config.php`.
- Releases: features bump `x.Y.0`, fixes `x.y.Z`; each release updates `VERSION`, the README "What's new",
  `CHANGELOG.md` and the in-app help.
