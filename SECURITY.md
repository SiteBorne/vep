# Security Policy

## Supported versions
Only the latest `0.4.x` prerelease receives fixes. VEP is alpha software; see the trust-model limits below before relying on it.

## Reporting a vulnerability — privately
**Please do not file public issues or pull requests for security problems.**

1. Use GitHub's private vulnerability reporting for this repository: *Security → Report a vulnerability* (a private advisory visible only to maintainers).
2. If that option is not available, contact the maintainers through the private channel listed in the repository's *About* section.

> **CONFIGURATION REQUIRED BEFORE PUBLICATION:** the maintainers must (a) enable *Private vulnerability reporting* in the repository settings and (b) replace this notice with a monitored contact address if they want an email path. No address is invented here.

Please include: affected version (`vep version --json`), a minimal reproduction, expected vs. actual behavior, and impact. We aim to acknowledge reports within a few working days; this is a volunteer project and no response-time guarantee is made.

## What counts as a vulnerability
Examples: a way to obtain a `CERTIFIED` candidate without passing the frozen required tests or authorization; a certificate that verifies against changed source, policy, objective or a different trust level; relabeling `TRUSTED_LOCAL` evidence as `ISOLATED_VERIFIED`; budget oversubscription; signing-key exposure through VEP's own behavior; path traversal in snapshot/CAS/context handling; container-plan option injection; leaked secrets in released artifacts.

## Known, documented limitations (not vulnerabilities)
* `TRUSTED_LOCAL` evaluation runs code with the operator's permissions and no isolation; evaluated code can read the signing key and forge parts of its own report. Only evaluate code you trust.
* Hostile-code isolation is **unverified** on the development host; VEP makes no claim about evaluating untrusted code.
* Provider token usage is supplied by the caller and is not authenticated.
See [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) and [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## Verifying releases
See [docs/RELEASE_PROVENANCE.md](docs/RELEASE_PROVENANCE.md).
