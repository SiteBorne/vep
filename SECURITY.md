# Security Policy

## Supported versions
Only the latest prerelease (`0.5.0b1` today; `0.6.0b1` once released) receives fixes. VEP is pre-release software; see the trust-model limits below before relying on it.

## Reporting a vulnerability — privately
**Please do not file public issues or pull requests for security problems.**

1. Use GitHub's private vulnerability reporting for this repository: <https://github.com/SiteBorne/vep/security/advisories/new> (*Security → Report a vulnerability*). A private advisory is visible only to maintainers. Private vulnerability reporting was confirmed **enabled** for this repository on 2026-10-19 (`gh api repos/SiteBorne/vep/private-vulnerability-reporting` returned `{"enabled":true}`).
2. No e-mail address is published for security reports; none is invented here. If the advisory form is unavailable, open a public issue that says only "security contact needed" (no details) and a maintainer will arrange a private channel.

Please include: affected version (`vep version --json`), a minimal reproduction, expected vs. actual behavior, and impact. We aim to acknowledge reports within a few working days; this is a volunteer project and no response-time guarantee is made.

## What counts as a vulnerability
Examples: a way to obtain a `CERTIFIED` candidate without passing the frozen required tests or authorization; a certificate that verifies against changed source, policy, objective or a different trust level; relabeling `TRUSTED_LOCAL` evidence as `ISOLATED_VERIFIED`; budget oversubscription; signing-key exposure through VEP's own behavior; path traversal in snapshot/CAS/context handling; container-plan option injection; leaked secrets in released artifacts.

## Known, documented limitations (not vulnerabilities)
* `TRUSTED_LOCAL` evaluation runs code with the operator's permissions and no isolation; evaluated code can read the signing key and forge parts of its own report. Only evaluate code you trust.
* Docker + gVisor isolation passed its verification matrix on one GitHub-hosted runner (see [docs/isolation/README.md](docs/isolation/README.md)); it is unverified on other hosts, not escape-tested and not externally reviewed, so VEP makes no claim about evaluating untrusted code.
* Provider token usage is supplied by the caller and is not authenticated.
See [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) and [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## Verifying releases
See [docs/RELEASE_PROVENANCE.md](docs/RELEASE_PROVENANCE.md).
