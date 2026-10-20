# Announcement drafts for the next beta (NOTHING HAS BEEN POSTED, and this candidate is NOT announcement-ready)

**Status.** `PUBLIC_ANNOUNCEMENT_READY = NO` for this work: it is committed locally on top of the published `v0.5.0b1`, not pushed, hosted CI and CodeQL have not run on it, no candidate version is set or released, and
Claude Code has not been observed using the server live ([PRODUCTION_QUALIFICATION_REPORT.md](PRODUCTION_QUALIFICATION_REPORT.md), [PROFILES.md](PROFILES.md)). The published `v0.5.0b1` announcement in [ANNOUNCEMENT.md](ANNOUNCEMENT.md) is unaffected.
These drafts are for your edit and approval; every figure carries a claim tag resolved by `scripts/check_claims.py`.

Positioning: **VEP lets an agent ask for verification, and lets a third party check the answer, without letting the agent grade itself.**

## 1. What changed since 0.5.0b1 (release-notes style)
* **Relying-party trust.** A portable bundle can no longer authorize itself. Verification takes a trust policy the *verifier* controls (issuer keys with rotation/revocation, accepted evaluators, required trust level, expected snapshot). Two implementations that share no code agree on all 194 [C:vec12] frozen vectors. The old self-contained bundle still verifies, but is labelled internal-consistency-only.
* **MCP server (stdio).** `vep-mcp` exposes 12 [C:mcptools] compact tools and read-only resources to any MCP client. The operator fixes the authority at start-up; an agent cannot grant itself more, cannot supply a verdict, and gets stable error codes and idempotent writes.
* **Claude Code.** `vep claude install` adds the server, a Skill with three workflows, a short CLAUDE.md block and a guard hook, with backup and conflict handling; `vep claude plugin` writes a plugin. *Live use inside Claude Code has not yet been recorded.*
* **A2A 1.0 agent.** `vep-a2a` maps an A2A task onto a durable VEP job (bearer auth, idempotent on message id, cancel cancels the job). Tested with the official client and a raw JSON-RPC client; loopback by default.
* **Exact-input evidence reuse.** If the source, policy, runner, evaluator and environment are identical to an already-evidenced candidate, VEP can issue a derived attestation naming the original proof instead of re-running the tests (about 14.1x [C:reuse200] faster than the full workflow on a 200-module synthetic project, 17.6x [C:reuse1000] on a 1,000-module one). It is not a certificate, and anything different makes it refuse.
* **Corrected cache semantics.** Build-cache identities now cover timeout, isolation and declared dependencies, and results say whether they were one run or two matching runs, never "deterministic".

## 2. Show HN — draft
**Title:** Show HN: VEP – let an agent request verification, let someone else check it (MCP + A2A)

> Follow-up to the 0.5.0b1 post. The thing I got wrong in the first version: the portable bundle carried its own keys and expectations, so anyone could mint a "valid" one. It's fixed (the verifier brings the trust policy) and I wrote a regression test that reproduces the original flaw first.
>
> New: a local MCP server and an A2A endpoint so agents can register a change and request a protected evaluation, but the operator, not the agent, decides what is allowed, and the agent can never supply a verdict. Evidence reuse only for byte-identical inputs.
>
> Limits up front: still not faster than running your tests, still runs your code unisolated by default, no external review, Claude Code live use not yet observed by me, A2A not qualified for the public internet. Repo has the failure records and the conformance vectors.

## 3. Short posts (X / LinkedIn) — drafts
* Agents can now ask VEP to verify a change over MCP or A2A; the operator sets the authority and the agent can't certify itself. Verification by a third party needs *their* trust policy, not the bundle's. Still early, local, Apache-2.0.
* What I got wrong first: a bundle that carried its own keys. What I did: reproduced it in a test, fixed it, and checked the fix in a second implementation (194 [C:vec12] vectors).

## 4. Before posting anything
* Push the work, let hosted CI and CodeQL run on that exact commit, set the next version (proposed `0.6.0b1`), tag and verify a release, then re-run `python scripts/launch_check.py` and `python scripts/profile_check.py --run --run-packaging` on that commit.
* Record a live Claude Code run (approve the project server; one authorized model run) or keep every Claude-specific sentence marked unverified.
* Keep the limits above in the first comment.
