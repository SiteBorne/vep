# VEP — technical submission for Anthropic engineering review (DRAFT, NOT SUBMITTED)

Nothing here states or implies that Anthropic has endorsed, reviewed, adopted or validated VEP. This is an independently inspectable description written for reviewers. It has not been sent to anyone; sending it is the maintainer's decision.
Source: https://github.com/SiteBorne/vep, branch `protocol/claude-native-0.6`, PR #2, **evaluated commit `3cf2371`** (hosted CI and CodeQL green on it; the later commit only adds the profile-results file). Baseline release: `v0.5.0b1` (unchanged). Proposed next version: `0.6.0b1` (not set, not tagged).

## 1. Technical executive summary
VEP (Verified Evolution Protocol) makes a software change carry signed, exact-source test evidence, and lets a third party check it offline with their own trust policy, so an agent can request verification but cannot grade itself.
It exposes this to agents through a local **MCP stdio server** (12 compact tools; the operator fixes the authority), a **Claude Code** installer (project `.mcp.json`, a three-workflow Skill, a guard hook, a plugin), an optional **Claude Agent SDK** options builder, and an authenticated **A2A 1.0** agent that maps tasks onto durable VEP jobs.
What was verified: two verifiers that share no code agree on all 194 frozen conformance vectors; the MCP server and A2A agent are exercised with the official SDK clients; hosted CI and CodeQL pass on the feature branch. What was **not** verified: live tool use inside Claude Code, a live Agent SDK run, any external review, hostile-code isolation.

## 2. What VEP is
Python reference implementation (Apache-2.0, beta) plus a language-independent specification ([CORE_PROTOCOL_SPEC](CORE_PROTOCOL_SPEC.md)). An objective freezes a content-addressed source snapshot and an acceptance policy (existing tests protected by digest). A protected runner rejects false greens (zero tests, all skipped, forged output, an installed copy of the package being tested instead of the candidate), signs Evidence, and a Certificate binds exactly one candidate/snapshot/policy/evidence. Execution is by default `TRUSTED_LOCAL`: it runs the project's own code unisolated on the operator's machine and is labelled so; a gated Docker+gVisor path exists (verified once on a hosted runner, not escape-tested).

## 3. Claude Code integration ([CLAUDE_INTEGRATION](CLAUDE_INTEGRATION.md))
`vep claude install` writes `.mcp.json` (authority chosen by the operator), `.claude/skills/vep/` (short `SKILL.md` that routes to three workflow files: register-and-verify, explain-failure, retrieve-evidence; progressive disclosure), a managed `CLAUDE.md` block, and a PreToolUse guard hook (defense in depth, not a boundary). Conflicts and backups are handled; files are written atomically with owner-only permissions; uninstall removes only what VEP wrote. `vep claude plugin` emits the same as a plugin (`claude plugin validate` passes on Claude Code 2.1.220). `vep.agent_sdk.vep_options` builds `ClaudeAgentOptions` offline with an allow/deny list derived from the authority.
**Unverified:** a live Claude Code session calling the tools or triggering the Skill; `${CLAUDE_PROJECT_DIR:-.}` expansion by Claude Code; an Agent SDK model run. `claude mcp get vep` finds the server and reports "Pending approval".

## 4. MCP ([MCP](MCP.md))
Local **stdio only** (official `mcp` SDK 2.3; revision `2026-07-28` negotiated in tests). 12 tools with input/output schemas and annotations; 7 resources; stable `VEP_E_*` error codes; idempotency keys; bounded, paginated outputs with handles for logs. No tool accepts an authority, trust level or verdict; evaluation needs both the `evaluate` authority and `--trusted-local-execution`. Remote HTTP is not offered. Tool definitions total about 7 KB (≈1.8k tokens by a bytes/4 estimate; no provider usage measured).

## 5. A2A ([A2A](A2A.md))
`a2a-sdk` 1.2.3, JSON-RPC binding, Agent Card with a bearer scheme and three skills. A task maps to a candidate and a durable job: `COMPLETED` only if VEP certified; `FAILED` with an explanation otherwise; `CancelTask` cancels the job; the message id is the idempotency key; token expiry and a task deadline are enforced. Tested against a real process with the official client and a raw JSON-RPC client (malformed, wrong/missing version, unauthorized, expired, duplicate, lost response, cancel). Not qualified for public exposure; push notifications not offered; no external inspector run.

## 6. Relationship to Anthropic Scion
VEP does **not** integrate with, depend on, or claim compatibility with Scion. Scion's published architectural principles were used only as design guidance for performance work: content-addressed immutable objects, change-proportional work, sparse materialization, cheap programmatic state queries, bounded caches. VEP already used content addressing; the new measurements ([PERFORMANCE_REPORT](PERFORMANCE_REPORT.md)) showed file-proportional staging/hashing is about 44% of a workflow at 1,000 modules. The one candidate optimization tried (parse caching) gained about 2.7% and was reverted under a preregistered threshold; hard-linking staged files and mtime-based hashing were rejected for soundness. No Scion code, RPC or data format is used.

## 7. Independent certificate verification and external trust policy
A bundle that carries its own keys proves only internal consistency. **Bundle format 2** carries only two envelopes and is accepted only under a **relying-party trust policy** (`VEP-TP1`: issuer keys with validity windows and `active`/`retired`/`compromised` status, accepted evaluators, required trust level, expected snapshot) plus the relying party's clock; a fixed check order determines the reason code ([spec §8](CORE_PROTOCOL_SPEC.md)). Python (`src/vep/conformance.py`, `trustpolicy.py`) and Node (`conformance/node/verify.mjs`, standard library only) agree on suites 1.0/1.1/1.2 = 119/160/194 vectors. Both were written by the same author; no outside review.

## 8. Security defects found and fixed (including in this PR)
1. **Self-authorizing bundles.** The original verifier took trusted keys and expectations from the bundle it was checking, so a self-consistent forged bundle verified. Reproduced first in `tests/test_trust_anchor_risk.py`, then fixed by format 2 + trust policies; v1 results are labelled `INTERNAL_CONSISTENCY_ONLY`.
2. **Build-cache identity** omitted timeout, isolation and declared dependencies, and a hit was described as determinism-verified. Identities are now `bact2-…`; results say `SINGLE_RUN` or `TWO_RUN_MATCH`; old entries are misses.
3. **Installer file handling (CodeQL alert on PR #2, `py/clear-text-storage-sensitive-data`).** The alert's data flow shows the flagged "secret" was the boolean `trusted_local` written to the install manifest, not a credential. The genuine risks it pointed at were fixed regardless: predictable PID-named temp files, files created with the process umask (a rewrite could widen the mode of a `.mcp.json` holding other servers' tokens), `copy2` backups, symlink following, and `status` echoing foreign server entries. Now: `mkstemp` exclusive 0600 temp, full-write loop, `fsync`, atomic rename, existing modes never widened, owner-only config/manifest/backups (dirs 0700), symlink/special-file refusal during planning, redacted status. 17 regression tests were written first (12 failed before the fix). After the fix the PR code-scanning check passes and the alert is "fixed"; it was not dismissed or suppressed. Honest note: the rescan closed it after the code path changed, so this is not a proof that the original report was a false positive beyond the data-flow evidence above.

## 9. Build-cache and evidence-reuse guarantees ([EVIDENCE_REUSE](EVIDENCE_REUSE.md))
A build-cache hit is never evidence of correctness or a certificate. **Exact-input reuse** issues a `DerivedAttestation` naming the original signed PASS evidence only when snapshot, frozen policy, runner digest, evaluator, execution environment and trust level are identical and the evidence is `TRUSTED_LOCAL`; it is not a certificate and changes no candidate status; any difference makes it refuse. Python and Node verify the derivation chain (34 vectors). No incremental test skipping exists.

## 10. Reproduce
```bash
git clone https://github.com/SiteBorne/vep && cd vep && git checkout protocol/claude-native-0.6
python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
python -m pytest -q                                   # full suite
scripts/conformance_check.sh                          # suites 1.0-1.2, Python and Node
python scripts/profile_check.py --run --run-packaging # readiness profiles for the checked-out commit
python -m build && pip install dist/*.whl && vep claude install --root /tmp/demo --dry-run
```
The tested quickstart is [QUICKSTART](QUICKSTART.md) (every `bash quickstart` block is executed against the installed wheel by the release gate).

## 11. Measured performance and limits
Synthetic project, one macOS host, medians: full protect-sign-certify workflow 320 ms (200 trivial tests) and 1,223 ms (1,000); VEP-owned file-proportional work about 44% at 1,000 modules; signing 0.4 ms; exact-input reuse 22.7 ms and 69.4 ms. MCP `vep_status` median 40.6 ms over stdio. Historical real-project results stay in [REAL_WORLD_RESULTS](REAL_WORLD_RESULTS.md) and [BENCHMARK_RESULTS_HOSTED_LINUX](BENCHMARK_RESULTS_HOSTED_LINUX.md): **VEP showed no speed advantage over running the tests directly.** Not measured: provider token usage, prompt-cache hits, Claude-side savings.

## 12. Threat model and security boundary
Trusted: the operator, the machine, the project's tests in `TRUSTED_LOCAL` mode, the relying party's trust policy and clock. Untrusted: the agent (it can call tools within operator authority only), bundle contents, A2A callers (bearer token). Not defended: hostile code under evaluation (it runs with the operator's permissions; the isolated path is not escape-tested), a malicious operator, a stolen A2A token, TLS/exposure of the A2A port, a compromised signing key before the relying party marks it compromised. The guard hook can be evaded by an agent with a shell. Details: [SECURITY_LIMITATIONS](SECURITY_LIMITATIONS.md), [THREAT_MODEL](THREAT_MODEL.md).

## 13. Known unsupported capabilities
MCP remote HTTP and OAuth; A2A push notifications, public-internet use, persistence of A2A task state across restarts; Windows; languages other than Python projects (`unittest`/`pytest`); reuse of isolated evidence; hostile-code execution; key distribution/transparency log; external security review.

## 14. Questions for Anthropic engineers
1. Is a project-scoped `.mcp.json` entry with an operator-fixed `--authority` the recommended pattern, or should authority be expressed through Claude Code permission rules and managed settings instead (or in addition)?
2. For a verification tool whose results must not be self-certified by the agent, are there MCP annotations or result fields that clients are expected to surface (beyond `readOnlyHint`/`destructiveHint`) to keep "verified" claims tied to a tool result?
3. How reliably do Skills with `allowed-tools` for MCP tools trigger from the description alone, and is there guidance or an eval harness (`claude plugin eval`) for measuring trigger rate for this kind of workflow Skill?
4. Does `${CLAUDE_PROJECT_DIR:-.}` expand inside `.mcp.json` `args` as documented for env expansion in all launch paths (CLI, desktop, SDK)?
5. Are PreToolUse hooks intended to be relied on as defense in depth for MCP-adjacent policies, and is there a supported way to mark a hook's decision as non-bypassable by `Bash`-mediated edits?
6. For A2A, is there a canonical way for a task that wraps a long-running job to expose a stable external job id and cancellation semantics beyond `CancelTask`, and any expectation about task persistence across server restarts?
7. Would a stable, documented trust-policy format for verifying agent-produced evidence be useful to align with, rather than VEP's `VEP-TP1`?

## 15. Evidence index
| Claim | Evidence |
|---|---|
| Spec and profiles | [CORE_PROTOCOL_SPEC](CORE_PROTOCOL_SPEC.md), [PROFILES](PROFILES.md), `docs/production-profiles.json` |
| Conformance 119/160/194, Python and Node | `conformance/vectors/suite-1.{0,1,2}.json`, `scripts/conformance_check.sh`, `tests/test_trust_policy.py`, `tests/test_evidence_reuse.py` |
| Trust-anchor defect reproduced and fixed | `tests/test_trust_anchor_risk.py` |
| Installer hardening | `tests/test_claude_code_security.py`, `src/vep/claude_code.py` |
| MCP | `tests/test_mcp_server.py`, `tests/test_agent_sdk.py`, `benchmarks/results/mcp-context-profile.json` |
| A2A | `tests/test_a2a_server.py`, `tests/test_fault_injection.py` |
| Fault injection map | [FAULT_INJECTION](FAULT_INJECTION.md) |
| Performance and rejected optimizations | [PERFORMANCE_REPORT](PERFORMANCE_REPORT.md), `benchmarks/results/stage-profile-*.json`, `benchmarks/results/paired-object-parse-cache.json` |
| Hosted CI / CodeQL on the PR | https://github.com/SiteBorne/vep/pull/2 (checks) |
| Qualification report | [PRODUCTION_QUALIFICATION_REPORT](PRODUCTION_QUALIFICATION_REPORT.md) |
| Compatibility matrix | [COMPATIBILITY_MATRIX](COMPATIBILITY_MATRIX.md) |
