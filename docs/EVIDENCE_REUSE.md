# Exact-input evidence reuse

Four things are kept apart:
1. **Build-cache hit** (`vep build`): a cached output of a declared action. Never evidence of correctness, never a certificate, and described as `SINGLE_RUN` or `TWO_RUN_MATCH`, not as proof of determinism.
2. **Signed original evidence**: what the protected evaluator signed for one candidate. It is never copied, re-signed, or attached to another candidate.
3. **Derived attestation** (`DerivedAttestation`, id prefix `datt`): a new signed claim that candidate X has *exactly* the source snapshot, frozen policy, runner digest, evaluator id, execution environment and trust level of candidate Y, whose signed PASS evidence E it names by id and envelope digest.
4. **Certificate**: only a protected evaluation of the candidate itself produces one. A derived attestation is **not** a certificate and leaves the candidate's status unchanged.

## Correctness conditions (all must hold at issuance; `reuse.find_original`)
E is PASS, schema v2 and signature-valid; E's snapshot, staged tree and policy equal X's; E's `runner_digest`, `evaluator_id` and `execution_environment` equal the current ones; E's trust level is `TRUSTED_LOCAL`
(reuse of isolated evidence is not defined) and the policy does not require `ISOLATED_VERIFIED`; X is a different candidate than Y. Source, policy, runner, evaluator or environment changes therefore make reuse **refuse**
(`NO_REUSABLE_EVIDENCE` with the reasons) and the candidate must be evaluated. Nothing is inferred from dependency graphs, and no tests are skipped inside a run: incremental test selection is out of scope and unsound for certification.

## Verification
`vep reuse derive|export --candidate ID`, then `vep reuse verify --bundle FILE --trust-policy POLICY [--now T]`. A relying party uses the same `VEP-TP1` trust policy as for certificates. The chain
(attestation → original evidence → authorized issuers/evaluator/trust/expectations) is checked by the Python reference and independently by `conformance/node/verify.mjs derived`; suite 1.2 has 34 derived-verification vectors
on which both agree (194/194 in total). Normative text: [CORE_PROTOCOL_SPEC](CORE_PROTOCOL_SPEC.md) §9. The MCP tool is `vep_reuse_evidence` (authority `evaluate`; it executes nothing).

## Cost (measured, synthetic project, this host)
Deriving, exporting and verifying a derived attestation took a median 22.7 ms on a synthetic project with 200 trivial test modules and 69.4 ms with 1,000, against 320.3 ms and 1,222.5 ms for the full
protected evaluation-to-certificate workflow it replaces (7 and 5 measured runs after one warm-up; `benchmarks/results/stage-profile-200.json`, `stage-profile-1000.json`, produced by `benchmarks/profile_stages.py`). The test modules are trivial; a real suite costs its own test time, which reuse avoids entirely for an identical tree.
This is a measurement of *verified unchanged-input reuse*; it says nothing about incremental test skipping, which is deliberately not implemented. It is also not a claim that VEP made the code better.
