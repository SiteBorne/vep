# VEP Core Protocol Specification (normative)

Status: normative for the **Core Profile**, protocol version `0.3`, canonical format `VEP-C1`, conformance suites `1.0`–`1.2`.
Key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119. This document is independent of any programming language: an implementation
needs only SHA-256, Ed25519 and a strict JSON parser. The Python package in `src/vep/` is the *reference implementation*; where this text and
the code disagree, the frozen vectors in `conformance/vectors/` decide and the disagreement is a bug in one of them.
`docs/RFC-0001.md` is the original lifecycle description; this file supersedes it for everything that affects verification.

## 1. Scope and conformance classes

The Core Profile covers: canonical serialization, object identity, signed envelopes, the objects needed to verify a change
(Snapshot, ExecutionPolicy, Evidence, Certificate, DerivedAttestation), the candidate lifecycle invariants, and **verification by a relying
party that supplies its own trust policy**. It does not cover MCP, A2A, Claude integrations, isolation technology, budgets' storage layout, or
any agent behaviour; those are separate profiles (`docs/PROFILES.md`) and inherit nothing from this one.

* A **verifier** conforms if it produces the expected result for every vector of suites 1.0, 1.1 and 1.2 that applies to the operations it
  implements (`canonicalize`, `domain_hash`, `object_id`, `verify_bundle`, `verify_authorized`, `verify_derived`, `trust_policy_id`).
* An **issuer** (evaluator + certifier) conforms if everything it emits is accepted by a conforming verifier under a trust policy naming its key
  and evaluator, and it never emits objects violating Sections 4–7.

## 2. Serialization (VEP-C1)

Values are `null`, booleans, integers with |n| ≤ 2^63−1, strings, arrays and objects with string keys. Floats, `NaN`, `Infinity` and
duplicate keys MUST be rejected; decimals are strings. Canonical output is UTF-8 without BOM, keys sorted by Unicode **code point**, separators
`,` and `:`, no whitespace, no ASCII escaping (only `"`, `\`, and C0 controls are escaped). Nesting deeper than 64 MUST be rejected. A payload that
is not byte-identical to the canonical form of its own parse MUST be rejected (`NONCANONICAL_PAYLOAD`). Details and edge cases: `docs/CONFORMANCE.md` §1.

## 3. Identity

`domain_hash(domain, data) = SHA-256("vep-id\0" ‖ u32be(len(domain)) ‖ domain ‖ u64be(len(data)) ‖ data)`.
An object is `{"type","schema_version","fields"}`; its **id** is `<prefix>-<hex>` with `hex = domain_hash("vep.<Type>.v<schema_version>", canonical(fields))`.
Prefixes: `obj snap claim cand act evd cert obs rcpt lease ctx pol exp datt`. Ids, digests (64 lowercase hex) and timestamps
(`YYYY-MM-DDTHH:MM:SSZ`, UTC) are ASCII-only and MUST match exactly; a trailing newline is invalid. Unknown fields, missing required fields and
unsupported schema versions MUST be rejected (`SCHEMA_INVALID`, `UNSUPPORTED_SCHEMA_VERSION`); a body MUST NOT be reinterpreted under another version.
Optional fields are omitted when absent, never `null`.

## 4. Envelope and signatures

`{"payloadType":"application/vnd.vep.object+json;v=1","payload":<base64, padded, no whitespace>,"signatures":[{"keyid","sig"}]}` — exactly those members,
exactly one signature. `sig` is Ed25519 over `PAE = "DSSEv1 " len(payloadType) " " payloadType " " len(payload) " " payload` (decimal ASCII lengths, `payload`
the decoded bytes). `keyid` is the SHA-256 of the raw 32-byte public key. A verifier MUST resolve `keyid` only in keys it trusts (Section 8) and MUST check the
signature before interpreting the payload.

## 5. Objects needed for verification

Kinds: `id:T` an id of type T; `digest`; `ts`; `int>=0`; `enum[...]`; `str`; `json`. All listed fields are required unless marked optional.

**Evidence v2** (`evd`): `candidate_id:id:Candidate`, `objective_id`, `snapshot_id`, `policy_id`, `action_id:id:Action`, `runner_digest`, `argv:list[str]`, `exit_code:int`,
`verdict:enum[PASS,FAIL]`, `tests_discovered`, `tests_run`, `tests_passed`, `tests_failed`, `tests_skipped` (`int>=0`), `executed_ids_digest`, `stdout_digest`, `stderr_digest`,
`staged_tree_snapshot_id`, `isolation:enum[NONE_TRUSTED_LOCAL,DOCKER_GVISOR]`, `started_at`, `finished_at`, `budget_reservation:str`,
`trust_level:enum[TRUSTED_LOCAL,ISOLATED_VERIFIED,UNVERIFIED]`, `evaluator_id:str(<=256)`, `execution_environment:json`, optional `isolation_attestation_digest`.
Cross-rules: `TRUSTED_LOCAL` ⇒ `isolation=NONE_TRUSTED_LOCAL` and no attestation; `ISOLATED_VERIFIED` ⇒ `isolation=DOCKER_GVISOR` and an attestation digest;
`UNVERIFIED` ⇒ `verdict≠PASS`. **Evidence v1** has no trust fields; its trust level is `TRUSTED_LOCAL` iff `isolation=NONE_TRUSTED_LOCAL`, else `UNVERIFIED`, and is never upgraded.

**Certificate v2** (`cert`): `candidate_id`, `objective_id`, `snapshot_id`, `policy_id`, `evidence_id:id:Evidence`, `evidence_envelope_digest`, `issuer_key_id`, `issued_at`,
`trust_level:enum`, `evaluator_id`. **Certificate v1** lacks the last two.

**DerivedAttestation v1** (`datt`): `candidate_id`, `objective_id`, `snapshot_id`, `policy_id` (the *new* candidate), `original_evidence_id:id:Evidence`,
`original_evidence_envelope_digest`, `original_candidate_id`, `original_objective_id`, `reuse_mode:enum[EXACT_INPUT]`, `trust_level:enum[TRUSTED_LOCAL,ISOLATED_VERIFIED]`,
`evaluator_id`, `runner_digest`, `environment_digest` (SHA-256 of canonical `execution_environment` of the original), `issuer_key_id`, `issued_at`.

**Snapshot v1**: `manifest_version=1`, `entries`: list sorted by `path`, unique, each `{path, digest, type:"file", executable:bool}`. Paths are relative,
`/`-separated, without `.`, `..` or empty components, not absolute, no backslash/NUL/control characters, ≤1024 characters, and no two paths may collide after NFC+casefold.
Symlinks and special files MUST be rejected, never followed. The snapshot id is the identity of the source; `digest` is SHA-256 of the file bytes.

**ExecutionPolicy v1** names the evaluator (closed grammar), protected path patterns, required test files **by digest**, limits and audits, and MAY carry `required_trust`.
Its id freezes all of it: a different policy is a different id.

## 6. Candidate lifecycle invariants

States: `PROPOSED → POLICY_CHECKED → BUDGET_RESERVED → EVALUATING → EVIDENCE_READY → CERTIFIED`; any non-terminal state → `REJECTED`; `CERTIFIED` and `REJECTED` are terminal.
Transitions are compare-and-swap on a version counter and append to an immutable log. `EVIDENCE_READY` MUST NOT be reachable without PASS evidence bound to the
candidate's snapshot; `CERTIFIED` MUST NOT be reachable without a certificate bound to it. A candidate MUST NOT add, modify or remove protected paths, MUST retain every
required test byte-identical, and MUST NOT introduce modules that shadow runner or standard-library modules. Execution MUST NOT begin without a successful budget reservation;
an execution whose outcome is unknown MUST leave the reservation `UNCERTAIN` (funds held) and MUST NOT be retried automatically.

## 7. Evaluation and certification obligations

Evidence MAY be signed only if: the staged tree equals the candidate snapshot before and after the run; the signing key and VEP state were not touched; the report shows discovery and
execution (≥ the policy minimum passed, not all skipped, every required test file executed, internally consistent, exit status consistent). Failing-but-valid runs produce signed FAIL
evidence and reject the candidate. Non-isolated execution MUST be explicitly authorized and MUST be labelled `TRUSTED_LOCAL`; an implementation MUST NOT fall back from a requested
isolation to host execution and MUST NOT relabel evidence. A certificate MUST bind exactly one candidate/objective/snapshot/policy to exactly one evidence envelope and MUST NOT be
inherited by a modified source, a composition, or a different objective or policy. v1 evidence MUST NOT be newly certified.

## 8. Authorized verification (relying-party trust policy)

A bundle never carries the means to authorize itself. **Bundle format 2** contains only `certificate_envelope` and `evidence_envelope`. **Bundle format 1** embeds its signer keys and
expectations; it can establish only `INTERNAL_CONSISTENCY_ONLY` and a verifier MUST report that assurance, never "authorized".

**Trust policy `VEP-TP1`** (supplied by the relying party, never by the bundle) is an object with exactly: `trust_policy_version:1`, `name:str`, `issuers`,
`authorized_evaluators:list[str]`, `require_trust:enum[TRUSTED_LOCAL,ISOLATED_VERIFIED]`, `permitted_evidence_versions`, `permitted_certificate_versions` (non-empty subsets of {1,2}),
`allow_legacy_evidence:bool`, `expect:{snapshot_id (required), objective_id?, policy_id?}`. Each issuer is `{key_id, public_key_hex, valid_from, valid_until|null, status, status_effective_at|null}` with
`status ∈ {active, retired, compromised}`, `key_id = SHA-256(raw key)`, a retired key requiring `status_effective_at`, no duplicate issuers. A policy with no expected `snapshot_id` MUST be refused
(`SUBJECT_UNSPECIFIED`). The policy id is `"tp-" + domain_hash("vep.TrustPolicy.v1", canonical(policy))`. The verifier is also given `now` by the relying party (a UTC timestamp); it MUST NOT read a clock itself.

**Key status** is evaluated at the time the signed object *claims* (certificate `issued_at`, evidence `finished_at`): `compromised` ⇒ always `REVOKED_KEY` (its holder controls the timestamps);
`retired` ⇒ `REVOKED_KEY` if the time ≥ `status_effective_at`; time < `valid_from` ⇒ `KEY_NOT_YET_VALID`; time ≥ `valid_until` ⇒ `KEY_EXPIRED`; time > `now` ⇒ `ISSUED_IN_FUTURE`.
Rotation is expressed by listing the new key (`valid_from` = rotation time) and marking the old key `retired`.

**Evaluator match**: `evaluator_id` equals an `authorized_evaluators` entry exactly, or the entry ends with `*` and `evaluator_id` starts with the part before it.

**Check order** (the first failing check decides the code): 1. `now` format; 2. policy validity (`MALFORMED_TRUST_POLICY`, `SUBJECT_UNSPECIFIED`); 3. bundle shape and version
(`MALFORMED_BUNDLE`, `UNSUPPORTED_BUNDLE_VERSION`); 4. open the certificate then the evidence using **only the policy's issuers** (`MALFORMED_ENVELOPE`, `UNAUTHORIZED_ISSUER` for a key not in the policy,
`SIGNATURE_INVALID`, `MALFORMED_PAYLOAD`, `WRONG_TYPE`, `UNSUPPORTED_SCHEMA_VERSION`, `SCHEMA_INVALID`, `NONCANONICAL_PAYLOAD`); 5. `ISSUER_KEY_MISMATCH` (the certificate's `issuer_key_id` must equal the
signing key id); 6. key status for both signatures; 7. `CERTIFICATE_VERSION_NOT_PERMITTED`, `EVIDENCE_VERSION_NOT_PERMITTED`; 8. bindings: `EVIDENCE_DIGEST_MISMATCH` (SHA-256 of the canonical evidence
envelope = certificate digest field), `IDENTITY_MISMATCH`, `BINDING_MISMATCH` (candidate, objective, snapshot, policy equal), `TRUST_BINDING_MISMATCH` (v2 certificate repeats evidence trust level
and evaluator), `TRUST_INSUFFICIENT` (evidence `UNVERIFIED`), `EVIDENCE_NOT_PASSING` (verdict PASS, passed ≥ 1, skipped < run, failed = 0), `EVIDENCE_SNAPSHOT_MISMATCH` (`staged_tree_snapshot_id` = certified
snapshot); 9. `LEGACY_EVIDENCE_NOT_PERMITTED` (v1 evidence without `allow_legacy_evidence`) or `EVALUATOR_NOT_AUTHORIZED`; 10. `TRUST_INSUFFICIENT` (below `require_trust`); 11. expectations `OBJECTIVE_MISMATCH`,
`POLICY_MISMATCH`, `SNAPSHOT_MISMATCH`. Success reports `assurance = AUTHORIZED`, the policy id, the issuer key id, the trust level and the snapshot id.

What success proves: a key *you* authorized signed evidence and a certificate that agree, from an evaluator *you* accept, at or above the trust level *you* require, for the source snapshot *you* expect.
It does not prove the snapshot's contents (compare the id with your own tree), test adequacy, or isolation beyond the signed trust level.

## 9. Derived attestations (exact-input evidence reuse)

A **DerivedAttestation** says: candidate X has the same source snapshot, frozen policy, runner, evaluator, execution environment and trust level as candidate Y, whose signed PASS evidence E exists. It
names E by id and envelope digest; E is never copied, re-signed or moved. It is not a certificate and does not change any candidate's status. An issuer MUST issue one only when all of these hold at issuance:
E is PASS, schema v2, signature-valid; E's snapshot, `staged_tree_snapshot_id` and policy equal X's; E's `runner_digest`, `evaluator_id` and `execution_environment` equal the issuer's current ones; E's trust
level is `TRUSTED_LOCAL` (reuse of isolated evidence is not defined); the policy does not require `ISOLATED_VERIFIED`; X ≠ Y. No similarity, dependency analysis or partial-source inference is permitted.

**Bundle format 3** = `{bundle_version:3, attestation_envelope, evidence_envelope}`. Verification (`verify_derived`) uses the same trust policy and the same steps 1–7 and 9–11 of Section 8 with the attestation in the
certificate's place, and replaces step 8 by, in order: `EVIDENCE_DIGEST_MISMATCH`, `IDENTITY_MISMATCH`, `LEGACY_EVIDENCE_NOT_REUSABLE`, `DERIVATION_ORIGIN_MISMATCH` (evidence candidate/objective equal the claimed
originals), `NOT_DERIVED` (attestation candidate ≠ evidence candidate), `BINDING_MISMATCH` (snapshot, policy), `EVIDENCE_SNAPSHOT_MISMATCH`, `TRUST_BINDING_MISMATCH` (trust level and evaluator),
`RUNNER_BINDING_MISMATCH`, `ENVIRONMENT_BINDING_MISMATCH`, `EVIDENCE_NOT_PASSING`. Success reports `assurance = AUTHORIZED_DERIVED` and the derivation chain `[attestation id, evidence id, original candidate id]`.
A relying party that wants a certificate for X, not a derived claim, MUST evaluate X.

## 10. Compatibility, revocation and failure semantics

* Five independent version axes (package, protocol, canonical format, per-type schema, database schema; `docs/COMPATIBILITY.md`). Identity-affecting changes require a new schema version or protocol version.
* A verifier MUST fail closed: any malformed, unknown, ambiguous or unverifiable input yields a rejection with one of the codes above, never a partial success and never a guess.
* Revocation is the relying party's decision, expressed in its trust policy and evaluated at the issuer-claimed time; a verifier MUST NOT consult the bundle for revocation status.
* New reason codes MAY be added in a new suite version; the meaning of an existing code MUST NOT change.
* Time is supplied by the caller (`now`); no verifier reads a clock for trust decisions.

## 11. Core Profile requirements (machine-checked by `scripts/profile_check.py`)

C1 the specification is present and versioned; C2 suites 1.0, 1.1 and 1.2 regenerate byte-identically and carry their predecessors verbatim; C3 the Python reference agrees with every vector;
C4 an independent implementation that shares no code with it (Node, standard library only) agrees with every vector; C5 every authorized-verification reason code and every derived-verification code is
exercised by a vector; C6 the self-authorizing-bundle defect has a regression test showing a v1 bundle never reports `AUTHORIZED`; C7 the fault-injection map is complete and its tests exist.

## 12. Non-goals and limits

No claim is made about the safety of executing hostile code, about the adequacy of tests, about confidentiality, or about transparency-log style non-equivocation. Both implementations were written by the
same author from this text; agreement with the published format is shown, independent review by another team is not.
