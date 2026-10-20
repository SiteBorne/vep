# VEP wire-format conformance (suite 1.0)

Anyone can verify a VEP certificate without Python, a database or VEP's object model, using only SHA-256, Ed25519
and a JSON parser. This document is the normative description; `conformance/vectors/suite-1.0.json` is the frozen
test data (119 vectors); `conformance/node/verify.mjs` is a second implementation (Node standard library only) that
shares no code with the Python reference (`src/vep/conformance.py`).

Versions: suite `1.0`, canonical format `VEP-C1`, protocol `0.3`, bundle format `1`. A suite change that alters any
expected result requires a new suite version; `scripts/gen_conformance_vectors.py --check` fails if the committed
file drifts.

## 1. Canonical serialization (VEP-C1)
Input is UTF-8 without BOM. Parsing is strict: duplicate object keys, floats (anything with `.` or an exponent),
`NaN`/`Infinity`, trailing data, raw control characters in strings, lone surrogate escapes and invalid UTF-8 are
rejected. Integers must satisfy |n| <= 2^63-1 (`-0` is `0`). Depth: a scalar nested inside 65 containers is rejected
(64 is accepted). Output: object keys sorted by Unicode **code point** (not UTF-16 unit), no whitespace, strings in raw
UTF-8 with only `"`, `\`, `\b \f \n \r \t` and other C0 controls (as lowercase `\u00xx`) escaped.

## 2. Identity
`domain_hash(domain, data) = SHA-256("vep-id\0" || u32be(len(domain)) || domain || u64be(len(data)) || data)`.
Object bytes are `canonical({"type","schema_version","fields"})`. The id is `<prefix>-<hex>` where hex is
`domain_hash("vep.<Type>.v<schema_version>", canonical(fields))`. Prefixes: obj snap claim cand act evd cert obs rcpt
lease ctx pol exp. Id, digest and timestamp fields are ASCII-only and must match exactly (no trailing newline).

## 3. Envelope
`{"payloadType":"application/vnd.vep.object+json;v=1","payload":<base64>,"signatures":[{"keyid","sig"}]}` with exactly
those keys and exactly one signature. Base64 is strict (padded, no whitespace). The signature is Ed25519 over the DSSE
PAE `"DSSEv1 " len(type) " " type " " len(payload) " " payload` (lengths in decimal ASCII). `keyid` is the SHA-256 of
the raw 32-byte public key and must be in the verifier's trusted-key list. The payload must already be in canonical form.

## 4. Bundle verification order (decides the reported code)
Bundle `{"bundle_version":1,"trusted_keys","certificate_envelope","evidence_envelope","expect"}`; `expect.require_trust`
is `TRUSTED_LOCAL` or `ISOLATED_VERIFIED`; `objective_id`, `policy_id`, `snapshot_id` are optional expectations.
1. Shape: `MALFORMED_BUNDLE`, `UNSUPPORTED_BUNDLE_VERSION`; every trusted key's id must equal the hash of its key.
2. Open the certificate, then the evidence envelope: `MALFORMED_ENVELOPE`, `UNTRUSTED_KEY`, `SIGNATURE_INVALID`,
   `MALFORMED_PAYLOAD`, `WRONG_TYPE`, `UNSUPPORTED_SCHEMA_VERSION` (known: Evidence and Certificate v1, v2),
   `SCHEMA_INVALID` (field set, types, ids, trust/isolation cross-rules), `NONCANONICAL_PAYLOAD`.
3. `EVIDENCE_DIGEST_MISMATCH` (SHA-256 of the canonical evidence envelope must equal the certificate's digest field),
   `IDENTITY_MISMATCH`, `BINDING_MISMATCH` (candidate, objective, snapshot, policy equal in both).
4. Trust: evidence trust is its `trust_level` (v2) or derived from `isolation` (v1: only `NONE_TRUSTED_LOCAL` gives
   `TRUSTED_LOCAL`, else `UNVERIFIED`; never upgraded). v2 certificates must repeat the evidence trust level and
   evaluator id (`TRUST_BINDING_MISMATCH`). `UNVERIFIED`, or a level below `require_trust`: `TRUST_INSUFFICIENT`.
5. `EVIDENCE_NOT_PASSING` (verdict PASS, passed >= 1, skipped < run, failed = 0), `EVIDENCE_SNAPSHOT_MISMATCH`, then the
   caller's expectations: `OBJECTIVE_MISMATCH`, `POLICY_MISMATCH`, `SNAPSHOT_MISMATCH`.

## 5. What a valid bundle does and does not prove
It proves a trusted key signed evidence and a certificate that agree with each other, at the stated trust level, for
the stated snapshot id. It does **not** prove the snapshot's contents (compare the snapshot id with your own tree),
that the signing key is the right one (you choose the trusted keys), that tests were adequate, or anything about
isolation beyond the signed `trust_level`. Database-level checks (candidate/objective rows exist) are outside a bundle.

## 6. Running it
`scripts/conformance_check.sh` (exit 3 and "NOT RUN" if node is missing), `vep conformance export|verify|vectors`,
`node conformance/node/verify.mjs suite conformance/vectors/suite-1.0.json`.
Observed result in this repository: both verifiers agree on 119/119 vectors; a deliberately sabotaged verifier
(signature check removed) disagrees on 4. Both were written by the same author and share this document, so this shows
agreement with the published format, not independent review by another team.
