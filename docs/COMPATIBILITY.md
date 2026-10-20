# Compatibility Contract

Five version axes move independently. A change on one axis never silently changes another.

| Axis | Current | Where | Bumped when |
|---|---|---|---|
| Package | `0.5.0b1` | `pyproject.toml`, `vep.__version__`, `vep.versions.PACKAGE_VERSION` | any release |
| Protocol | `0.3` | `vep.versions.PROTOCOL_VERSION` | lifecycle/identity/canonicalization **semantics** change |
| Canonical format | `VEP-C1` | `canonical.py`, RFC-0001 §2 | serialization rules change (changes every identity) |
| Object schema | per type; Evidence/Certificate = **2**, all others = 1 | `objects.CURRENT_VERSION` | a type's fields or cross-field rules change |
| Database schema | **3** (2 plus `jobs`, `job_events`, `build_cache`, `build_log`) | `meta.schema_version`, `migrations.py` | table/trigger layout changes |
| Evidence format | **2** | `versions.EVIDENCE_FORMAT_VERSION` | what evidence/certificates assert changes |

`vep version --json` prints all of them.

## Promises (for the 0.5 beta line; unchanged in kind from 0.4.x)
* **Identities are stable.** An object's id is derived from `(type, schema_version, canonical fields)`. Unchanged types keep their 0.3.0 ids (pinned by `tests/test_compat.py`). Schema-v1 `Evidence`/`Certificate` keep decoding to the same bytes and ids (frozen fixtures in `tests/fixtures/`).
* **Unknown versions fail predictably.** Decoding an unsupported `schema_version` raises `SchemaError("UNSUPPORTED_SCHEMA_VERSION …")` (CLI exit 11); a database newer than the build raises `UNSUPPORTED_DATABASE_VERSION`. Nothing is guessed.
* **No silent reinterpretation.** v1 evidence has no trust field; it is classified by a closed mapping (`NONE_TRUSTED_LOCAL → TRUSTED_LOCAL`, anything else → `UNVERIFIED`) and **can never become `ISOLATED_VERIFIED`**. v1 evidence cannot be newly certified; existing v1 certificates still verify and report `legacy_schema: true`.
* **Policies.** `required_trust` is an optional policy field, omitted when unused, so existing policy ids are unchanged. When absent, the *verifier* states its requirement (`--require-trust`, default `TRUSTED_LOCAL`, echoed in the output); there is no hidden default.
* **CLI.** Commands and flags from 0.3.0 keep working. Additions in 0.4.0a1: `vep version`, `vep isolation detect|verify`, `--field`, `--budget` (objective), `--require-trust`, `--image`/`--attestation-file` (evaluate). Exit codes are stable (`docs/VARIABLES.md`, "CLI and process"). `--json` output is a JSON object/array; field *addition* is not considered breaking, removal/renaming is.
* **Python API.** Modules named in the README quickstart and `docs/ARCHITECTURE.md` are the supported surface; names starting with `_` are private. In alpha, minor releases may change module-level APIs with a CHANGELOG entry.

## Intentional behavior changes after 0.5.0b1 (unreleased; the next package version is proposed as `0.6.0b1`, protocol version stays `0.3`)
| Change | Why | Compatibility effect |
|---|---|---|
| `vep conformance export` writes **bundle format 2** by default; `--bundle-version 1` keeps the old self-contained format; `vep conformance verify` requires a trust policy (or `--internal-only`) | a bundle that carries its own keys and expectations cannot authorize itself (reproduced in `tests/test_trust_anchor_risk.py`) | scripts that exported and verified v1 bundles keep working with `--bundle-version 1 --internal-only`; the result is now labelled `INTERNAL_CONSISTENCY_ONLY`. Protocol semantics are unchanged |
| New object type `DerivedAttestation` (v1, prefix `datt`), bundle format 3, `vep reuse` | exact-input evidence reuse with a verifiable derivation chain | additive; Evidence and Certificate schemas are unchanged |
| Build actions are `bact2-` identities: timeout, isolation and declared dependencies are part of the identity; results carry `assurance` (`SINGLE_RUN` or `TWO_RUN_MATCH`) | the old identity omitted inputs that change the executed contract, and a hit was described as determinism-verified | cache entries written by 0.5.0b1 are not reusable (a miss, never a wrong hit) |
| Conformance suites 1.1 and 1.2; CLI default suite is 1.2 | new vectors | suite 1.0 is untouched and still passes |
| Optional extras `mcp`, `a2a`, `claude`; console scripts `vep-mcp`, `vep-a2a`; `vep claude`, `vep reuse` | MCP/A2A/Claude integration | additive; the core install has no new required dependency |
| Database schema stays 3 (idempotency keys, A2A task maps and derived-attestation indexes use the existing `meta` table) | - | none |

## Intentional behavior changes in 0.5.0b1
| Change | Why | Compatibility effect |
|---|---|---|
| Ids, digests, timestamps, decimals reject a trailing newline and non-ASCII digits | independent verifier found the reference accepted them | none for objects VEP produced; hand-made objects containing such values are rejected. Protocol version stays 0.3 (strictly fewer inputs accepted) |
| Unittest runner places staged roots before site-packages; shadowed modules fail the evaluation | an installed copy of the project could be tested instead of the candidate | new evaluations of projects whose package is also installed now test the staged copy; the runner digest changes, so earlier cached evidence is not reused |
| `evaluate`/`certify` accept an optional `guard` | controller fencing | none for callers that omit it |
| Database schema 3 | controller and build-cache tables | additive; opening a schema-2 workspace migrates it (see MIGRATIONS); a 0.4 build must not be pointed at a migrated workspace |
| `TokenReceipt.usage_source` accepts `caller_supplied` | provenance of tool-claimed usage | older receipts decode unchanged |

## Intentional behavior changes in 0.4.0a1
| Change | Why | Compatibility effect |
|---|---|---|
| `certify` refuses schema-v1 evidence | v1 carries no trust level | evidence from 0.3.0 workspaces must be regenerated by re-evaluating; existing certificates are unaffected |
| `evaluate` refuses when the policy requires `ISOLATED_VERIFIED` | structural no-downgrade | only affects new policies using `required_trust` |
| `.vep` is chmod 0700 on init | SR-02 | none for the owning user |
| Unix-only `O_NOFOLLOW` reads | SR-04 | none on supported platforms (Linux, macOS) |

## Supported platforms
Linux and macOS with Python ≥ 3.11 (tested locally on macOS with 3.11–3.14; the hosted CI matrix (Linux 3.11–3.14, macOS 3.13) passed on the `0.5.0b1` release commit). Windows is **not supported** (POSIX file modes, process groups, `O_NOFOLLOW`).
