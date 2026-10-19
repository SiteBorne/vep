# Security Architecture

## What a VEP result does and does not mean

Three questions are deliberately kept apart:

| Question | Established by | NOT established by |
|---|---|---|
| **A. Evidence integrity** — were these exact bytes produced by a holder of the signing key and left unmodified? | Ed25519 signature over the DSSE-style envelope; content-addressed digests; immutable DB rows | A signature says nothing about *how* the evidence was produced |
| **B. Evaluator authorization** — was running this code permitted? | The explicit `--trusted-local-execution` acknowledgment (trusted-local), or a current isolation attestation (isolated); the funded budget reservation; the frozen policy | Authorization is not a guarantee of safety |
| **C. Independence of the execution environment** — could the candidate have touched the evaluator or the signing authority? | The recorded `trust_level` and, for `ISOLATED_VERIFIED`, an attestation of the T1–T12 matrix observed in this environment | Local processes alone never establish it |

## Trust levels

| Level | Meaning | Produced by | Can satisfy |
|---|---|---|---|
| `TRUSTED_LOCAL` | Operator-authorized run of **operator-trusted** code in an ordinary host subprocess. Candidate code had the signer's OS authority. Local development use. | `vep evaluate --trusted-local-execution` | `--require-trust TRUSTED_LOCAL` (the default) |
| `ISOLATED_VERIFIED` | Run inside a Docker+gVisor boundary whose properties (T1–T12) were *observed* for this image/runtime; signing authority outside the candidate's reach; evidence records runtime identity and attestation digest | `vep evaluate --isolated` with a current attestation | both requirements |
| `UNVERIFIED` | Required isolation facts are absent or failed. Never certifies, never satisfies any requirement, never falls back to trusted-local. | any failed/absent verification | nothing |

Rules enforced in code (not prose):
* Evidence/Certificate schema v2 carries `trust_level`, `evaluator_id`, `execution_environment`; `ISOLATED_VERIFIED` is rejected at object construction unless `isolation == DOCKER_GVISOR` **and** an attestation digest is present; a local run cannot carry an attestation (`objects._check_trust_consistency`).
* The certificate must repeat the evidence's trust level and evaluator id; a mismatch fails verification.
* A policy may set `required_trust: ISOLATED_VERIFIED`; trusted-local evaluation then refuses to start. Verifiers choose `--require-trust`.
* Legacy v1 objects stay verifiable and are classified by a closed mapping that never yields `ISOLATED_VERIFIED`.
* Isolation failures raise `IsolationUnavailable` (exit 8) before any state change; no code path runs the candidate on the host as a fallback.

## Why moving the key into another process is not a fix

If candidate code and the signer share an OS user, filesystem and ptrace authority, a separate process boundary changes nothing: the candidate can read the key file or attach to the signer. VEP therefore does **not** claim to fix SR-01 by process separation. The signing authority is outside the candidate's reach only in the isolated path, where candidate code runs in a container that mounts nothing of VEP's state (verified by tests T4/T5 in the matrix).

## The evaluator trust boundary

* The runner (`_runner.py`) is identified by digest in the Action and the Evidence and lives outside the staged tree.
* The final evidence record is derived by the parent from what it observed: exit status, captured stdout/stderr digests, the staged-tree re-hash, and a *validated* report. A candidate-supplied report never authorizes anything by itself: it must be consistent with the exit status, the runner's stderr summary, the frozen required-test digests and the minimum-test rule.
* Even inside a sandbox the test runner and code under test share a process; a hostile candidate can still make *its own tests* misreport. `ISOLATED_VERIFIED` protects the host and the signer, not the semantic truth of the test outcome (SR-09). Independent re-execution is future work.

## Isolation verification matrix (executable, offline)

`vep isolation verify --image <name@sha256:…>` runs these against the local daemon and writes an attestation; each is `PASS` only if observed:

T1 source readable · T2 source mount not writable · T3 root filesystem read-only · T4 signing key absent · T5 VEP database absent · T6 external networking denied · T7 privileged operations denied (non-root, no capabilities, no-new-privileges, no docker socket) · T8 resource limits enforced (memory kill observed) · T9 timeout terminates work and leaves no container · T10 wrong runtime fails closed · T11 image substitution detected (pinned digest must match the local image) · T12 runtime identity recorded from `docker inspect` of a started container.

Plan invariants: digest-pinned local image (`--pull=never`), `--runtime=runsc`, `--network=none`, `--read-only`, read-only source mount, no VEP mounts, no Docker socket, no `--privileged`, `--cap-drop=ALL`, `no-new-privileges`, non-root uid, CPU/memory/PID limits, bounded tmpfs, enforced timeout, forced container removal.

**Status on the development host (macOS, Docker CLI present, daemon not running, no `runsc`): `ISOLATION_UNVERIFIED`; every matrix test is `NOT_RUN`.** The decision logic is tested with a stub docker CLI (`tests/fixtures/stub_docker.py`), which proves nothing about real isolation. To obtain a real result you need a Linux Docker daemon with gVisor registered ([gVisor Docker quick start](https://gvisor.dev/docs/user_guide/quick_start/docker/)) and a locally present digest-pinned Python image; then `VEP_ISOLATION_IMAGE=<image> scripts/release_check.sh` records the result under `OPTIONAL_ISOLATION`. Docker Desktop on macOS does not ship gVisor.

## What VEP will never claim
That arbitrary untrusted code can be safely evaluated, that a signature implies correct evaluation, that tests passing implies software correctness, or any SLSA level. The release policy rejects such claims mechanically (`scripts/release/release_policy.json`, tested in `tests/test_release.py`).
