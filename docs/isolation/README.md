# Isolation test on a hosted runner (Phase I)

Workflow: `.github/workflows/isolation.yml` (permissions `contents: read`; triggers `workflow_dispatch` and push to the
`isolation-ci` branch only; no secrets; uploads only the attestation and summaries). Environment: GitHub-hosted
`ubuntu-24.04` x86_64, Docker with `runsc` installed from gVisor's apt repository after checking the archive-key
fingerprint (`6F1DF85E3A71C24918E727D56FC6D554E32BD943`, recorded from gvisor.dev/archive.key on 2026-10-19 over TLS; the
pin protects against later change, not against a compromised first fetch), image `python:3.13-slim` pulled by index digest
`sha256:70729b46...c2f`.

| Run | Result | Why |
|---|---|---|
| 39347349190 (first) | matrix `ISOLATION_UNVERIFIED`, end-to-end FAIL | gVisor installed and `runsc` registered, but VEP's pinned-image check compared `python:3.13-slim@sha256:...` with Docker's `RepoDigests` (`python@sha256:...`, no tag) and never matched. A bug that no real runtime had ever exercised. VEP failed closed and ran nothing. |
| 39347549501 (after fix) | **T1-T12 all PASS; `ISOLATED_VERIFIED`; end-to-end PASS** | Isolated evaluation of the example project (2 tests) gave PASS evidence at `ISOLATED_VERIFIED`, certified, verified by the Python reference and the independent Node verifier; a wrong image string and an unauthorized host run were both refused. Records: `ci-run-39347549501-*.json`. |

## What this establishes
The offline matrix (source readable, source mount and root filesystem read-only, signing key and VEP database absent,
external networking denied, privileged operations denied, memory/pids limits set, timeout terminates work, wrong runtime
fails closed, image substitution detected, runtime identity recorded) held for **this runner, runtime and image on one run**,
and VEP's isolated path produced and verified an `ISOLATED_VERIFIED` certificate there.

## What it does not establish
* Not escape resistance: gVisor reduces the kernel attack surface; VEP did not attempt escapes. Residual risk remains.
* T12 (`corroboration: docker-inspect-only`) takes the runtime name from `docker inspect`; it does not independently observe from inside the container that gVisor is the kernel in use. Strengthening this is open work.
* The signing key in that job was ephemeral (demonstration issuer). A hosted-runner attestation cannot authorize isolated evaluation on another machine: `attestation_is_current` re-checks the local runtime, and the development Mac remains `ISOLATION_UNVERIFIED` (colima not running, no `runsc`).
* Isolated mode supports the stdlib `unittest` runner and projects without third-party packages in the image; the test runner and code under test share a process, so a hostile candidate can still make its own tests misreport (SR-09). Untrusted-submission evaluation is therefore **not** claimed.
* One run, one image, one runner generation; GitHub-hosted runner images change over time.
