# Revalidation of the hosted isolation evidence (run 39347549501)

Re-inspected from the saved artifacts and from the run's raw logs (downloaded with `gh api .../actions/runs/39347549501/logs`), not from the workflow status alone.

| Item | What the evidence shows |
|---|---|
| Source commit | The run's head SHA is `c8e1f00d57cfbbd013d71a26518b882d05786495` on branch `isolation-ci` (event: push). That commit contains the pinned-image fix and is an ancestor of the release candidate branch (`git merge-base --is-ancestor c8e1f00 HEAD` succeeds). |
| Earlier run | 39347349190 (commit `c1b89d8`) failed closed with `ISOLATION_UNVERIFIED` because of the pinned-image comparison defect; kept as a defect-discovery record (`docs/isolation/README.md`). |
| Runner | `ubuntu-24.04`, runner image version 20261012.334.1, x86_64; server `Ubuntu 24.04.5 LTS`. |
| gVisor | `runsc version release-20261012.0`, installed from the official apt repository after the archive key fingerprint `6F1DF85E3A71C24918E727D56FC6D554E32BD943` matched the pin (log line "key fingerprint: ..."). The runtime's own metadata reports platform `systrap`. Docker lists `runsc` among its runtimes. |
| Image | `docker.io/library/python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f` pulled by digest (log: "Digest: sha256:70729b46..."); local `RepoDigests` equal the pin; image id `sha256:ce3ff952...7569`. |
| Tests actually executed | Matrix T1-T12 each ran a command in a `--runtime=runsc` container; observations are stored in the attestation. The end-to-end step then evaluated the 2-test example project inside the container (2 run, 2 passed, 0 skipped), certified it and verified the certificate (Python reference and Node). |

## Property-by-property
| Property | Observation (from the attestation) | Verified as stated? |
|---|---|---|
| Source readable | read succeeded | yes |
| Source mount not writable | write raised PermissionError | yes |
| Root filesystem read-only | write raised PermissionError | yes |
| No signing key in the container | search of the checked locations found nothing | yes, for the locations searched only (not exhaustive) |
| No VEP database in the container | search of the checked locations found nothing | yes, same limit |
| No host credentials | not a separate test; follows only from what is mounted (source, runner, tmpfs) | **not independently tested** |
| External networking denied | connect failed with OSError; no non-loopback interfaces listed | yes |
| Privileged operations denied | effective capabilities 0, no `docker.sock`, `no_new_privs`=1, uid 65534, setuid failed | yes, for the operations tried |
| Resource limits | memory 128m: an over-allocating process was killed (exit 137); pids limit 64 and 1 CPU are set per `docker inspect`; pids exhaustion itself was not exercised | memory yes; pids/CPU configured only |
| Timeout enforcement | the work was terminated, nothing left behind | yes |
| Failure handling | a nonexistent runtime made Docker refuse (exit 125) and nothing ran | yes |
| Image substitution | the pinned digest matched; a substituted reference did not resolve | yes |
| Runtime identity | taken from `docker inspect` (runtime `runsc`, network none, read-only rootfs) | **configuration only**: the kernel in use was not observed from inside the container |
| Result transport integrity | the report returns on stdout as a marker line and is cross-checked against the exit status and the runner's stderr summary | yes for accidents; a hostile candidate sharing the runner process can still forge its own report (SR-09) |
| Environment cleanup | containers run with `--rm`; leftover processes checked by T9 only | partly |

## Still `ISOLATION_UNVERIFIED` (or unclaimed)
* In-container confirmation that gVisor is the kernel (the "runtime identity" row), and host-credential absence beyond the mounted paths.
* Escape resistance, malicious-code immunity and production-grade isolation are **not** claimed. One run, one runner image, one container image.
* This development machine: no `runsc`, container VM not running: `ISOLATION_UNVERIFIED`.
