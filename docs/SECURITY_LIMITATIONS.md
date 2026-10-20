# Security limitations

Read together with [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](../SECURITY.md).

## What is and is not verified
| Area | State |
|---|---|
| Trusted-local execution (`TRUSTED_LOCAL`) | Works; runs code with **your permissions and no isolation**. Use only for code you already trust. |
| Docker + gVisor isolation (`ISOLATED_VERIFIED`) | Verified on **one** GitHub-hosted Linux run: 12 of 12 [C:matrix] matrix tests passed and an isolated evaluation was certified ([isolation/README.md](isolation/README.md)). **Not** verified on the development Mac (container VM not running, no `runsc`). Not escape-tested. |
| Evaluating untrusted or hostile submissions | **Not claimed.** Even inside the sandbox, the test runner and the code under test share a process, so hostile tests can misreport their own outcome (SR-09). |
| Runtime identity (T12) | Taken from `docker inspect`; not independently observed from inside the container. |
| Signing | One local Ed25519 key per workspace; no rotation, no transparency log, no external signer. A signature proves who signed which bytes, not that the run was honest. |
| Token usage | Runtime-reported counts are labelled as such; tool-claimed counts are unauthenticated and labelled `caller_supplied`. |
| Shadow check | The unittest runner fails closed when an installed copy of the project would be tested instead of the staged tree; the pytest evaluator does not yet perform this check. |
| Evidence reuse | Exact snapshot only. Cross-candidate reuse is not implemented. |
| Cancellation | Cooperative: a running subprocess is not killed, its result is discarded at the commit boundary. |
| Independent verification | A second implementation exists (Node) but was written by the same author; it has had no outside review. |
| External review | None. No third-party security audit has been performed. |

## Defects this project found in itself while being tested
These were found by dogfooding, an external project and a real runtime, then fixed with regression tests (see [CHANGELOG](../CHANGELOG.md)): the anti-shadowing rule blocked VEP's own package name; tests were not hermetic against an installed copy; **an installed copy of a project could be tested instead of the candidate and certify**; ids and digests with a trailing newline were accepted; and the pinned-image check could never match a tagged reference on a real runtime (it failed closed). Expect more.

## Reporting
Use GitHub private vulnerability reporting for this repository where enabled ([SECURITY.md](../SECURITY.md)).
