# Why VEP

**Status: pre-release local reference implementation. The published prerelease is `v0.4.0a1`; the work described here is on the development branch and unreleased.**

## The problem it targets
When an agent (or a person) changes code, the cost is not only producing the change. Someone or something must then decide whether to trust it, and the answer usually lives in a CI log that says nothing portable about *which exact source* was tested, under *which* acceptance rules, with *what* level of isolation. VEP's premise is that a change is a proposal, and the valuable output is a **verified improvement that carries its own evidence**.

## What VEP adds
VEP makes software changes evidence-carrying, resource-aware, and independently checkable:
* **Exact-snapshot binding.** A certificate is valid for one content-addressed source tree. Edit one byte and it stops applying; the dogfood runs show this ([docs/dogfood/README.md](dogfood/README.md)).
* **Protected acceptance.** The tests that existed when the objective was created are frozen by digest. A candidate that edits, deletes or shadows them, or whose run could not have tested the staged code, is rejected by code, not by review.
* **False-green defences.** Zero tests, all-skipped suites, forged exit codes and a project's installed copy shadowing the staged source are all rejected, with machine-readable reasons.
* **Honest trust labels.** Evidence says whether it came from `TRUSTED_LOCAL` (your own code, no isolation) or `ISOLATED_VERIFIED` (a gVisor container whose properties were tested), and a verifier chooses which it accepts.
* **Independent checking.** A certificate can be exported as a bundle and verified without VEP's database by a second implementation; both agree on all 119 vectors [C:vectors] in the frozen suite ([CONFORMANCE.md](CONFORMANCE.md)).
* **Resource accounting.** Budgets are transactional, token usage keeps its provenance (runtime-reported, tool-claimed, estimated), and local compute is measured rather than priced.

## What it does not do
* It does **not** make verification faster. Measured against running the tests directly it is slower on a small suite (+50.5% [C:t1-small]) and within noise on a longer one (+3.9% [C:t1-big]); change-based test selection with pytest-testmon was about 14.5x [C:testmon-edit] faster after a small edit ([REAL_WORLD_RESULTS.md](REAL_WORLD_RESULTS.md)). VEP re-runs the full suite after any change on purpose.
* It does not replace Git, CI, Bazel or an agent framework ([COMPARISON.md](COMPARISON.md)).
* It does not execute hostile code safely. Isolation was verified on one hosted runner and is not escape-tested ([SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md)).
* It is not a guarantee of correctness: a certificate says *these tests passed against this exact source under this policy and trust level*.

## When it may be worth using
You run agents or contributors that produce many changes, you want a record of what was verified that someone else can check offline, and you value rejecting unsound results more than shaving seconds. If you only need fast feedback on a small project, plain test runs or an incremental tool are the better fit.
