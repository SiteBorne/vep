# Announcement package (drafts for approval — NOTHING HAS BEEN POSTED)

**Status: the launch gate reports `ANNOUNCEMENT_READY = YES` for the published prerelease `v0.5.0b1`; NOTHING HAS BEEN POSTED.** The decision and its evidence are in `launch-gate.json` and `docs/LAUNCH_READINESS_REPORT.md` (gate run on commit `1e1c5b1` with hosted CI and CodeQL green, published assets re-verified, valid hosted benchmark evidence). Everything below is a draft for your approval and edit. Every figure carries a claim tag (`[C:` plus a name) resolved by `scripts/check_claims.py` against a report in this repository; if you edit a number, run that script. YES means the declared rules are met, not that VEP is production-ready or that untrusted code is safe to run (see [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md)).

Positioning: **VEP makes software changes evidence-carrying, resource-aware, and independently checkable.** Not faster, not safer than the tools it sits beside; see [COMPARISON.md](COMPARISON.md).

## 1. GitHub repository description (one line)
Evidence-carrying changes: bind test results to an exact source snapshot, sign them, and verify the certificate offline with an independent implementation. Local reference implementation, Apache-2.0.

## 2. Architecture in one paragraph
An objective freezes a source snapshot (content-addressed) and an acceptance policy (existing tests protected by digest). A candidate change is evaluated by a protected runner that rejects false greens, under a leased, fenced job in a SQLite-backed controller; the result is signed evidence labelled `TRUSTED_LOCAL` or `ISOLATED_VERIFIED`, and a certificate valid for exactly that snapshot. A certificate can be exported as a bundle and checked with only SHA-256, Ed25519 and a JSON parser; a second implementation does so for all 119 vectors [C:vectors] of the frozen conformance suite.

## 3. One-minute demo script (all commands are executed by the release gate; see [QUICKSTART.md](QUICKSTART.md))
```text
0:00  vep init                                   # workspace + signing key, nothing leaves the machine
0:10  vep objective create --title "keep calc correct" --budget 1.00
0:20  (edit calc.py: add a function)  vep candidate create --objective $OBJ
0:30  vep evaluate --candidate $CAND             # refused: no authorization (exit 7)
0:35  vep run --candidate $CAND --trusted-local-execution     # evaluated, signed, certified
0:45  vep conformance export --certificate $CERT --out bundle.json
0:50  node conformance/node/verify.mjs bundle bundle.json     # independent check: valid
0:55  edit calc.py again; vep verify --certificate $CERT      # rejected: SOURCE_CHANGED
```

## 4. Verifiable summary of results (details: [REAL_WORLD_RESULTS.md](REAL_WORLD_RESULTS.md))
* VEP verified its own change through its own pipeline: 365 tests [C:dogfood-tests] passed, a negative control was rejected and a post-certification edit invalidated the certificate ([dogfood/README.md](dogfood/README.md)).
* On two small open-source projects at pinned commits, the one-line mutants were rejected by 259 tests [C:pyflakes-mutant] and by 43 tests [C:mit-mutant] of the projects' own suites ([external/README.md](external/README.md)).
* Isolation: 12 of 12 [C:matrix] matrix tests passed on one GitHub-hosted runner with gVisor ([isolation/README.md](isolation/README.md)). Not escape-tested; not claimed for untrusted code.
* Speed: no advantage. A single check cost +43.8% [C:t1-small] on a short suite and +2.0% [C:t1-big] on a longer one; pytest-testmon was about 18.2x [C:testmon-edit] faster after a small edit. Measured on a fresh GitHub-hosted Linux VM that met the declared idle criterion ([BENCHMARK_RESULTS_HOSTED_LINUX.md](BENCHMARK_RESULTS_HOSTED_LINUX.md)); the earlier macOS runs agree qualitatively ([REAL_WORLD_RESULTS.md](REAL_WORLD_RESULTS.md)).
* While being tested VEP exposed several defects in itself, including a path where an installed copy of a project could be tested instead of the candidate ([SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md)). All were fixed with regression tests.

## 5. Hacker News (Show HN) — draft
**Title:** Show HN: VEP – signed, exact-snapshot test evidence you can verify offline

**First comment:**
> I built VEP because agent-produced changes end up re-checked by hand, and a CI log doesn't tell you which exact source was tested or what could have tampered with the run. VEP binds the test result to a content-addressed snapshot, freezes the tests that existed at the start, rejects false greens (zero tests, all skipped, forged output, an installed copy of the package being tested instead of the candidate), signs the evidence, and lets you verify the certificate with a second implementation that shares no code with the first.
>
> What it is not: it is not faster than running your tests (+2.0% [C:t1-big] on a longer suite, +43.8% [C:t1-small] on a short one), pytest-testmon beats it badly on re-runs, and it does not make untrusted code safe to run. Default mode runs your own code unisolated; there is a gVisor path that passed 12 of 12 [C:matrix] checks on one CI run, not escape-tested. No external audit. Everything is local; no account, no model calls.
>
> The part I found most useful: pointing it at its own repo and two small OSS projects turned up real bugs in VEP, which are documented. Repo, quickstart, failure records and the benchmark methodology (thresholds written before measuring) are all in the repo. Happy to be told what's wrong with it.

## 6. Reddit — draft (check the subreddit's current self-promotion rules before posting; r/Python and r/programming have restrictions that change)
**Title:** A small tool that turns "tests passed" into a signed certificate bound to an exact source snapshot (Python, Apache-2.0, early)

> Local reference implementation, not production software. What it does: freeze the acceptance tests, reject false greens, sign the evidence, export a bundle that an independent Node verifier checks. What it doesn't: speed anything up, or sandbox hostile code by default. Real numbers and the places it was slower or wrong are in the repo's results doc. Feedback on the wire format ([CONFORMANCE.md](CONFORMANCE.md)) especially welcome.

## 7. LinkedIn — draft
Agents can produce changes faster than people can check them. I've been building VEP, a small open-source protocol and reference implementation where a change comes with evidence: the exact source snapshot it was tested against, the acceptance rules frozen at the start, a signed result, and a certificate that a second, independent implementation can verify offline.
What I learned by testing it on itself and on two open-source projects: it adds no speed (slower on a short suite, about the same on a longer one), its guarantees are narrower than they sound, and the most valuable output was a list of real defects it exposed in itself, including an installed copy of a package being tested instead of the candidate change. All documented, with the benchmark methodology written before the measurements. Early, local, Apache-2.0, no external audit.

## 8. X — draft (two posts)
1/ VEP: make a code change carry its own evidence. Tests bound to an exact source snapshot, signed, checkable offline by an independent verifier. Early, local, Apache-2.0.
2/ Honest bits: not faster (+2.0% [C:t1-big] to +43.8% [C:t1-small] vs plain runs; testmon ~18.2x [C:testmon-edit] faster on edits), gVisor path passed 12 of 12 [C:matrix] on one CI run, not for hostile code. Failure records in the repo.

## 9. Before any of this is posted
* Review and edit the drafts; check each target community's current rules (the Reddit and Hacker News drafts are starting points, not approved text).
* Keep the limits in the first comment: no speed advantage, trusted-local by default, isolation verified on one hosted run and not escape-tested, no external audit, one local-model run.
* The gate is a snapshot of commit `1e1c5b1`; re-run `python scripts/launch_check.py` on the commit you announce from.
