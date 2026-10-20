# External projects evaluated through VEP

Read-only clones at pinned commits; nothing was pushed. Both projects are MIT-licensed (LICENSE files confirmed in
the clones). Their tests ran **as the invoking user with no isolation**, with the user's prior approval for these two
repositories. Produced by `scripts/external_eval.py` using `benchmarks/external/projects.json`. One host, one run each.
Neither project has third-party runtime dependencies, so "nontrivial dependencies" is **not** covered by this exercise.

| Project (pinned) | Upstream suite | Upstream via VEP | Benign +1 test | Mutant, project tests only | Mutant + covering test | Edit after certification |
|---|---|---|---|---|---|---|
| pyflakes 4.0.3 (`8526af8`), small linter application | 795 run, 28 skipped, 0.47 s direct | CERTIFIED, 0.60 s | CERTIFIED | REJECTED (259 failures) | REJECTED | certificate rejected (`SOURCE_CHANGED`) |
| more-itertools v11.2.1 (`4aeb433`), library | 930 run, 5 skipped, 6.46 s direct | CERTIFIED, 6.65 s | CERTIFIED | REJECTED (43 failures) | REJECTED | certificate rejected |

Both certificates verify as portable bundles in the Python reference and the independent Node verifier. VEP's
evaluation wall time was within about 0.15 s (pyflakes) and 0.2 s (more-itertools) of running the tests directly; a
single run each, so this is an observation, not an overhead claim.

## What the exercise found (kept as records in `earlier/`)
1. **pyflakes, run 1: upstream rejected.** `test_lazy_imports.py` is entirely skipped on Python 3.14, and VEP refuses a required file that cannot run (`REQUIRED_SUITE_ALL_SKIPPED`). VEP behaved as designed. Resolution: an explicit operator-side `required_exclude` in `make_policy`, recorded in the report with its reason (the file still runs, but is no longer digest-protected).
2. **more-itertools, run 2: a false green that VEP did not detect.** The evaluator interpreter contained an installed `more_itertools`, which shadowed the staged project. The upstream and "mutant" candidates were certified while testing the *installed* library; the mutant appeared to survive and a covering test appeared to pass, which was impossible. Cause: the runner appended project roots after site-packages and never checked what was loaded. Fix (committed, tested): roots are placed after the standard library but before site-packages, and the runner reports any module the staged tree provides but that was loaded from elsewhere; such a report fails closed as `CODE_UNDER_TEST_SHADOWED`. After the fix the mutant is correctly rejected by the project's own suite.
3. Earlier VEP-on-VEP runs (see `docs/dogfood/`) were made before this fix; in them `vep` was deliberately absent from the evaluator interpreter, and the staged-code negative control passed, but they should be re-run with the current runner before any release claim.

Not covered: the pytest evaluator does not perform the shadow check (no runner report); isolated mode; any project with
dependencies; more than one run.

## Final re-run at the release-candidate source (commit `4d0216a`, version `0.5.0b1`)
Both projects: upstream CERTIFIED, benign change CERTIFIED, mutant REJECTED by the project's own tests, mutant plus covering test REJECTED, post-certification edit rejected, bundle verified by the Python and Node verifiers. Reports: `pyflakes.json`, `more-itertools.json`; the previous runs are kept in `earlier/` (`*-run-3-before-0.5.0b1.json`).
