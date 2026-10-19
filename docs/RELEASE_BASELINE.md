# Release Baseline (observed, not inherited)

Everything below was measured at the start of the 0.4.0a1 work by running the commands shown. Prior-session claims were treated as unverified until reproduced.

| Field | Observed value |
|---|---|
| BASELINE_COMMIT | `aba193de65e4d255bf4d1f87a24377819cb47f70` (see note) |
| BASELINE_VERSION | 0.3.0 (`pyproject.toml`, `vep.__version__`) |
| BASELINE_TEST_COUNT | unittest: **221** run; pytest: **221** passed |
| BASELINE_FAILED_TESTS | 0 (unittest and pytest) |
| BASELINE_SKIPPED_TESTS | 0 (`pytest -rs` listed none; unittest output contained no `skipped`) |
| BASELINE_CLI_STATUS | `vep --help` lists 17 subcommands; `scripts/verify.sh` smoke test of the installed CLI passed; demo (`examples/run_demo.py`) printed `DEMO OK` |
| BASELINE_PACKAGE_STATUS | `python -m build` produced `vep_protocol-0.3.0-py3-none-any.whl` and `vep_protocol-0.3.0.tar.gz`; installed in a fresh venv; `vep` entry point worked |
| Benchmark reproducibility | `benchmarks/run_simulation.py` ran twice with seed 20261019: identical (sha256 `e98e2a562d7a5df09f90cc03a532376b80ed8c36790add89f644167e902c3b2f`) |

## How the baseline was taken
```
scripts/verify.sh                                  # rc 0, "ALL VERIFICATION STEPS PASSED"
python -m unittest discover -s tests -t .          # Ran 221 tests ... OK
python -m pytest -q -rs                            # 221 passed
```
Environment: macOS 15.6 (Darwin 24.6.0, arm64), Python 3.14.7 for the venv; Python 3.11, 3.12, 3.13 interpreters also present (used later for the compatibility matrix). Docker CLI present, **daemon not running**, no `runsc`.

**Note on the baseline commit.** The working directory was *not* a Git repository when this milestone began (no `.git`, no remotes). To preserve the exact 0.3.0 state (including all user files) before any change, a local repository was initialized and the untouched tree was committed as the baseline (`git init`, one commit; no remote configured; nothing pushed). No file was discarded or rewritten.

## BASELINE_SECURITY_LIMITATIONS (as found)
1. Trusted-local evaluation runs candidate code with the invoking user's authority; candidate code can read the signing key (`.vep/keys/signing.pem`) and can forge or influence the test report it is judged by. A locally signed certificate therefore demonstrates *who signed*, not independent verification of hostile code.
2. Evidence/Certificate schema v1 carried an unattested `isolation` string and no trust level or evaluator identity.
3. The Docker/gVisor adapter produced a plan and probe only; `evaluate(mode="isolated")` always failed closed. No real container execution had ever been performed.
4. `.vep/` was created with the default umask.
5. Provider token usage is caller-supplied and unauthenticated.
6. No CI, no release gate, no provenance record, no community/security documents existed.
7. Snapshot content was read with a symlink-following read after the tree scan (race window), docker `--mount` values were built by string interpolation of paths, and absurdly large budget amounts raised an uncaught SQLite overflow (fixed in this milestone: SR-02…SR-05 in [SECURITY_REVIEW](SECURITY_REVIEW.md)).

## Reported-vs-observed
All of the previous session's headline claims (221 passing tests, no skips, adversarial F01–F20, registry checks, demo, reproducible benchmark, wheel/sdist, fresh-venv install) were reproduced exactly. No claim in the previous completion report was found to be false at the baseline.
