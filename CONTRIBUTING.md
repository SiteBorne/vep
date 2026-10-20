# Contributing

Thanks for helping. VEP's rule of thumb: **remove failure modes with code, schemas and tests rather than adding instructions.**

## Setup
```bash
git clone https://github.com/SiteBorne/vep && cd vep   # or your fork
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```
Python ≥ 3.11 on Linux or macOS. No network access or accounts are needed to run the tests.

## Workflow
1. Open an issue (or comment on one) for anything larger than a bug fix.
2. Write a failing test first. Prefer small deterministic tests that drive real behavior; do not add tests that assert hard-coded success, and never skip or delete a test to get green.
3. Make the change. Keep public CLI behavior and documented APIs stable unless fixing a defect (then update `docs/COMPATIBILITY.md` and `CHANGELOG.md`).
4. Run:
   ```bash
   python -m unittest discover -s tests -t .
   python -m pytest -q
   python scripts/gen_variables.py          # if you changed object schemas or documented parameters
   scripts/release_check.sh --skip-matrix   # builds, installs, clean-room test, scans
   ```
5. Open a pull request describing the behavior change and the test that covers it.

## Ground rules
* Free/open-source dependencies only; no mandatory network, hosted service, or paid API.
* Honest claims: label things IMPLEMENTED / TESTED / SIMULATED / DESIGNED / UNVERIFIED. Simulated numbers are never presented as measurements. `scripts/release/release_policy.json` rejects unsupported security claims in docs.
* Never commit secrets, keys, databases or machine-specific paths (`scripts/release/ci_checks.py` checks tree and history).
* Security-sensitive changes (evidence, trust levels, snapshots, budgets, isolation) need a regression test and a row in `docs/SECURITY_REVIEW.md` if they fix a finding.
* By contributing you agree your contribution is licensed under Apache-2.0.

Security problems: do **not** use public issues; see [SECURITY.md](SECURITY.md).
