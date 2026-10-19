# VEP — Verified Evolution Protocol (0.3.0 reference MVP)

Software changes are *proposals*; **verified improvements** are the output. VEP is a local, offline, source-control-independent protocol implementation for AI-native development: exact-snapshot identities, a frozen acceptance policy candidates cannot rewrite, transactional budgets, false-green-proof evaluation, Ed25519-signed evidence and certificates.

> **Not production-ready. Not a sandbox.** The only implemented execution mode runs candidate code in a plain host subprocess behind an explicit `--trusted-local-execution` authorization. It provides **no security isolation**. The Docker+gVisor adapter produces a hardened plan and a probe; container execution is *not implemented/unverified* and always fails closed. No live LLM, cloud, or paid service is used or required. See `docs/IMPLEMENTATION_STATUS.md`, `docs/THREAT_MODEL.md`.

## Install and verify (Python ≥ 3.11)
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # cryptography is the only runtime dependency
python -m unittest discover -s tests -t .   # baseline (stdlib unittest)
python -m pytest -q                          # same suite under pytest
python examples/run_demo.py                  # end-to-end demo on the real implementation
python benchmarks/run_simulation.py          # seeded synthetic benchmark (runs twice, checks reproducibility)
scripts/verify.sh                            # everything above + wheel build + installed-CLI smoke test
```

## Quick CLI tour
```bash
cd my-python-project
vep init                                         # .vep/ state + Ed25519 key (key id printed; secret never shown)
vep budget create --account org --kind organization --limit 10
vep objective create --title "keep tests green"  # snapshots, freezes policy + required tests
vep budget create --account objective:<obj-id> --kind objective --limit 1.00 --parent org
vep candidate create --objective <obj-id> --author agent-1
vep evaluate --candidate <cand-id> --trusted-local-execution   # runs candidate code WITHOUT isolation
vep certify  --candidate <cand-id>
vep verify   --certificate <cert-id>             # fails if the live source differs; --historical to skip
vep route --models-file models.json --task-file task.json
vep cache --prefix-tokens 10000 --input-price 3 --output-price 15 --write-multiplier 1.25 --read-multiplier 0.1 --reuses 5
vep simulate --tasks 20000 --seed 20261019
vep isolation probe          # reports ISOLATION_UNVERIFIED when Docker/gVisor are unavailable
```
Every subcommand has `--help` and `--json`. Exit codes are stable (`docs/VARIABLES.md`, "CLI and process").

## Layout
`src/vep/` implementation · `tests/` unittest/pytest suite (incl. failure matrix F01–F20) · `examples/` demo + sample policy · `docs/` RFC-0001, architecture, variable registry, invariants, threat model, evidence, benchmarks, status · `benchmarks/` simulation runner · `scripts/` registry generator and verification gate.

## Honest labels
IMPLEMENTED / TESTED / SIMULATED / DESIGNED / UNVERIFIED are tracked per capability in `docs/IMPLEMENTATION_STATUS.md`. Simulation numbers are illustrative assumptions, never measurements of real models. Apache-2.0.
