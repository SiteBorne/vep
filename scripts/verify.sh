#!/usr/bin/env bash
# Final verification gate. Usage: scripts/verify.sh   (uses .venv if present)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
echo "== unit tests (unittest)";            $PY -m unittest discover -s tests -t . 
echo "== unit tests (pytest)";              $PY -m pytest -q
echo "== conformance suite (frozen + independent verifier)"; scripts/conformance_check.sh
echo "== registry up to date";              $PY scripts/gen_variables.py --check
echo "== demo";                             $PY examples/run_demo.py | tail -3
echo "== simulation reproducibility";       $PY benchmarks/run_simulation.py --out-json /dev/null --out-md /dev/null
echo "== build wheel + sdist";              rm -rf dist; $PY -m build >/dev/null; ls dist
echo "== installed CLI smoke test (fresh venv)"
T=$(mktemp -d); python3 -m venv "$T/v"; "$T/v/bin/pip" install -q dist/*.whl
"$T/v/bin/vep" --help >/dev/null; "$T/v/bin/vep" isolation probe --json >/dev/null || [ $? -eq 8 ]
"$T/v/bin/vep" simulate --tasks 200 --json >/dev/null
mkdir "$T/p"; (cd "$T/p" && "$T/v/bin/vep" init --json >/dev/null && "$T/v/bin/vep" status --json >/dev/null)
rm -rf "$T"; echo "ALL VERIFICATION STEPS PASSED"
