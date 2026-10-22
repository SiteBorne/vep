#!/usr/bin/env bash
# Frozen-suite check: regenerates vectors (must be byte-identical), runs the reference verifier and, if node is
# present, the independent verifier. A missing node is reported as NOT RUN and exits 3 (never a silent pass).
set -euo pipefail
cd "$(dirname "$0")/.."
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
SUITE=conformance/vectors/suite-1.2.json
$PY scripts/gen_conformance_vectors.py --check && echo "suite 1.0 frozen: regenerates identically"
$PY scripts/gen_conformance_vectors_11.py --check && echo "suite 1.1 frozen: regenerates identically"
$PY scripts/gen_conformance_vectors_12.py --check && echo "suite 1.2 frozen: regenerates identically"
$PY -m vep.cli conformance vectors --suite "$SUITE" --json | tail -6
if command -v node >/dev/null; then
  node conformance/node/verify.mjs suite conformance/vectors/suite-1.0.json
  node conformance/node/verify.mjs suite conformance/vectors/suite-1.1.json
  node conformance/node/verify.mjs suite "$SUITE"
else
  echo "INDEPENDENT_VERIFIER: NOT RUN (node not installed)"; exit 3
fi
