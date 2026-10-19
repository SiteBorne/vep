#!/usr/bin/env bash
# Single release qualification command. Exit 0 iff every REQUIRED gate passes (decision GO).
# Usage: scripts/release_check.sh [--skip-matrix]
set -uo pipefail
cd "$(dirname "$0")/.."
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
exec "$PY" scripts/release/release_gate.py "$@"
