# Quickstart

Ten minutes, no accounts, no network after installation. Every ```` ```bash quickstart ```` block below is executed by the release gate (`scripts/release/quickstart_runner.py`) against the *installed* wheel, so these commands are tested, not illustrative.

> **Safety:** `vep evaluate` runs the project's code on your machine with your permissions and **no isolation**. Only evaluate code you already trust. See [SECURITY.md](../SECURITY.md).

## 1. Install
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install vep-protocol==0.4.0a1   # or: pip install dist/vep_protocol-0.4.0a1-py3-none-any.whl
vep version
```
(Until a PyPI release exists, install the wheel from the GitHub prerelease or a local build; see `docs/RELEASE_PROVENANCE.md` for verifying it first.)

## 2. A tiny trusted project
```bash quickstart
mkdir demo && cd demo
cat > calc.py <<'PY'
def add(a, b):
    return a + b
PY
mkdir tests
cat > tests/test_calc.py <<'PY'
import unittest
from calc import add

class CalcTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_negative(self):
        self.assertEqual(add(-1, 1), 0)
PY
vep init
```

## 3. Objective: freeze the source and the acceptance policy
```bash quickstart
cd demo
OBJ=$(vep objective create --title "keep calc correct" --budget 1.00 --field objective_id)
echo "objective: $OBJ"
```
This snapshots the tree, freezes `tests/test_calc.py` by content digest as a *required* test, and opens a $1.00 budget for the objective.

## 4. Candidate: a change an agent (or you) proposes
```bash quickstart
cd demo
cat > calc.py <<'PY'
def add(a, b):
    return a + b

def sub(a, b):
    return a - b
PY
OBJ=$(vep objective list --json | python3 -c "import json,sys; print(json.load(sys.stdin)[0])")
CAND=$(vep candidate create --objective "$OBJ" --author me --field candidate_id)
echo "$CAND" > ../cand.txt
echo "$OBJ" > ../obj.txt
vep candidate check --id "$CAND"
```

## 5. Evaluate: denied by default, allowed only with explicit trust
```bash quickstart
cd demo
CAND=$(cat ../cand.txt)
if vep evaluate --candidate "$CAND"; then echo "UNEXPECTED: ran without authorization"; exit 1; else echo "denied as expected (exit $?)"; fi
vep evaluate --candidate "$CAND" --trusted-local-execution --json
```
The result is labeled `TRUSTED_LOCAL`: signed evidence that *you authorized running this code locally*, not evidence of hostile-code isolation.

## 6. Certify and verify
```bash quickstart
cd demo
CAND=$(cat ../cand.txt)
CERT=$(vep certify --candidate "$CAND" --field certificate_id)
echo "$CERT" > ../cert.txt
vep verify --certificate "$CERT"
```

## 7. Change the source: the certificate no longer applies to what is on disk
```bash quickstart
cd demo
CERT=$(cat ../cert.txt)
echo "# edited after certification" >> calc.py
if vep verify --certificate "$CERT"; then echo "UNEXPECTED: stale certificate verified"; exit 1; else echo "rejected as expected (exit $?)"; fi
vep verify --certificate "$CERT" --historical      # still true about the certified snapshot
vep verify --certificate "$CERT" --historical --require-trust ISOLATED_VERIFIED || echo "not isolation-verified (exit $?), as expected"
```

## 8. The offline economics tools
```bash quickstart
cd demo
cat > models.json <<'JSON'
[{"name": "small", "price_in_per_m": "0.25", "price_out_per_m": "1.25", "context_capacity": 100000,
  "capabilities": ["code"], "acceptance_estimate": "0.6", "success_lower_bound": "0.5", "latency_s": "2",
  "max_risk": "medium", "evidence_source": "supplied", "false_accept_upper": "0.01"},
 {"name": "large", "price_in_per_m": "3", "price_out_per_m": "15", "context_capacity": 200000,
  "capabilities": ["code"], "acceptance_estimate": "0.9", "success_lower_bound": "0.95", "latency_s": "8",
  "max_risk": "high", "evidence_source": "supplied"}]
JSON
cat > task.json <<'JSON'
{"input_tokens": 8000, "output_tokens": 1500, "required_capabilities": ["code"],
 "allowed_sources": ["supplied"], "min_success_lower_bound": "0.9"}
JSON
vep route --models-file models.json --task-file task.json --field decision
vep cache --prefix-tokens 10000 --input-price 3 --output-price 15 --write-multiplier 1.25 --read-multiplier 0.1 --reuses 5 --field recommendation
vep simulate --tasks 500 --seed 7 --field result_sha256
vep isolation probe --json || echo "isolation: UNVERIFIED on this machine (exit $?)"
```
The model numbers above are **made-up inputs** you must replace with your own measurements; VEP never calls a model.

## Next
* Run the test-suite: `pip install "vep-protocol[dev]" && python -m unittest discover -s tests -t .` from a source checkout.
* Understand the guarantees and limits: [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md).
* Protocol details: [RFC-0001.md](RFC-0001.md); compatibility promises: [COMPATIBILITY.md](COMPATIBILITY.md).
