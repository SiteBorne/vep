# Quickstart

Ten minutes, no accounts, no network after installation. Steps 9-12 need a build of the current source: step 9 uses commands introduced in `0.5.0b1` (`vep run`, `vep jobs`), step 10 the authorized-verification flow and steps 11-12 the Claude Code installer and exact-input reuse, which are not in the published `0.5.0b1` wheel; the published `0.4.0a1` prerelease supports steps 1-8 only. Every ```` ```bash quickstart ```` block below is executed by the release gate (`scripts/release/quickstart_runner.py`) against the *installed* wheel, so these commands are tested, not illustrative.

> **Safety:** `vep evaluate` runs the project's code on your machine with your permissions and **no isolation**. Only evaluate code you already trust. See [SECURITY.md](../SECURITY.md).

## 1. Install
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install ./vep_protocol-0.5.0b1-py3-none-any.whl   # wheel from the GitHub release; verify it first (docs/RELEASE_PROVENANCE.md)
vep version
```
(There is no PyPI release; install the wheel from the GitHub prerelease or from `python -m build` in a checkout. See `docs/RELEASE_PROVENANCE.md` for verifying it first.)

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

## 9. Run through the durable controller (unreleased: needs a build of the current source)
`vep run` enqueues the candidate as an idempotent job, evaluates it with a lease and fencing token, and certifies it on PASS. Repeating it never certifies twice.
```bash quickstart
cd demo
OBJ=$(cat ../obj.txt)
cat >> calc.py <<'PY'

def mul(a, b):
    return a * b
PY
CAND2=$(vep candidate create --objective "$OBJ" --author me --field candidate_id)
vep run --candidate "$CAND2" --trusted-local-execution --json > ../run.json
python3 -c "import json; r = json.load(open('../run.json')); print(r['job']['state'], r['run']['candidate_status'])"
python3 -c "import json; print(json.load(open('../run.json'))['run']['certificate_id'])" > ../cert2.txt
vep jobs list --json | python3 -c "import json,sys; print(len(json.load(sys.stdin)), 'job(s) recorded')"
```

## 10. Check the certificate without VEP's database
A format-2 bundle contains only the two signed envelopes. It can be **authorized** only against a trust policy that *you*, the relying party, control: which issuer keys you trust, which evaluator identities you accept, the trust level you need and the exact source snapshot you expect. A bundle that carries its own keys proves internal consistency only, never who issued it. Verification needs only SHA-256, Ed25519 and a JSON parser; `conformance/node/verify.mjs` is a second implementation (see [CONFORMANCE.md](CONFORMANCE.md)).
```bash quickstart
cd demo
CAND2=$(python3 -c "import json; print(json.load(open('../run.json'))['run']['candidate_id'])")
SNAP=$(vep candidate show --id "$CAND2" --json | python3 -c "import json,sys; print(json.load(sys.stdin)['state']['snapshot_id'])")
vep conformance export --certificate "$(cat ../cert2.txt)" --out ../bundle.json --json
vep conformance trust-policy --snapshot "$SNAP" --require-trust TRUSTED_LOCAL --json > ../trust-policy.json
vep conformance verify --bundle ../bundle.json --trust-policy ../trust-policy.json --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --json
if vep conformance verify --bundle ../bundle.json 2>/dev/null; then echo "UNEXPECTED: verified without a trust policy"; exit 1; else echo "refused without a trust policy, as expected"; fi
```

## 11. Exact-input evidence reuse
If another candidate has *exactly* the same source, policy, runner, evaluator and environment as one that already has signed PASS evidence, VEP can issue a derived attestation that names the original proof instead of running the tests again. It is **not** a certificate and the candidate's status does not change ([EVIDENCE_REUSE.md](EVIDENCE_REUSE.md)). Any difference makes it refuse.
```bash quickstart
cd demo
OBJ=$(cat ../obj.txt)
CAND3=$(vep candidate create --objective "$OBJ" --author second-agent --field candidate_id)
vep reuse derive --candidate "$CAND3" --json
vep reuse export --candidate "$CAND3" --out ../bundle3.json --json
vep reuse verify --bundle ../bundle3.json --trust-policy ../trust-policy.json --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --json
echo "# a different tree" >> calc.py
CAND4=$(vep candidate create --objective "$OBJ" --author third-agent --field candidate_id)
if vep reuse derive --candidate "$CAND4"; then echo "UNEXPECTED: reused evidence for a changed tree"; exit 1; else echo "refused for a changed tree, as expected"; fi
```

## 12. Use VEP from Claude Code (MCP server, Skill, guard hook)
`vep claude install` writes a project `.mcp.json`, the `vep` Skill, a short `CLAUDE.md` block and a guard hook, with backups and conflict detection. Authority is chosen by you here, not by the agent. See [CLAUDE_INTEGRATION.md](CLAUDE_INTEGRATION.md) and [MCP.md](MCP.md); the server needs `pip install "vep-protocol[mcp]"`.
```bash quickstart
mkdir ccdemo
vep claude install --root ccdemo --dry-run --json > /dev/null
vep claude install --root ccdemo --json > /dev/null
vep claude status --root ccdemo --field installed
test -f ccdemo/.mcp.json && test -f ccdemo/.claude/skills/vep/SKILL.md
vep claude uninstall --root ccdemo --json > /dev/null
test ! -e ccdemo/.mcp.json
```
Then, in a project where it is installed, start `claude`, approve the project-scoped `vep` server when asked, and ask it to verify a change with VEP. To let an agent evaluate (running candidate code **unisolated on your machine**) use `vep claude install --allow-evaluate`. For A2A see [A2A.md](A2A.md).

## Next
* Run the test-suite: `pip install "vep-protocol[dev]" && python -m unittest discover -s tests -t .` from a source checkout.
* Understand the guarantees and limits: [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md).
* Protocol details: [RFC-0001.md](RFC-0001.md); compatibility promises: [COMPATIBILITY.md](COMPATIBILITY.md).
