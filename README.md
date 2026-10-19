# VEP — Verified Evolution Protocol

**Version 0.4.0a1 — initial public developer preview (prerelease).** A local reference implementation of an agent-native, evidence-oriented software development protocol. Apache-2.0. No accounts, no network, no paid services.

> **Read this first.** VEP's only exercised execution mode, `TRUSTED_LOCAL`, runs a project's code on your machine **with your permissions and no isolation**, and only after you pass `--trusted-local-execution`. Use it for code you already trust. Verified isolation for untrusted code (`ISOLATED_VERIFIED`) is implemented as an optional adapter but is **UNVERIFIED** — it has not been run against a real Docker + gVisor runtime — so VEP makes no claim about evaluating untrusted code. Details: [SECURITY_ARCHITECTURE](docs/SECURITY_ARCHITECTURE.md).

## What VEP is
A Python package and CLI (`vep`) that turns "an agent changed some code" into a checkable record: an **objective** bound to an exact **snapshot** of the source and a frozen acceptance policy; a **candidate** change; a protected **evaluation**; signed **evidence**; and a **certificate** that is valid for exactly that source, policy and trust level. It also ships offline tools for token accounting, transactional budgets, model-routing economics and prompt-cache break-even analysis, plus a seeded simulator.

## What it is not
* Not a replacement for Git (it reads Git state, read-only, and never commits, pushes or merges).
* Not a production CI hosting service; it is a single-machine reference implementation.
* Not a safe untrusted-code execution platform by default.
* Not a live model-provider service: it never calls a model, and all model numbers are inputs you supply.
* Not a guarantee of software correctness: a certificate says *these tests passed against this exact source under this policy and trust level*.

## Why it exists
Agents burn compute producing changes that humans then re-check. VEP's premise is that a change is only a *proposal*; the valuable output is a **verified improvement** that carries explicit evidence, so unnecessary computation and re-verification can be avoided while rules that matter (no false greens, no stale certificates, no budget bypass) are enforced by code, schemas and database triggers rather than by instructions.

## How it works
```
Objective ─► Snapshot ─► Candidate ─► Evaluation ─► Evidence ─► Certificate
 (policy      (content-    (proposed     (protected,   (signed,     (signed; bound to snapshot,
  + budget)    addressed)   change)       budgeted)     trust-       policy, objective, evaluator
                                                        labelled)    and trust level)
```
Identities are domain-separated SHA-256 over canonical JSON. Candidates move through a SQLite-enforced state machine (`PROPOSED → POLICY_CHECKED → BUDGET_RESERVED → EVALUATING → EVIDENCE_READY → CERTIFIED | REJECTED`) and cannot certify themselves. Full specification: [RFC-0001](docs/RFC-0001.md); architecture: [ARCHITECTURE](docs/ARCHITECTURE.md).

## Install (Python ≥ 3.11, Linux or macOS)
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install ./dist/vep_protocol-0.4.0a1-py3-none-any.whl     # wheel from the GitHub prerelease (verify it first: docs/RELEASE_PROVENANCE.md)
vep version
```
From a checkout: `pip install -e ".[dev]"`. A PyPI release is **not** published yet; the distribution name is `vep-protocol`.

## Run (a complete minimal example)
The commands below are executed against the installed wheel by the release gate ([docs/QUICKSTART.md](docs/QUICKSTART.md) has the full, tested walkthrough).
```bash
mkdir demo && cd demo && mkdir tests
printf 'def add(a, b):\n    return a + b\n' > calc.py
printf 'import unittest\nfrom calc import add\n\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n' > tests/test_calc.py
vep init
OBJ=$(vep objective create --title "keep calc correct" --budget 1.00 --field objective_id)
printf '\ndef sub(a, b):\n    return a - b\n' >> calc.py                  # the "agent's" change
CAND=$(vep candidate create --objective "$OBJ" --field candidate_id)
vep evaluate --candidate "$CAND"                                         # refused: exit 7, no authorization
vep evaluate --candidate "$CAND" --trusted-local-execution               # runs YOUR trusted code, unisolated
CERT=$(vep certify --candidate "$CAND" --field certificate_id)
```

## Verify
```text
$ vep verify --certificate "$CERT"
{
  "checks_passed": ["certificate signature", "evidence signature", "evidence binding",
                    "candidate/objective/policy binding", "current source equals certified snapshot"],
  "evaluator_id": "vep-local-evaluator/0.4.0a1/TRUSTED_LOCAL",
  "legacy_schema": false,
  "mode": "current-source",
  "required_trust": "TRUSTED_LOCAL",
  "trust_level": "TRUSTED_LOCAL", ...
}
$ echo "# edit" >> calc.py && vep verify --certificate "$CERT"; echo $?
vep: VerificationFailed: SOURCE_CHANGED: current tree snap-7d9c… != certified snap-2895…
4
```
`--historical` checks the certificate without requiring the live tree to match; `--require-trust ISOLATED_VERIFIED` makes a trusted-local certificate fail (exit 4).

## Test
```bash
pip install -e ".[dev]"
python -m unittest discover -s tests -t .      # standard-library baseline
python -m pytest -q                            # same suite under pytest
scripts/release_check.sh                       # full release qualification (builds, installs, clean-room test, scans)
```

## Use it safely
* `TRUSTED_LOCAL` = *you* authorized running *trusted* code here. The signature proves who signed; it does not prove the code was harmless or the evaluation independent.
* Never evaluate code you would not run directly on your machine. Evaluated code can read your files, including `.vep/keys/signing.pem`, and anything it prints is stored in the CAS.
* Policies can require isolation (`required_trust: ISOLATED_VERIFIED`); VEP then refuses to run locally and never downgrades.
* Optional isolation: `vep isolation detect`, `vep isolation verify --image <name@sha256:…> --out att.json`, `vep evaluate --isolated --image … --attestation-file att.json`. Needs a Linux Docker daemon with gVisor (`runsc`) registered and a local digest-pinned Python image. On a machine without them every command reports `ISOLATION_UNVERIFIED` (exit 8) and nothing runs.

## Documentation map
[QUICKSTART](docs/QUICKSTART.md) · [ARCHITECTURE](docs/ARCHITECTURE.md) · [RFC-0001](docs/RFC-0001.md) · [COMPATIBILITY](docs/COMPATIBILITY.md) · [MIGRATIONS](docs/MIGRATIONS.md) · [SECURITY_ARCHITECTURE](docs/SECURITY_ARCHITECTURE.md) · [THREAT_MODEL](docs/THREAT_MODEL.md) · [SECURITY_REVIEW](docs/SECURITY_REVIEW.md) · [INVARIANTS](docs/INVARIANTS.md) · [VARIABLES](docs/VARIABLES.md) · [EVIDENCE](docs/EVIDENCE.md) · [BENCHMARKS](docs/BENCHMARKS.md) · [IMPLEMENTATION_STATUS](docs/IMPLEMENTATION_STATUS.md) · [RELEASE_NOTES](docs/RELEASE_NOTES.md) · [RELEASE_PROVENANCE](docs/RELEASE_PROVENANCE.md)

## Contribute
See [CONTRIBUTING.md](CONTRIBUTING.md): fork, `pip install -e ".[dev]"`, add a focused test for every behavior change, run the suite and `scripts/release_check.sh --skip-matrix`, open a pull request. Be kind: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Report a security problem
**Do not open a public issue.** Follow [SECURITY.md](SECURITY.md) (private vulnerability reporting).

## License
Apache-2.0 — see [LICENSE](LICENSE).
