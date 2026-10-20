"""Public numbers must trace to reports (scripts/check_claims.py)."""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ClaimsTests(unittest.TestCase):
    def test_every_tagged_figure_matches_its_report_and_none_is_untagged(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_claims.py")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_drifted_claim_is_detected(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_claims
        claim = {"id": "x", "text": "99%", "expr": "a", "vars": {"a": {"file": "docs/claims.json", "path": [0, "id"], "len": True}}, "fmt": "{}%"}
        self.assertNotEqual(check_claims.evaluate(claim), claim["text"])
