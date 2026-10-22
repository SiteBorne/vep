"""The agent fast path keeps its three outcomes apart and never substitutes one for another."""
import os
import tempfile
import unittest
from pathlib import Path

from tests.helpers import AUTH, Env, VepTestCase
from vep import candidates, controller, fastpath, snapshots
from vep.errors import StateError

FILES = {"calc.py": "def add(a, b):\n    return a + b\n", "other.py": "X = 1\n",
         "tests/test_calc.py": "import unittest\nfrom calc import add\n\n\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n",
         "tests/test_other.py": "import unittest\nimport other\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.assertEqual(other.X, 1)\n"}


class FastPathTests(VepTestCase):
    def env(self):
        return Env(Path(tempfile.mkdtemp(dir=self.tmp)), files=dict(FILES))

    def test_fresh_issues_a_certificate_and_reuse_only_never_executes(self):
        e = self.env()
        a = e.candidate({"extra.py": "Y = 1\n"})
        self.assertEqual(fastpath.verify(e.ws, a, mode="reuse_only")["outcome"], "NO_REUSABLE_EVIDENCE")  # nothing to reuse yet, and nothing was run
        self.assertEqual(candidates.get_state(e.ws, a)["status"], "PROPOSED")
        r = fastpath.verify(e.ws, a, mode="fresh")
        self.assertEqual((r["outcome"], r["executed"]), ("FRESH_CERTIFICATE", True)); self.assertTrue(r["certificate_id"])
        b = e.candidate({"extra.py": "Y = 1\n"}, author="second")  # identical tree
        r = fastpath.verify(e.ws, b, mode="reuse_only")
        self.assertEqual((r["outcome"], r["executed"], r["certificate_id"]), ("DERIVED_ATTESTATION", False, None))
        self.assertIn("not a certificate", r["assurance"])
        self.assertEqual(candidates.get_state(e.ws, b)["status"], "PROPOSED")  # a derived attestation changes no candidate status

    def test_reuse_if_identical_reports_which_path_it_took(self):
        e = self.env()
        a = e.candidate({"extra.py": "Y = 1\n"})
        first = fastpath.verify(e.ws, a, mode="reuse_if_identical")
        self.assertEqual((first["outcome"], first["reuse_attempted"]), ("FRESH_CERTIFICATE", True))  # nothing reusable: declared fallback, reported as fresh
        b = e.candidate({"extra.py": "Y = 1\n"}, author="x")
        self.assertEqual(fastpath.verify(e.ws, b, mode="reuse_if_identical")["outcome"], "DERIVED_ATTESTATION")
        c = e.candidate({"extra.py": "Y = 2\n"})
        r = fastpath.verify(e.ws, c, mode="reuse_if_identical")
        self.assertEqual((r["outcome"], r["executed"]), ("FRESH_CERTIFICATE", True))  # changed source can only get a new certificate

    def test_failed_evidence_and_policy_violations_are_never_reused_or_softened(self):
        e = self.env()
        bad = e.candidate({"calc.py": "def add(a, b):\n    return 0\n"})
        self.assertEqual(fastpath.verify(e.ws, bad, mode="fresh")["outcome"], "REJECTED")
        twin = e.candidate({"calc.py": "def add(a, b):\n    return 0\n"})
        self.assertEqual(fastpath.verify(e.ws, twin, mode="reuse_only")["outcome"], "NO_REUSABLE_EVIDENCE")
        tamper = e.candidate({"tests/test_calc.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_add(self):\n        pass\n"})
        self.assertEqual(fastpath.verify(e.ws, tamper, mode="reuse_if_identical")["outcome"], "REJECTED")  # protected test edited

    def test_advisory_is_heuristic_changes_no_state_and_can_never_certify(self):
        e = self.env()
        base = snapshots.take_snapshot(e.ws)
        cid = e.candidate({"calc.py": "def add(a, b):\n    return a - b\n"})
        r = fastpath.verify(e.ws, cid, mode="advisory", root=e.last_dir, previous_snapshot_id=base.id)
        self.assertEqual((r["outcome"], r["certificate_id"], r["candidate_status"]), ("ADVISORY_FEEDBACK", None, "PROPOSED"))
        self.assertFalse(r["advisory_pass"]); self.assertIn("not evidence", r["assurance"])
        ok = e.candidate({"other.py": "X = 1\n# comment\n"})
        r2 = fastpath.verify(e.ws, ok, mode="advisory", root=e.last_dir, previous_snapshot_id=base.id)
        self.assertTrue(r2["advisory_pass"]); self.assertIsNone(r2["certificate_id"])
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"], 0)
        with self.assertRaises(ValueError):
            fastpath.verify(e.ws, cid, mode="advisory")
        with self.assertRaises(ValueError):
            fastpath.verify(e.ws, cid, mode="best_effort")


if __name__ == "__main__":
    unittest.main()
