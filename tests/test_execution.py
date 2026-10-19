import json
import os
import unittest
from decimal import Decimal

from vep import budgets, candidates, certificates, execution
from vep.errors import (AuthorizationError, BudgetError, FalseGreen, IsolationUnavailable, StateError)
from tests.helpers import AUTH, BASE_FILES, VepTestCase


def report(**kw):
    base = {"kind": "unittest", "discovered": 0, "run": 0, "passed": [], "failed": [], "errors": [],
            "skipped": [], "expected_failures": [], "unexpected_successes": []}
    base.update(kw)
    return base


class ReportValidationTests(VepTestCase):
    """validate_report is exercised with crafted reports; these are labeled test inputs, not results."""
    def setUp(self):
        super().setUp()
        self.policy = self.env().policy

    def test_zero_tests_rejected_even_with_exit_zero(self):
        with self.assertRaisesRegex(FalseGreen, "ZERO_TESTS"):
            execution.validate_report(report(), self.policy, 0)

    def test_all_skipped_rejected(self):
        with self.assertRaisesRegex(FalseGreen, "ALL_SKIPPED"):
            execution.validate_report(report(discovered=2, run=2, skipped=["test_arithmetic.T.a", "test_arithmetic.T.b"]),
                                      self.policy, 0)

    def test_exit_zero_with_failures_is_inconsistent(self):
        with self.assertRaisesRegex(FalseGreen, "EXIT_REPORT_MISMATCH"):
            execution.validate_report(report(discovered=2, run=2, passed=["test_arithmetic.T.a"],
                                             failed=["test_arithmetic.T.b"]), self.policy, 0)

    def test_required_suite_must_actually_run(self):
        with self.assertRaisesRegex(FalseGreen, "REQUIRED_SUITE_NOT_EXECUTED"):
            execution.validate_report(report(discovered=1, run=1, passed=["test_other.T.a"]), self.policy, 0)

    def test_required_suite_all_skipped_even_if_others_pass(self):
        with self.assertRaisesRegex(FalseGreen, "REQUIRED_SUITE_ALL_SKIPPED"):
            execution.validate_report(report(discovered=2, run=2, passed=["test_other.T.a"],
                                             skipped=["test_arithmetic.T.a"]), self.policy, 0)

    def test_count_inconsistency_rejected(self):
        with self.assertRaisesRegex(FalseGreen, "REPORT_INCONSISTENT"):
            execution.validate_report(report(discovered=5, run=5, passed=["test_arithmetic.T.a"]), self.policy, 0)

    def test_pass_and_fail_verdicts(self):
        ok = report(discovered=2, run=2, passed=["test_arithmetic.T.a", "test_arithmetic.T.b"])
        self.assertEqual(execution.validate_report(ok, self.policy, 0)[0], "PASS")
        bad = report(discovered=2, run=2, passed=["test_arithmetic.T.a"], failed=["test_arithmetic.T.b"])
        self.assertEqual(execution.validate_report(bad, self.policy, 1)[0], "FAIL")

    def test_nonzero_exit_without_reported_failures_is_not_pass(self):
        ok = report(discovered=2, run=2, passed=["test_arithmetic.T.a", "test_arithmetic.T.b"])
        self.assertEqual(execution.validate_report(ok, self.policy, 1)[0], "FAIL")

    def test_malformed_report_files(self):
        p = self.tmp / "r.json"
        for content in ("", "{", "[]", '{"kind":"unittest"}', '{"kind":"unittest","run":1.5}'):
            p.write_text(content)
            with self.assertRaises(FalseGreen, msg=content):
                execution.parse_unittest_report(p)
        with self.assertRaises(FalseGreen):
            execution.parse_unittest_report(self.tmp / "absent.json")

    def test_test_ordering_by_failure_probability_per_cost(self):
        order = execution.order_tests([("slow_flaky", Decimal(10), Decimal("0.5")),
                                       ("fast_flaky", Decimal(1), Decimal("0.3")),
                                       ("fast_solid", Decimal(1), Decimal("0.01"))])
        self.assertEqual(order, ["fast_flaky", "slow_flaky", "fast_solid"])


class EvaluationTests(VepTestCase):
    def test_pass_end_to_end_with_real_subprocess(self):
        e = self.env()
        cid = e.candidate({"extra.py": "X = 1\n"})
        r = e.evaluate(cid)
        self.assertEqual((r["status"], r["verdict"]), ("EVIDENCE_READY", "PASS"))
        self.assertEqual(r["counts"], {"discovered": 2, "run": 2, "passed": 2, "failed": 0, "skipped": 0})
        self.assertIn("no security isolation", r["isolation"])
        cert = certificates.certify(e.ws, cid)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "CERTIFIED")
        self.assertTrue(certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir))

    def test_failing_tests_yield_signed_fail_evidence_and_rejection(self):
        e = self.env()
        cid = e.candidate({"arithmetic.py": "def add(a, b):\n    return 0\n"})
        r = e.evaluate(cid)
        self.assertEqual((r["status"], r["verdict"]), ("REJECTED", "FAIL"))
        with self.assertRaises(StateError):
            certificates.certify(e.ws, cid)

    def test_authorization_required_before_any_state_change(self):
        e = self.env()
        cid = e.candidate()
        for auth in (None, "yes", "true", AUTH.lower()):
            with self.assertRaises(AuthorizationError):
                e.evaluate(cid, trusted_local_authorization=auth)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")

    def test_isolated_mode_fails_closed_and_never_runs_on_host(self):
        e = self.env()
        cid = e.candidate()
        with self.assertRaises(IsolationUnavailable):
            e.evaluate(cid, mode="isolated")
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")

    def test_all_skipped_candidate_cannot_certify(self):
        e = self.env()
        cid = e.candidate({"arithmetic.py": "import unittest\nraise unittest.SkipTest('nope')\n"})
        r = e.evaluate(cid)
        self.assertEqual(r["status"], "REJECTED")
        self.assertIn("ALL_SKIPPED", r["reason"])
        with self.assertRaises(StateError):
            certificates.certify(e.ws, cid)

    def test_zero_test_suite_cannot_certify(self):
        files = dict(BASE_FILES)
        files["tests/test_arithmetic.py"] = (
            "import unittest\n\ndef load_tests(loader, tests, pattern):\n    return unittest.TestSuite()\n")
        e = self.env(files=files)
        cid = e.candidate()
        r = e.evaluate(cid)  # exit code 0, nothing ran
        self.assertEqual(r["status"], "REJECTED")
        self.assertIn("ZERO_TESTS", r["reason"])

    def test_timeout_is_rejected(self):
        e = self.env(limits={"timeout_s": 1})
        cid = e.candidate({"arithmetic.py": "import time\ntime.sleep(30)\n"})
        self.assertIn("TIMEOUT", e.evaluate(cid)["reason"])

    def test_duplicate_evaluation_does_not_double_spend(self):
        e = self.env()
        cid = e.candidate()
        e.evaluate(cid)
        with self.assertRaises(StateError):
            e.evaluate(cid)
        acct = f"objective:{e.objective.id}"
        self.assertEqual(budgets.report(e.ws, acct)["settled"], "0.001")

    def test_no_budget_account_blocks_execution(self):
        e = self.env(budget=None)
        cid = e.candidate()
        with self.assertRaises(BudgetError):
            e.evaluate(cid)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "POLICY_CHECKED")

    def test_insufficient_budget_blocks_execution(self):
        e = self.env(budget="0.0005")
        cid = e.candidate()
        with self.assertRaises(BudgetError):
            e.evaluate(cid)
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"], 0)

    def test_policy_violation_never_executes(self):
        e = self.env()
        cid = e.candidate({"conftest.py": "raise SystemExit(0)\n"})
        from vep.errors import PolicyViolation
        with self.assertRaises(PolicyViolation):
            e.evaluate(cid)
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"], 0)

    def test_pytest_evaluator_kind(self):
        files = dict(BASE_FILES)
        e = self.env(files=files, evaluator={"kind": "pytest", "targets": ["tests"], "import_roots": ["."], "min_tests": 2})
        cid = e.candidate({"extra.py": "X = 1\n"})
        r = e.evaluate(cid)
        self.assertEqual(r["verdict"], "PASS", r)
        self.assertEqual(r["counts"]["passed"], 2)

    def test_pytest_all_skipped_rejected(self):
        files = dict(BASE_FILES)
        e = self.env(files=files, evaluator={"kind": "pytest", "targets": ["tests"], "import_roots": ["."], "min_tests": 1})
        cid = e.candidate({"arithmetic.py": "import pytest\npytest.skip('x', allow_module_level=True)\n"})
        r = e.evaluate(cid)
        self.assertEqual(r["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
