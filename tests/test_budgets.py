import threading
import unittest
from decimal import Decimal

from vep import budgets
from vep.errors import BudgetError
from tests.helpers import VepTestCase


class BudgetTests(VepTestCase):
    def setUp(self):
        super().setUp()
        self.e = self.env(budget=None)
        self.ws = self.e.ws
        budgets.create_account(self.ws, "org", "organization", "10")
        budgets.create_account(self.ws, "obj", "objective", "1.00", "org")
        budgets.create_account(self.ws, "cand", "candidate", "0.50", "obj")

    def test_reserve_settle_release_cycle(self):
        budgets.reserve(self.ws, "cand", "0.20", "k1")
        self.assertEqual(budgets.available(self.ws, "cand"), Decimal("0.30"))
        budgets.settle(self.ws, "k1", "0.15", "s1")
        self.assertEqual(budgets.available(self.ws, "cand"), Decimal("0.35"))
        budgets.reserve(self.ws, "cand", "0.10", "k2")
        budgets.release(self.ws, "k2")
        self.assertEqual(budgets.available(self.ws, "cand"), Decimal("0.35"))
        self.assertEqual([h["event"] for h in budgets.history(self.ws, "cand")],
                         ["ACCOUNT_CREATED", "RESERVE", "SETTLE", "RESERVE", "RELEASE"])

    def test_hierarchy_limits_apply_to_every_ancestor(self):
        budgets.create_account(self.ws, "cand2", "candidate", "0.90", "obj")
        budgets.reserve(self.ws, "cand", "0.50", "a")
        with self.assertRaises(BudgetError):
            budgets.reserve(self.ws, "cand2", "0.60", "b")  # objective has only 0.50 left
        budgets.reserve(self.ws, "cand2", "0.50", "c")
        self.assertEqual(budgets.available(self.ws, "obj"), Decimal("0"))

    def test_child_cannot_outrank_parent(self):
        with self.assertRaises(BudgetError):
            budgets.create_account(self.ws, "bad", "organization", "1", "cand")

    def test_concurrent_reservations_cannot_oversubscribe(self):
        results = []

        def worker(i):
            try:
                budgets.reserve(self.ws, "obj", "0.10", f"c-{i}")
                results.append(True)
            except BudgetError:
                results.append(False)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(sum(results), 10)
        self.assertEqual(budgets.available(self.ws, "obj"), Decimal("0"))

    def test_reservation_is_idempotent_and_conflicts_fail(self):
        a = budgets.reserve(self.ws, "cand", "0.10", "same")
        b = budgets.reserve(self.ws, "cand", "0.10", "same")
        self.assertEqual(a, b)
        self.assertEqual(budgets.available(self.ws, "cand"), Decimal("0.40"))  # not charged twice
        with self.assertRaises(BudgetError):
            budgets.reserve(self.ws, "cand", "0.20", "same")

    def test_identical_settlement_is_idempotent(self):
        budgets.reserve(self.ws, "cand", "0.10", "r")
        budgets.settle(self.ws, "r", "0.08", "s")
        budgets.settle(self.ws, "r", "0.08", "s")
        self.assertEqual(budgets.report(self.ws, "cand")["settled"], "0.08")
        self.assertEqual(sum(1 for h in budgets.history(self.ws, "cand") if h["event"] == "SETTLE"), 1)

    def test_conflicting_settlement_rejected(self):
        budgets.reserve(self.ws, "cand", "0.10", "r")
        budgets.settle(self.ws, "r", "0.08", "s")
        with self.assertRaises(BudgetError):
            budgets.settle(self.ws, "r", "0.09", "s")
        with self.assertRaises(BudgetError):
            budgets.settle(self.ws, "r", "0.08", "other-key")

    def test_overrun_is_recorded_and_blocks_new_work(self):
        budgets.reserve(self.ws, "cand", "0.30", "r")
        budgets.settle(self.ws, "r", "0.60", "s")
        rep = budgets.report(self.ws, "cand")
        self.assertEqual((rep["settled"], rep["overrun"], rep["overspent"]), ("0.6", "0.3", True))
        self.assertEqual(rep["available"], "0")
        with self.assertRaises(BudgetError):
            budgets.reserve(self.ws, "cand", "0.000001", "next")
        self.assertIn("OVERRUN", [h["event"] for h in budgets.history(self.ws, "cand")])

    def test_exhausted_budget_authorizes_nothing(self):
        budgets.reserve(self.ws, "cand", "0.50", "all")
        with self.assertRaises(BudgetError):
            budgets.reserve(self.ws, "cand", "0.01", "more")

    def test_uncertain_operations_hold_funds_until_resolved(self):
        budgets.reserve(self.ws, "cand", "0.20", "u")
        budgets.mark_uncertain(self.ws, "u")
        rep = budgets.report(self.ws, "cand")
        self.assertEqual((rep["uncertain"], rep["reserved"], rep["available"]), ("0.2", "0", "0.3"))
        budgets.settle(self.ws, "u", "0.05", "s")
        self.assertEqual(budgets.report(self.ws, "cand")["uncertain"], "0")

    def test_released_or_settled_states_are_final(self):
        budgets.reserve(self.ws, "cand", "0.10", "r")
        budgets.release(self.ws, "r")
        with self.assertRaises(BudgetError):
            budgets.settle(self.ws, "r", "0.05", "s")
        budgets.reserve(self.ws, "cand", "0.10", "r2")
        budgets.settle(self.ws, "r2", "0.05", "s")
        with self.assertRaises(BudgetError):
            budgets.release(self.ws, "r2")

    def test_money_validation(self):
        for bad in (0.1, "abc", "NaN", "Infinity", "0.0000001", "-1", "0"):
            with self.assertRaises(BudgetError, msg=str(bad)):
                budgets.reserve(self.ws, "cand", bad, "bad")

    def test_transaction_rollback_on_failure(self):
        with self.assertRaises(RuntimeError):
            with self.ws.db.tx() as c:
                budgets.reserve(self.ws, "cand", "0.10", "rb", conn=c)
                raise RuntimeError("boom")
        self.assertIsNone(budgets.get_reservation(self.ws, "rb"))
        self.assertEqual(budgets.available(self.ws, "cand"), Decimal("0.50"))

    def test_unknown_account_and_reservation(self):
        with self.assertRaises(BudgetError):
            budgets.reserve(self.ws, "nope", "1", "k")
        with self.assertRaises(BudgetError):
            budgets.settle(self.ws, "nope", "1", "s")

    def test_operation_budget_level(self):
        budgets.create_account(self.ws, "op", "operation", "0.05", "cand")
        budgets.reserve(self.ws, "op", "0.05", "o1")
        with self.assertRaises(BudgetError):
            budgets.reserve(self.ws, "op", "0.01", "o2")
        self.assertEqual(budgets.available(self.ws, "cand"), Decimal("0.45"))


if __name__ == "__main__":
    unittest.main()
