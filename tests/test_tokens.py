import unittest
from decimal import Decimal

from vep import budgets, tokens
from vep.errors import SchemaError
from tests.helpers import VepTestCase

PRICES = {"input": "3.00", "cached_input": "0.30", "cache_write": "3.75", "output": "15.00"}


class TokenTests(VepTestCase):
    def setUp(self):
        super().setUp()
        self.e = self.env(budget=None)
        self.ws = self.e.ws
        self.cid = self.e.candidate({"x.py": "X=1\n"})

    def receipt(self, **kw):
        base = dict(provider="local-test", model="m", pricing_version="p1", candidate_id=self.cid, attempt=0,
                    ordinary_input_tokens=1000, cached_input_tokens=2000, cache_write_tokens=500,
                    output_tokens=800, reasoning_tokens_in_output=300, prices_per_million=PRICES,
                    usage_source="simulated", idempotency_key="k1")
        base.update(kw)
        return tokens.make_receipt(**base)

    def test_cost_formula_exact(self):
        r = self.receipt(other_provider_charges="0.001")
        expected = (Decimal(1000) * 3 + Decimal(2000) * Decimal("0.30") + Decimal(500) * Decimal("3.75")
                    + Decimal(800) * 15) / 1_000_000 + Decimal("0.001")
        self.assertEqual(Decimal(r["cost_usd"]), expected)

    def test_reasoning_tokens_not_double_counted(self):
        a = self.receipt(reasoning_tokens_in_output=0)
        b = self.receipt(reasoning_tokens_in_output=800)
        self.assertEqual(a["cost_usd"], b["cost_usd"])

    def test_reasoning_exceeding_output_rejected(self):
        with self.assertRaises(SchemaError):
            self.receipt(reasoning_tokens_in_output=801)

    def test_usage_source_is_mandatory_and_validated(self):
        with self.assertRaises(SchemaError):
            self.receipt(usage_source=None)
        with self.assertRaises(SchemaError):
            self.receipt(usage_source="trust-me")

    def test_negative_floats_and_bad_prices_rejected(self):
        with self.assertRaises(SchemaError):
            self.receipt(output_tokens=-1)
        with self.assertRaises(SchemaError):
            self.receipt(prices_per_million={**PRICES, "output": 15.0})
        with self.assertRaises(SchemaError):
            self.receipt(other_provider_charges="-1")

    def test_receipt_records_pricing_and_source(self):
        r = self.receipt()
        self.assertEqual(r["pricing_version"], "p1")
        self.assertEqual(r["prices_per_million"], PRICES)
        self.assertEqual(r["usage_source"], "simulated")

    def test_record_is_idempotent_and_settles_once(self):
        budgets.create_account(self.ws, "cand", "candidate", "1.00")
        budgets.reserve(self.ws, "cand", "0.10", "res")
        r = self.receipt()
        first = tokens.record_receipt(self.ws, r, "res")
        second = tokens.record_receipt(self.ws, r, "res")
        self.assertFalse(first["duplicate"]); self.assertTrue(second["duplicate"])
        self.assertEqual(tokens.totals(self.ws, self.cid)["receipts"], 1)
        self.assertEqual(budgets.report(self.ws, "cand")["settled"], str(Decimal(r["cost_usd"])))

    def test_idempotency_key_reuse_with_different_receipt_rejected(self):
        tokens.record_receipt(self.ws, self.receipt())
        with self.assertRaises(SchemaError):
            tokens.record_receipt(self.ws, self.receipt(output_tokens=1))

    def test_cost_above_reservation_is_recorded_as_overrun(self):
        budgets.create_account(self.ws, "cand", "candidate", "1.00")
        budgets.reserve(self.ws, "cand", "0.001", "res")
        tokens.record_receipt(self.ws, self.receipt(), "res")
        self.assertNotEqual(budgets.report(self.ws, "cand")["overrun"], "0")


if __name__ == "__main__":
    unittest.main()
