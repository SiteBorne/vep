import unittest
from decimal import Decimal as D

from vep import cache_planner as cp
from vep.errors import SchemaError


def inputs(**kw):
    base = dict(prefix_tokens=10000, suffix_tokens=500, output_tokens=1000, ordinary_input_price="3",
                output_price="15", cache_write_multiplier="1.25", cache_read_multiplier="0.1", expected_reuses=5)
    base.update(kw)
    return cp.CacheInputs.build(**base)


class CacheTests(unittest.TestCase):
    def test_break_even_closed_form(self):
        self.assertEqual(cp.break_even_requests(D("1.25"), D("0.1")), D("1.15") / D("0.9"))
        self.assertEqual(cp.break_even_requests(D("2"), D("0")), D("2"))

    def test_break_even_is_exact_threshold(self):
        w, r = D("1.25"), D("0.1")
        be = cp.break_even_requests(w, r)  # ~1.2778 -> 2 total requests wins, 1 does not
        cached = lambda n: w + (n - 1) * r
        self.assertGreaterEqual(cached(1), 1)
        self.assertLess(cached(2), 2)
        self.assertTrue(1 < be < 2)
        # at exactly the threshold the totals are equal
        w2, r2 = D("2"), D("0")
        self.assertEqual(w2 + (cp.break_even_requests(w2, r2) - 1) * r2, cp.break_even_requests(w2, r2))

    def test_zero_denominator(self):
        self.assertIsNone(cp.break_even_requests(D("1.25"), D("1")))
        self.assertEqual(cp.break_even_requests(D("0.5"), D("1")), D("0"))

    def test_invalid_parameters(self):
        with self.assertRaises(SchemaError):
            cp.break_even_requests(D("-1"), D("0.1"))
        with self.assertRaises(SchemaError):
            cp.break_even_requests(D("1"), D("1.5"))
        for bad in (dict(prefix_tokens=-1), dict(cache_read_multiplier="1.5"), dict(estimated_hit_probability="1.2"),
                    dict(cache_write_multiplier="-1"), dict(ordinary_input_price=3.0), dict(expected_reuses=True)):
            with self.assertRaises(SchemaError, msg=str(bad)):
                inputs(**bad)

    def test_plan_includes_output_costs_and_matches_hand_calculation(self):
        p = cp.plan(inputs())
        pre, suf, out = D("10000") * 3 / 1_000_000, D("500") * 3 / 1_000_000, D("1000") * 15 / 1_000_000
        self.assertEqual(D(p["uncached_cost_usd"]), 6 * (pre + suf + out))
        self.assertEqual(D(p["cached_expected_cost_usd"]),
                         (D("1.25") * pre + suf + out) + 5 * (D("0.1") * pre + suf + out))
        self.assertEqual(p["recommendation"], "USE_CACHE")

    def test_single_request_does_not_pay_off(self):
        p = cp.plan(inputs(expected_reuses=0))
        self.assertEqual(p["recommendation"], "DO_NOT_CACHE")

    def test_lifetime_shorter_than_interval_disables_hits(self):
        p = cp.plan(inputs(cache_lifetime_s="300", request_interval_s="600"))
        self.assertEqual(p["effective_hit_probability"], "0")
        self.assertEqual(p["recommendation"], "DO_NOT_CACHE")
        self.assertTrue(any("lifetime" in n for n in p["notes"]))

    def test_hit_probability_shifts_break_even(self):
        perfect = cp.plan(inputs())
        weak = cp.plan(inputs(estimated_hit_probability="0.9"))
        self.assertLess(D(perfect["break_even_total_requests"]), D(weak["break_even_total_requests"]))

    def test_low_hit_probability_can_make_caching_never_pay(self):
        p = cp.plan(inputs(estimated_hit_probability="0.2"))  # effective reuse multiplier 1.02 > 1
        self.assertIsNone(p["break_even_total_requests"])
        self.assertEqual(p["recommendation"], "DO_NOT_CACHE")

    def test_never_beneficial_returns_no_break_even(self):
        p = cp.plan(inputs(cache_read_multiplier="1", cache_write_multiplier="1.25"))
        self.assertIsNone(p["break_even_total_requests"])
        self.assertEqual(p["recommendation"], "DO_NOT_CACHE")

    def test_makes_no_provider_control_claim(self):
        self.assertTrue(any("cannot control" in n for n in cp.plan(inputs())["notes"]))


if __name__ == "__main__":
    unittest.main()
