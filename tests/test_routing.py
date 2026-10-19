import unittest
from decimal import Decimal

from vep import routing
from vep.errors import SchemaError


def model(name, pin, pout, **kw):
    d = dict(name=name, price_in_per_m=pin, price_out_per_m=pout, context_capacity=100000,
             capabilities=["code"], acceptance_estimate="0.7", success_lower_bound="0.95",
             latency_s="10", max_risk="high", evidence_source="measured", verification_cost="0")
    d.update(kw)
    return routing.ModelOption.from_dict(d)


TASK = routing.Task.from_dict({"input_tokens": 10000, "output_tokens": 2000, "required_capabilities": ["code"]})


class RoutingTests(unittest.TestCase):
    def test_cascade_formula_exact(self):
        self.assertEqual(routing.cascade_expected_cost(Decimal("1"), Decimal("0.6"), Decimal("10")), Decimal("5.0"))
        self.assertEqual(routing.cascade_expected_cost(Decimal("1"), Decimal("1"), Decimal("10")), Decimal("1"))
        self.assertEqual(routing.cascade_expected_cost(Decimal("1"), Decimal("0"), Decimal("10")), Decimal("11"))

    def test_cheapest_eligible_single_selected(self):
        r = routing.select([model("a", "3", "15"), model("b", "1", "5")], TASK)
        self.assertEqual(r["selected"]["models"], ["b"])

    def test_quality_constraint_excludes_cheap_model(self):
        r = routing.select([model("a", "3", "15"), model("b", "0.1", "0.5", success_lower_bound="0.5")], TASK)
        self.assertEqual(r["selected"]["models"], ["a"])
        self.assertIn("b[single]", r["rejected"])

    def test_cascade_requires_measured_false_accept_bound(self):
        cheap = model("cheap", "0.1", "0.5", success_lower_bound="0.5")
        strong = model("strong", "3", "15")
        r = routing.select([cheap, strong], TASK)
        self.assertEqual(r["selected"]["kind"], "single")
        self.assertIn("unmeasured", r["rejected"]["cheap->strong[cascade]"][0])

    def test_cascade_selected_when_measured_and_cheaper(self):
        cheap = model("cheap", "0.1", "0.5", success_lower_bound="0.5", false_accept_upper="0.001")
        strong = model("strong", "3", "15")
        r = routing.select([cheap, strong], TASK)
        self.assertEqual(r["selected"]["kind"], "cascade")
        cc = routing.attempt_cost(cheap, TASK); cs = routing.attempt_cost(strong, TASK)
        self.assertEqual(Decimal(r["selected"]["expected_cost_usd"]), cc + Decimal("0.3") * cs)

    def test_cascade_rejected_when_false_accept_too_high(self):
        cheap = model("cheap", "0.1", "0.5", success_lower_bound="0.5", false_accept_upper="0.2")
        r = routing.select([cheap, model("strong", "3", "15")], TASK)
        self.assertEqual(r["selected"]["kind"], "single")

    def test_verification_cost_included(self):
        cheap = model("cheap", "0.1", "0.5", success_lower_bound="0.5", false_accept_upper="0.001", verification_cost="1000")
        r = routing.select([cheap, model("strong", "3", "15")], TASK)
        self.assertEqual(r["selected"]["kind"], "single")

    def test_ineligibility_reasons(self):
        t = routing.Task.from_dict({"input_tokens": 90000, "output_tokens": 20000, "required_capabilities": ["code", "vision"],
                                    "risk": "high", "max_latency_s": "5"})
        m = model("a", "1", "1", max_risk="low")
        why = routing.ineligible_reasons(m, t)
        self.assertEqual(len(why), 4)
        r = routing.select([m], t)
        self.assertEqual((r["decision"], r["selected"]), ("ABSTAIN", None))

    def test_unmeasured_sources_excluded_by_default(self):
        r = routing.select([model("sim", "1", "1", evidence_source="simulated")], TASK)
        self.assertEqual(r["decision"], "ABSTAIN")
        t2 = routing.Task.from_dict({"input_tokens": 1, "output_tokens": 1, "allowed_sources": ["measured", "simulated"]})
        self.assertEqual(routing.select([model("sim", "1", "1", evidence_source="simulated")], t2)["decision"], "SELECTED")

    def test_budget_eligibility_uses_worst_case(self):
        cheap = model("cheap", "0.1", "0.5", success_lower_bound="0.5", false_accept_upper="0.001")
        strong = model("strong", "3", "15")
        t = routing.Task.from_dict({"input_tokens": 10000, "output_tokens": 2000, "required_capabilities": ["code"],
                                    "budget_available": format(routing.attempt_cost(strong, TASK), "f")})
        r = routing.select([cheap, strong], t)
        self.assertEqual(r["selected"]["kind"], "single")  # cascade worst case exceeds the budget

    def test_deterministic_ties(self):
        a = routing.select([model("b", "1", "1"), model("a", "1", "1")], TASK)
        b = routing.select([model("a", "1", "1"), model("b", "1", "1")], TASK)
        self.assertEqual(a, b)
        self.assertEqual(a["selected"]["models"], ["a"])

    def test_invalid_inputs(self):
        for bad in ({"acceptance_estimate": "1.5"}, {"acceptance_estimate": 0.5}, {"max_risk": "none"},
                    {"evidence_source": "vibes"}, {"price_in_per_m": "-1"}):
            with self.assertRaises(SchemaError, msg=str(bad)):
                model("x", "1", "1", **bad)
        with self.assertRaises(SchemaError):
            routing.ModelOption.from_dict({"name": "x"})


if __name__ == "__main__":
    unittest.main()
