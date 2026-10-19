import unittest
from dataclasses import replace
from decimal import Decimal as D

from vep import simulation as sim
from vep.errors import SchemaError


class MathTests(unittest.TestCase):
    def test_expected_retry_cost_geometric(self):
        self.assertEqual(sim.expected_retry_cost(D("2"), D("0.5")), D("4"))
        self.assertEqual(sim.expected_attempts(D("0.25")), D("4"))
        # bounded k=2, p=0.5: 2*(1-0.25)/0.5 = 3
        self.assertEqual(sim.expected_retry_cost(D("2"), D("0.5"), 2), D("3"))
        with self.assertRaises(SchemaError):
            sim.expected_retry_cost(D("1"), D("0"))

    def test_geometric_formula_matches_simulation(self):
        import random
        rng = random.Random(7)
        p, n = 0.4, 60000
        attempts = 0
        for _ in range(n):
            a = 1
            while rng.random() >= p:
                a += 1
            attempts += a
        self.assertAlmostEqual(attempts / n, 1 / p, delta=0.05)

    def test_littles_law(self):
        self.assertEqual(sim.littles_law(arrival_rate=D("2"), wait=D("30")), D("60"))
        self.assertEqual(sim.littles_law(arrival_rate=D("2"), in_system=D("60")), D("30"))
        self.assertEqual(sim.littles_law(wait=D("30"), in_system=D("60")), D("2"))
        with self.assertRaises(SchemaError):
            sim.littles_law(arrival_rate=D("2"))

    def test_throughput_bound(self):
        self.assertEqual(sim.max_throughput(4, D("2")), D("2"))
        with self.assertRaises(SchemaError):
            sim.max_throughput(0, D("2"))

    def test_benjamini_hochberg_known_example(self):
        # classic textbook example: m=5, q=0.05 -> reject the two smallest
        p = [0.001, 0.008, 0.039, 0.041, 0.6]
        self.assertEqual(sim.benjamini_hochberg(p, 0.05), [0, 1])
        self.assertEqual(sim.benjamini_hochberg([0.9, 0.8], 0.05), [])
        self.assertEqual(sim.benjamini_hochberg([0.01, 0.011, 0.012], 0.05), [0, 1, 2])

    def test_false_acceptance_dependence(self):
        self.assertAlmostEqual(sim.false_acceptance_probability(0.1, 0.1, 0.0), 0.01)
        self.assertAlmostEqual(sim.false_acceptance_probability(0.1, 0.1, 1.0), 0.1)
        a, b = sim.false_acceptance_probability(0.1, 0.1, 0.3), sim.false_acceptance_probability(0.1, 0.1, 0.6)
        self.assertLess(a, b)


class SimulationTests(unittest.TestCase):
    P = sim.SimParams(n_tasks=3000)

    def test_same_seed_reproduces_exactly(self):
        self.assertEqual(sim.run_report(self.P, with_sensitivity=False), sim.run_report(self.P, with_sensitivity=False))

    def test_different_seed_differs(self):
        a = sim.run_strategies(self.P)
        b = sim.run_strategies(replace(self.P, seed=self.P.seed + 1))
        self.assertNotEqual(a, b)

    def test_accounting_identity(self):
        r = sim.run_strategies(self.P)
        for name, m in r.items():
            correct = round(D(m["correctly_accepted_fraction"]) * self.P.n_tasks)
            self.assertEqual(correct + m["incorrect_acceptances"] + m["unaccepted_tasks"], self.P.n_tasks, name)

    def test_perfect_verifier_has_no_incorrect_acceptances(self):
        r = sim.run_strategies(replace(self.P, verifier_fp=0.0, verifier_sensitivity=1.0))
        self.assertTrue(all(m["incorrect_acceptances"] == 0 for m in r.values()))

    def test_double_verification_dependence_monotone(self):
        indep = sim.run_strategies(replace(self.P, verifier_rho=0.0))["E_double_verified_cascade"]["incorrect_acceptances"]
        dep = sim.run_strategies(replace(self.P, verifier_rho=1.0))["E_double_verified_cascade"]["incorrect_acceptances"]
        self.assertLess(indep, dep)

    def test_report_is_labeled_simulated_and_makes_no_optimality_claim(self):
        rep = sim.run_report(replace(self.P, n_tasks=400), with_sensitivity=True)
        self.assertIn("SIMULATED", rep["label"])
        self.assertTrue(any("optimal" in a for a in rep["assumptions"]))
        self.assertGreaterEqual(len(rep["sensitivity"]), 15)
        self.assertEqual(set(rep["results"]), set(sim.STRATEGIES))

    def test_parameter_validation(self):
        with self.assertRaises(SchemaError):
            sim.run_strategies(replace(self.P, verifier_fp=1.5))
        with self.assertRaises(SchemaError):
            sim.run_strategies(replace(self.P, n_tasks=0))


if __name__ == "__main__":
    unittest.main()
