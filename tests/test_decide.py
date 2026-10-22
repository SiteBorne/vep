"""Every branch of the preregistered adoption rule, on synthetic A/B documents (no measurement involved)."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks" / "analysis"))
import decide as D  # noqa: E402


def cmp(verdict, rel, diff, lo=None, hi=None):
    lo = rel - 0.02 if lo is None else lo; hi = rel + 0.02 if hi is None else hi
    return {"welch_preregistered": {"verdict": verdict, "rel_diff": rel, "diff_s": diff, "rel_ci95": [lo, hi]}, "paired_bootstrap": {"verdict": verdict, "rel_diff": rel, "mean_paired_diff_s": diff, "rel_ci95": [lo, hi]}}


def doc(n, verdict="VEP_FASTER", rel=-0.2, diff=-0.4, env_ok=True, excluded=0, rss=(100.0, 100.0), cpu=None):
    return {"n_files": n, "baseline": "ctl", "arms": ["ctl", "x"], "excluded": [{}] * excluded,
            "blocks": [{"env": {"load_avg_1m": 0.8 if env_ok else 6.0, "cpu_idle_pct": 99.0 if env_ok else 50.0}}] * 5,
            "summary": {"ctl": {"wall_s": {"mean": 2.0}, "rss_child_max_mb": {"mean": rss[0]}}, "x": {"wall_s": {"mean": 1.6}, "rss_child_max_mb": {"mean": rss[1]}}},
            "comparisons": {"x_vs_ctl": {"wall_s": cmp(verdict, rel, diff), "cpu_s": cpu or cmp(verdict, rel, diff)}}}


def files(**kw):
    return {1000: doc(1000, **kw), 3000: doc(3000, **kw), 100: doc(100, **{**kw, "verdict": kw.get("cold", "NO_MEASURABLE_ADVANTAGE"), "rel": 0.0, "diff": 0.0}) if True else None}


class DecideTests(unittest.TestCase):
    def test_adopt_needs_everything(self):
        self.assertEqual(D.decide_arm("x", files(), True)["decision"], "ADOPT")

    def test_valid_environment_without_a_wall_gain_is_reject(self):
        f = files(verdict="NO_MEASURABLE_ADVANTAGE", rel=-0.04, diff=-0.08)
        self.assertEqual(D.decide_arm("x", f, True)["decision"], "REJECT")

    def test_gain_on_one_size_only_is_not_adopted(self):
        f = files(); f[3000] = doc(3000, verdict="NO_MEASURABLE_ADVANTAGE", rel=-0.05, diff=-0.1)
        self.assertEqual(D.decide_arm("x", f, True)["decision"], "REJECT")

    def test_invalid_environment_is_inconclusive_even_with_a_big_gain(self):
        self.assertEqual(D.decide_arm("x", files(env_ok=False), True)["decision"], "INCONCLUSIVE")

    def test_inconclusive_verdict_is_inconclusive(self):
        self.assertEqual(D.decide_arm("x", files(verdict="INCONCLUSIVE", rel=-0.1, diff=-0.2), True)["decision"], "INCONCLUSIVE")

    def test_correctness_gate_missing_or_failed_blocks_adoption(self):
        self.assertEqual(D.decide_arm("x", files(), None)["decision"], "INCONCLUSIVE")
        self.assertEqual(D.decide_arm("x", files(), False)["decision"], "INCONCLUSIVE")

    def test_any_excluded_block_is_reject(self):
        self.assertEqual(D.decide_arm("x", files(excluded=1), True)["decision"], "REJECT")

    def test_memory_growth_is_reject(self):
        self.assertEqual(D.decide_arm("x", files(rss=(100.0, 140.0)), True)["decision"], "REJECT")

    def test_cold_path_regression_is_reject(self):
        f = files(); f[100] = doc(100, verdict="VEP_SLOWER", rel=0.2, diff=0.2, ) ; f[100]["comparisons"]["x_vs_ctl"]["wall_s"]["welch_preregistered"]["rel_ci95"] = [0.1, 0.3]
        self.assertEqual(D.decide_arm("x", f, True)["decision"], "REJECT")

    def test_missing_sizes_are_inconclusive(self):
        f = files(); del f[3000]
        self.assertEqual(D.decide_arm("x", f, True)["decision"], "INCONCLUSIVE")

    def test_thresholds_are_the_preregistered_ones(self):
        self.assertEqual((D.REL, D.ABS_S, D.WALL_SIZES), (0.10, 0.05, (1000, 3000)))


if __name__ == "__main__":
    unittest.main()
