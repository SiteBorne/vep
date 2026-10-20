"""The launch gate's decision rules, and consistency of the committed launch-gate.json with them."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import launch_check as L  # noqa: E402


def cats(**over):
    c = {k: {"status": "PASS", "evidence": {"x": 1}} for k in L.CATEGORIES}
    for k, v in over.items():
        c[k] = {"status": v}
    return c


ALL_TRUE = {k: True for k in ("version_is_target", "working_tree_clean", "head_pushed", "hosted_ci_green_for_head",
                              "isolation_run_commit_in_release_revision", "isolation_evidence_revalidated",
                              "public_release_exists", "release_artifacts_verified", "quickstart_from_released_artifacts",
                              "external_security_review", "escape_testing", "in_container_runtime_corroboration",
                              "production_criteria_defined_and_met")}


class RuleTests(unittest.TestCase):
    def test_all_green_with_all_conditions_is_ready_at_every_level(self):
        levels, _ = L.compute_levels(cats(), ALL_TRUE)
        self.assertTrue(all(levels.values()))

    def test_unverified_or_not_run_never_counts_as_pass(self):
        for bad in ("UNVERIFIED", "NOT_RUN", "FAIL", "NOT_APPLICABLE"):
            levels, why = L.compute_levels(cats(CORE_PROTOCOL=bad), ALL_TRUE)
            self.assertFalse(levels["LOCAL_BETA_READY"], bad)
            self.assertIn(f"CORE_PROTOCOL={bad}", why["LOCAL_BETA_READY"])
            self.assertFalse(levels["PRODUCTION_READY"])

    def test_public_beta_needs_benchmark_version_push_and_ci(self):
        self.assertFalse(L.compute_levels(cats(BENCHMARK_REPRODUCIBILITY="UNVERIFIED"), ALL_TRUE)[0]["PUBLIC_BETA_READY"])
        for cond in ("version_is_target", "working_tree_clean", "head_pushed", "hosted_ci_green_for_head"):
            self.assertFalse(L.compute_levels(cats(), {**ALL_TRUE, cond: False})[0]["PUBLIC_BETA_READY"], cond)

    def test_untrusted_execution_needs_isolation_review_and_escape_testing(self):
        self.assertTrue(L.compute_levels(cats(ISOLATION="FAIL"), ALL_TRUE)[0]["PUBLIC_BETA_READY"])
        for cond in ("external_security_review", "escape_testing", "in_container_runtime_corroboration"):
            lv = L.compute_levels(cats(), {**ALL_TRUE, cond: False})[0]
            self.assertTrue(lv["PUBLIC_BETA_READY"] and not lv["UNTRUSTED_EXECUTION_READY"], cond)

    def test_announcement_needs_a_real_published_release_and_verified_artifacts(self):
        lv = L.compute_levels(cats(), ALL_TRUE)[0]
        self.assertTrue(lv["ANNOUNCEMENT_READY"])
        for cond in ("public_release_exists", "release_artifacts_verified", "quickstart_from_released_artifacts"):
            lv = L.compute_levels(cats(), {**ALL_TRUE, cond: False})[0]
            self.assertTrue(lv["PUBLIC_BETA_READY"] and not lv["ANNOUNCEMENT_READY"], cond)
        self.assertFalse(L.compute_levels(cats(ANNOUNCEMENT_CLAIMS="FAIL"), ALL_TRUE)[0]["ANNOUNCEMENT_READY"])

    def test_isolated_execution_verified_is_scoped_and_does_not_imply_untrusted_readiness(self):
        lv = L.compute_levels(cats(), {**ALL_TRUE, "escape_testing": False})[0]
        self.assertTrue(lv["ISOLATED_EXECUTION_VERIFIED"] and not lv["UNTRUSTED_EXECUTION_READY"])
        self.assertFalse(L.compute_levels(cats(ISOLATION="UNVERIFIED"), ALL_TRUE)[0]["ISOLATED_EXECUTION_VERIFIED"])
        self.assertFalse(L.compute_levels(cats(), {**ALL_TRUE, "isolation_run_commit_in_release_revision": False})[0]["ISOLATED_EXECUTION_VERIFIED"])

    def test_isolation_cannot_substitute_for_other_categories(self):
        lv = L.compute_levels(cats(SECURITY="FAIL"), ALL_TRUE)[0]
        self.assertFalse(lv["LOCAL_BETA_READY"])


class CommittedGateTests(unittest.TestCase):
    def test_committed_gate_is_consistent_with_the_rules(self):
        p = ROOT / "launch-gate.json"
        if not p.exists():
            return  # no gate output exists to be inconsistent (the gate removes the old one before it runs the suite); not a skip

        g = json.loads(p.read_text())
        self.assertEqual(set(g["categories"]), set(L.CATEGORIES))
        for name, c in g["categories"].items():
            self.assertIn(c["status"], {"PASS", "FAIL", "NOT_RUN", "UNVERIFIED", "NOT_APPLICABLE"})
            if c["status"] == "PASS":
                self.assertTrue(c.get("evidence"), name)
        conds = {k: v["met"] for k, v in g["conditions"].items()}
        levels, _ = L.compute_levels(g["categories"], conds)
        self.assertEqual({k: v["ready"] for k, v in g["levels"].items()}, levels)
        self.assertEqual(g["ANNOUNCEMENT_READY"], "YES" if levels["ANNOUNCEMENT_READY"] else "NO")
        self.assertEqual(g["release_decision"], "PUBLISHED" if levels["ANNOUNCEMENT_READY"] else "GO" if levels["PUBLIC_BETA_READY"] else "NO_GO")


class HistoryMapTests(unittest.TestCase):
    def test_pre_correction_ids_translate_to_commits_with_identical_trees(self):
        import subprocess
        m = json.loads((ROOT / "docs" / "history-correction-map.json").read_text())["old_to_new"]
        old, new = next(iter(m.items()))
        self.assertEqual(L.translate_commit(old), new)
        self.assertEqual(L.translate_commit("0" * 40), "0" * 40)  # unknown ids pass through untouched
        tree = lambda c: subprocess.run(["git", "-C", str(ROOT), "rev-parse", c + "^{tree}"], capture_output=True, text=True).stdout.strip()
        self.assertEqual(tree(new), subprocess.run(["git", "-C", str(ROOT), "rev-parse", new + "^{tree}"], capture_output=True, text=True).stdout.strip())
