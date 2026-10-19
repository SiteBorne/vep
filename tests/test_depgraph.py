"""Dependency graph, claim scheduling, evidence invalidation and composite verification (real evaluator)."""
from __future__ import annotations

from tests.helpers import AUTH, VepTestCase
from vep import candidates, controller, depgraph, snapshots
from vep.workspace import utcnow

FILES = {
    "lib.py": "def area(w, h):\n    return w * h\n",
    "app.py": "from lib import area\n\n\ndef room():\n    return area(2, 3)\n",
    "util.py": "def shout(s):\n    return s.upper()\n",
    "api.json": '{"area": ["w", "h"]}\n',
    "tests/test_app.py": ("import unittest\nfrom app import room\n\n\nclass T(unittest.TestCase):\n"
                          "    def test_room(self):\n        self.assertEqual(room(), 6)\n"),
    "tests/test_util.py": ("import unittest\nfrom util import shout\n\n\nclass T(unittest.TestCase):\n"
                           "    def test_shout(self):\n        self.assertEqual(shout('a'), 'A')\n"),
}
FAR = "2099-01-01T00:00:00Z"


class GraphTests(VepTestCase):
    def env2(self):
        return self.env(files=FILES)

    def test_graph_edges_are_evidence_based(self):
        e = self.env2()
        g = depgraph.build_graph(e.ws, e.base.id, contracts={"app.py": ["api.json"]}, build_deps={"util.py": ["api.json"]})
        pairs = {(x["type"], x["from"], x["to"]) for x in g["edges"]}
        self.assertIn(("SOURCE_DEPENDENCY", "app.py", "lib.py"), pairs)
        self.assertIn(("SOURCE_DEPENDENCY", "tests/test_app.py", "app.py"), pairs)
        self.assertIn(("CONTRACT_DEPENDENCY", "app.py", "api.json"), pairs)
        self.assertIn(("BUILD_DEPENDENCY", "util.py", "api.json"), pairs)
        self.assertNotIn(("SOURCE_DEPENDENCY", "util.py", "lib.py"), pairs)  # nothing invented
        self.assertTrue(all(x["basis"] in ("STATIC_IMPORT", "DECLARED") for x in g["edges"]))

    def test_impact_is_prioritisation_only(self):
        e = self.env2()
        g = depgraph.build_graph(e.ws, e.base.id)
        d = e.variant({"lib.py": "def area(w, h):\n    return h * w\n", "notes.txt": "x"})
        new = snapshots.take_snapshot(e.ws, d)
        imp = depgraph.impact(e.ws, g, e.base.id, new.id)
        self.assertIn("tests/test_app.py", imp["affected_tests"])
        self.assertNotIn("tests/test_util.py", imp["affected_tests"])
        self.assertEqual(imp["unanalysable_changes"], ["notes.txt"])
        self.assertEqual((imp["required_evaluation"], imp["semantic_impact_established"]), ("FULL", False))

    def claim(self, e, who, paths):
        return candidates.create_work_claim(e.ws, e.objective.id, who, paths, FAR)

    def test_independent_claims_share_a_wave_dependent_ones_do_not(self):
        e = self.env2()
        g = depgraph.build_graph(e.ws, e.base.id)
        a, b, c = self.claim(e, "a", ["util.py"]), self.claim(e, "b", ["lib.py"]), self.claim(e, "c", ["app.py"])
        self.assertEqual(depgraph.claim_relations(g, a, b), [])
        rel = depgraph.claim_relations(g, b, c)
        self.assertEqual(rel[0]["type"], "SOURCE_DEPENDENCY")
        sched = depgraph.schedule(g, [a, b, c])
        self.assertEqual(sched["waves"], [["a", "b"], ["c"]])

    def test_overlapping_claims_conflict(self):
        e = self.env2()
        g = depgraph.build_graph(e.ws, e.base.id)
        rel = depgraph.claim_relations(g, self.claim(e, "a", ["lib.py"]), self.claim(e, "b", ["lib.py"]))
        self.assertEqual(rel[0]["type"], "WORK_CLAIM_CONFLICT")

    def run_candidate(self, e, cid):
        controller.enqueue(e.ws, cid)
        return controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))

    def test_two_independent_changes_compose_and_pass(self):
        e = self.env2()
        a = e.candidate({"util.py": "def shout(s):\n    return s.upper() + ''\n"})
        b = e.candidate({"lib.py": "def area(w, h):\n    return h * w\n"})
        r = depgraph.compose_candidates(e.ws, e.objective.id, a, b)
        self.assertEqual(r["status"], "TEXTUALLY_CLEAN")
        self.assertTrue(r["requires_composite_evaluation"])
        self.assertEqual(candidates.get_state(e.ws, r["composite_candidate_id"])["status"], "PROPOSED")
        self.assertEqual(self.run_candidate(e, r["composite_candidate_id"])["candidate_status"], "CERTIFIED")

    def test_overlapping_changes_conflict_with_replan(self):
        e = self.env2()
        a = e.candidate({"lib.py": "def area(w, h):\n    return h * w\n"})
        b = e.candidate({"lib.py": "def area(w, h):\n    return w * h * 1\n"})
        r = depgraph.compose_candidates(e.ws, e.objective.id, a, b)
        self.assertEqual((r["status"], r["conflicts"], r["composite_candidate_id"]), ("CONFLICT", ["lib.py"], None))
        self.assertEqual(r["replan"]["action"], "REBASE_ONE_CANDIDATE")

    def test_conflicting_contract_change_is_a_textual_conflict(self):
        e = self.env2()
        a = e.candidate({"api.json": '{"area": ["w", "h", "d"]}\n'})
        b = e.candidate({"api.json": '{"area": ["width", "h"]}\n'})
        self.assertEqual(depgraph.compose_candidates(e.ws, e.objective.id, a, b)["status"], "CONFLICT")

    def test_textually_clean_but_behaviourally_incompatible_is_caught(self):
        e = self.env2()
        # C changes area()'s signature and updates its existing caller: passes alone.
        c = e.candidate({"lib.py": "def area(w, h, d):\n    return w * h * d\n",
                         "app.py": "from lib import area\n\n\ndef room():\n    return area(2, 3, 1)\n"})
        # D adds a NEW module + NEW test using the old signature: passes alone.
        d = e.candidate({"extra.py": "from lib import area\n\n\ndef wall():\n    return area(4, 5)\n",
                         "tests/test_extra.py": ("import unittest\nfrom extra import wall\n\n\nclass T(unittest.TestCase):\n"
                                                 "    def test_wall(self):\n        self.assertEqual(wall(), 20)\n")})
        self.assertEqual(self.run_candidate(e, c)["candidate_status"], "CERTIFIED")
        self.assertEqual(self.run_candidate(e, d)["candidate_status"], "CERTIFIED")
        comp = depgraph.compose_candidates(e.ws, e.objective.id, c, d)
        self.assertEqual(comp["status"], "TEXTUALLY_CLEAN")
        res = self.run_candidate(e, comp["composite_candidate_id"])
        self.assertEqual((res["candidate_status"], res["verdict"]), ("REJECTED", "FAIL"))  # composite verification fails
        with e.ws.db.read() as cx:
            self.assertEqual(cx.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"], 2)  # parents only

    def test_agent_cannot_modify_required_tests(self):
        e = self.env2()
        cid = e.candidate({"tests/test_util.py": FILES["tests/test_util.py"] + "\n# edit\n"})
        r = self.run_candidate(e, cid)
        self.assertEqual((r["outcome"], r["failure_class"]), ("FAILED", "PolicyViolation"))
        self.assertIn("REQUIRED_TEST_MODIFIED", r["detail"])

    def test_evidence_invalidated_by_source_change_and_policy_mismatch(self):
        e = self.env2()
        cid = e.candidate()
        self.run_candidate(e, cid)
        with e.ws.db.read() as c:
            evid = c.execute("SELECT id, snapshot_id, policy_id FROM evidence").fetchone()
        ok = depgraph.evidence_validity(e.ws, evid["id"], snapshot_id=evid["snapshot_id"], policy_id=evid["policy_id"],
                                        trust_level="TRUSTED_LOCAL")
        self.assertTrue(ok["valid"])
        new = snapshots.take_snapshot(e.ws, e.variant({"util.py": "def shout(s):\n    return s.upper()\n# c\n"}))
        bad = depgraph.evidence_validity(e.ws, evid["id"], snapshot_id=new.id, policy_id=evid["policy_id"])
        self.assertEqual((bad["valid"], bad["reasons"]), (False, ["SNAPSHOT_CHANGED"]))
        self.assertEqual(depgraph.evidence_validity(e.ws, evid["id"], snapshot_id=evid["snapshot_id"],
                                                    policy_id="pol-other")["reasons"], ["POLICY_CHANGED"])
        self.assertEqual(depgraph.evidence_validity(e.ws, evid["id"], snapshot_id=evid["snapshot_id"],
                                                    policy_id=evid["policy_id"], trust_level="ISOLATED_VERIFIED")["reasons"],
                         ["TRUST_LEVEL_MISMATCH"])
        self.assertEqual([x["evidence_id"] for x in depgraph.invalidated_evidence(e.ws, new.id)], [evid["id"]])
        self.assertEqual(depgraph.evidence_validity(e.ws, "evd-" + "0" * 64, snapshot_id=new.id, policy_id="x")["reasons"],
                         ["EVIDENCE_UNKNOWN"])
