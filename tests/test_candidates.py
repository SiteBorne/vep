import sqlite3
import unittest

from vep import candidates
from vep.errors import StateError
from tests.helpers import VepTestCase


class CandidateStateTests(VepTestCase):
    def setUp(self):
        super().setUp()
        self.e = self.env()
        self.cid = self.e.candidate({"extra.py": "X = 1\n"})
        self.ws = self.e.ws

    def v(self):
        return candidates.get_state(self.ws, self.cid)["version"]

    def test_registration_starts_proposed_at_version_zero(self):
        st = candidates.get_state(self.ws, self.cid)
        self.assertEqual((st["status"], st["version"]), ("PROPOSED", 0))

    def test_legal_path_and_history(self):
        self.assertEqual(candidates.check_policy(self.ws, self.cid), [])
        v = self.v()
        for to in ("BUDGET_RESERVED", "EVALUATING"):
            v = candidates.transition(self.ws, self.cid, to, v, "t", "r")
        self.assertEqual(candidates.get_state(self.ws, self.cid)["status"], "EVALUATING")
        hist = [h["to_status"] for h in candidates.history(self.ws, self.cid)]
        self.assertEqual(hist, ["PROPOSED", "POLICY_CHECKED", "BUDGET_RESERVED", "EVALUATING"])

    def test_illegal_transitions_rejected(self):
        for to in ("CERTIFIED", "EVALUATING", "EVIDENCE_READY", "BUDGET_RESERVED"):
            with self.assertRaises(StateError, msg=to):
                candidates.transition(self.ws, self.cid, to, 0, "t", "r")
        with self.assertRaises(StateError):
            candidates.transition(self.ws, self.cid, "NOPE", 0, "t", "r")

    def test_stale_version_and_replay_rejected(self):
        candidates.transition(self.ws, self.cid, "POLICY_CHECKED", 0, "t", "r")
        with self.assertRaises(StateError):  # replay of the same operation
            candidates.transition(self.ws, self.cid, "POLICY_CHECKED", 0, "t", "r")
        with self.assertRaises(StateError):  # duplicate with fresh version but illegal edge
            candidates.transition(self.ws, self.cid, "POLICY_CHECKED", 1, "t", "r")

    def test_terminal_states(self):
        candidates.transition(self.ws, self.cid, "REJECTED", 0, "t", "r")
        for to in ("PROPOSED", "POLICY_CHECKED", "REJECTED", "CERTIFIED"):
            with self.assertRaises(StateError):
                candidates.transition(self.ws, self.cid, to, 1, "t", "r")

    def test_cannot_self_certify_by_status_change(self):
        v = self.v()
        for to in ("POLICY_CHECKED", "BUDGET_RESERVED", "EVALUATING"):
            v = candidates.transition(self.ws, self.cid, to, v, "t", "r")
        with self.assertRaises(StateError):  # EVIDENCE_READY needs PASS evidence (DB trigger)
            candidates.transition(self.ws, self.cid, "EVIDENCE_READY", v, "t", "self-declared")
        with self.assertRaises(sqlite3.IntegrityError):  # even raw SQL cannot skip the guard
            with self.ws.db.tx() as c:
                c.execute("UPDATE candidates SET status='CERTIFIED' WHERE id=?", (self.cid,))
        self.assertEqual(candidates.get_state(self.ws, self.cid)["status"], "EVALUATING")

    def test_transition_log_is_append_only(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.ws.db.tx() as c:
                c.execute("UPDATE transitions SET reason='forged'")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.ws.db.tx() as c:
                c.execute("DELETE FROM transitions")

    def test_candidate_identity_columns_immutable(self):
        with self.assertRaises(sqlite3.IntegrityError):
            with self.ws.db.tx() as c:
                c.execute("UPDATE candidates SET snapshot_id=? WHERE id=?", ("snap-" + "0" * 64, self.cid))

    def test_failed_transition_rolls_back(self):
        with self.assertRaises(StateError):
            candidates.transition(self.ws, self.cid, "CERTIFIED", 0, "t", "r")
        self.assertEqual(len(candidates.history(self.ws, self.cid)), 1)

    def test_unknown_candidate(self):
        with self.assertRaises(StateError):
            candidates.get_state(self.ws, "cand-" + "0" * 64)

    def test_policy_violation_rejects_candidate(self):
        bad = self.e.candidate({"conftest.py": "import os\n"})
        v = candidates.check_policy(self.ws, bad)
        self.assertTrue(v)
        self.assertEqual(candidates.get_state(self.ws, bad)["status"], "REJECTED")
        self.assertIn("PROTECTED_PATH_CHANGED", candidates.history(self.ws, bad)[-1]["reason"])


class CompositionTests(VepTestCase):
    def test_disjoint_changes_compose_into_new_identity(self):
        e = self.env()
        a = e.candidate({"a.py": "A = 1\n"})
        b = e.candidate({"b.py": "B = 1\n"})
        r = candidates.compose(e.ws, e.base.id, a, b)
        self.assertEqual(r["conflicts"], [])
        paths = [x["path"] for x in r["snapshot"]["entries"]]
        self.assertIn("a.py", paths); self.assertIn("b.py", paths)
        self.assertNotIn(r["snapshot"].id, (e.ws.get_object(a, "Candidate")["snapshot_id"],
                                            e.ws.get_object(b, "Candidate")["snapshot_id"]))

    def test_conflicting_changes_detected(self):
        e = self.env()
        a = e.candidate({"arithmetic.py": "A = 1\n"})
        b = e.candidate({"arithmetic.py": "B = 1\n"})
        self.assertEqual(candidates.compose(e.ws, e.base.id, a, b)["conflicts"], ["arithmetic.py"])

    def test_identical_changes_do_not_conflict(self):
        e = self.env()
        a = e.candidate({"x.py": "same\n"}); b = e.candidate({"x.py": "same\n"})
        self.assertEqual(candidates.compose(e.ws, e.base.id, a, b)["conflicts"], [])

    def test_work_claim_overlap(self):
        e = self.env()
        c1 = candidates.create_work_claim(e.ws, e.objective.id, "a", ["src/"], "2030-01-01T00:00:00Z")
        c2 = candidates.create_work_claim(e.ws, e.objective.id, "b", ["src/x.py"], "2030-01-01T00:00:00Z")
        c3 = candidates.create_work_claim(e.ws, e.objective.id, "c", ["docs/"], "2030-01-01T00:00:00Z")
        self.assertEqual(candidates.claims_overlap(c1, c2), ["src/"])
        self.assertEqual(candidates.claims_overlap(c1, c3), [])


if __name__ == "__main__":
    unittest.main()
