"""Execution controller: leases, fencing, recovery, idempotency, multi-process safety (real processes, real evaluator)."""
from __future__ import annotations

import json
import multiprocessing as mp
import sqlite3

from tests.helpers import AUTH, VepTestCase
from vep import budgets, candidates, certificates, controller, execution
from vep.errors import AuthorizationError, BudgetError, StaleLease
from vep.workspace import Workspace

BAD = {"arithmetic.py": "def add(a, b):\n    return a - b\n"}


def worker(name):
    return controller.LocalToolWorker(name, AUTH)


class ControllerTests(VepTestCase):
    def test_happy_path_certifies_once_and_is_idempotent(self):
        e = self.env()
        cid = e.candidate({"extra.py": "X = 1\n"})
        j1 = controller.enqueue(e.ws, cid)
        j2 = controller.enqueue(e.ws, cid)
        self.assertEqual(j1["id"], j2["id"])
        self.assertEqual(len(controller.list_jobs(e.ws)), 1)
        r = controller.run_one(e.ws, worker("w1"))
        self.assertEqual(r["outcome"], "SUCCEEDED")
        self.assertEqual(r["candidate_status"], "CERTIFIED")
        self.assertIsNone(controller.run_one(e.ws, worker("w1")))
        job = controller.get_job(e.ws, j1["id"])
        self.assertEqual((job["state"], job["attempts"], job["fence"]), ("SUCCEEDED", 1, 1))
        # re-enqueue of a finished job does not re-run or re-certify
        self.assertEqual(controller.enqueue(e.ws, cid)["state"], "SUCCEEDED")
        self.assertIsNone(controller.run_one(e.ws, worker("w1")))
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"], 1)
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"], 1)
        self.assertEqual([x["event"] for x in controller.events(e.ws, j1["id"])], ["ENQUEUED", "CLAIMED", "SUCCEEDED"])
        cert_id = json.loads(job["result"])["certificate_id"]
        v = certificates.verify_certificate(e.ws, cert_id, current_root=None)
        self.assertEqual(v["certificate_id"], cert_id)

    def test_failing_candidate_completes_job_but_is_not_certified(self):
        e = self.env()
        cid = e.candidate(BAD)
        controller.enqueue(e.ws, cid)
        r = controller.run_one(e.ws, worker("w1"))
        self.assertEqual(r["outcome"], "SUCCEEDED")
        self.assertEqual(r["candidate_status"], "REJECTED")
        self.assertNotIn("certificate_id", r)

    def test_missing_authorization_fails_job_without_retry(self):
        e = self.env()
        cid = e.candidate()
        jid = controller.enqueue(e.ws, cid)["id"]
        r = controller.run_one(e.ws, controller.LocalToolWorker("w1", None))
        self.assertEqual((r["outcome"], r["failure_class"]), ("FAILED", AuthorizationError.__name__))
        job = controller.get_job(e.ws, jid)
        self.assertEqual((job["state"], job["attempts"]), ("FAILED", 1))
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")

    def test_isolated_job_is_not_run_by_a_trusted_local_worker(self):
        e = self.env()
        cid = e.candidate()
        controller.enqueue(e.ws, cid, mode="isolated")
        self.assertIsNone(controller.run_one(e.ws, worker("w1")))  # mode filter: no host fallback
        r = controller.run_one(e.ws, controller.IsolatedWorker("iso", None, None))
        self.assertEqual(r["outcome"], "FAILED")
        self.assertEqual(r["failure_class"], "IsolationUnavailable")

    def test_admission_control_refuses_unfunded_work(self):
        e = self.env(budget="0.0005")
        cid = e.candidate()
        with self.assertRaises(BudgetError):
            controller.enqueue(e.ws, cid)
        self.assertEqual(controller.list_jobs(e.ws), [])

    def test_stale_worker_is_fenced_at_commit(self):
        e = self.env()
        cid = e.candidate()
        jid = controller.enqueue(e.ws, cid)["id"]
        a = controller.claim(e.ws, "A", lease_s=10, now=1000)
        self.assertEqual(a["fence"], 1)
        self.assertIsNone(controller.claim(e.ws, "B", lease_s=10, now=1005))  # lease still held
        b = controller.claim(e.ws, "B", lease_s=10, now=2000)  # A's lease expired, pre-execution -> requeued
        self.assertEqual((b["owner"], b["fence"], b["attempts"]), ("B", 2, 2))
        # A wakes up late and tries every commit path
        with self.assertRaises(StaleLease):
            controller.complete(e.ws, jid, "A", 1, {"candidate_status": "CERTIFIED"})
        with self.assertRaises(StaleLease):
            execution.evaluate(e.ws, cid, trusted_local_authorization=AUTH, guard=controller.guard_for(jid, "A", 1))
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "POLICY_CHECKED")  # untouched by the stale worker
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"], 0)
        # the current owner proceeds normally
        out = worker("B").run(e.ws, b, controller.guard_for(jid, "B", 2))
        self.assertEqual(out["candidate_status"], "CERTIFIED")
        controller.complete(e.ws, jid, "B", 2, out)

    def test_stale_worker_cannot_certify(self):
        e = self.env()
        cid = e.candidate()
        jid = controller.enqueue(e.ws, cid)["id"]
        controller.claim(e.ws, "A", lease_s=1, now=10)
        e.evaluate(cid)  # evidence is ready; A then stalls
        b = controller.claim(e.ws, "B", lease_s=60, now=1000)  # EVIDENCE_READY + auto_certify -> requeued, B owns it
        self.assertEqual(b["fence"], 2)
        with self.assertRaises(StaleLease):
            certificates.certify(e.ws, cid, guard=controller.guard_for(jid, "A", 1))
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "EVIDENCE_READY")
        certificates.certify(e.ws, cid, guard=controller.guard_for(jid, "B", 2))

    def test_complete_is_idempotent_and_conflicting_replay_refused(self):
        e = self.env()
        jid = controller.enqueue(e.ws, e.candidate())["id"]
        j = controller.claim(e.ws, "A", lease_s=60, now=1)
        res = {"candidate_status": "REJECTED"}
        controller.complete(e.ws, jid, "A", j["fence"], res)
        self.assertEqual(controller.complete(e.ws, jid, "A", j["fence"], res)["state"], "SUCCEEDED")
        with self.assertRaises(StaleLease):
            controller.complete(e.ws, jid, "A", j["fence"], {"candidate_status": "CERTIFIED"})

    def test_lease_expiry_mid_evaluation_is_not_retried_and_holds_funds(self):
        e = self.env()
        cid = e.candidate()
        jid = controller.enqueue(e.ws, cid)["id"]
        j = controller.claim(e.ws, "A", lease_s=10, now=1000)
        # simulate a worker that died after reserving budget and starting evaluation
        candidates.check_policy(e.ws, cid)
        st = candidates.get_state(e.ws, cid)
        cap = budgets.available(e.ws, f"objective:{e.objective.id}")
        acct = execution._cand_account(e.ws, e.objective.id, cid)
        budgets.reserve(e.ws, acct, "0.001", f"eval:{cid}")
        v = candidates.transition(e.ws, cid, "BUDGET_RESERVED", st["version"], "A", "x")
        candidates.transition(e.ws, cid, "EVALUATING", v, "A", "x")
        actions = controller.recover(e.ws, now=2000)
        self.assertEqual(actions[0]["action"], "FAILED_UNKNOWN_OUTCOME")
        job = controller.get_job(e.ws, jid)
        self.assertEqual((job["state"], job["failure_class"]), ("FAILED", "WORKER_LOST_AFTER_EXECUTION_STARTED"))
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "REJECTED")
        self.assertEqual(budgets.get_reservation(e.ws, f"eval:{cid}")["state"], "UNCERTAIN")
        self.assertLess(budgets.available(e.ws, f"objective:{e.objective.id}"), cap)
        with self.assertRaises(StaleLease):
            controller.complete(e.ws, jid, "A", j["fence"], {"candidate_status": "CERTIFIED"})
        self.assertIsNone(controller.claim(e.ws, "B", now=3000))

    def test_attempts_are_bounded(self):
        e = self.env()
        jid = controller.enqueue(e.ws, e.candidate(), max_attempts=2)["id"]
        controller.claim(e.ws, "A", lease_s=1, now=100)
        controller.claim(e.ws, "B", lease_s=1, now=200)
        controller.recover(e.ws, now=300)
        job = controller.get_job(e.ws, jid)
        self.assertEqual((job["state"], job["failure_class"], job["attempts"]),
                         ("FAILED", "LEASE_EXPIRED_ATTEMPTS_EXHAUSTED", 2))

    def test_cancel_discards_running_work_and_restores_consistency(self):
        e = self.env()
        cid = e.candidate()
        jid = controller.enqueue(e.ws, cid)["id"]
        j = controller.claim(e.ws, "A", lease_s=60, now=1)
        controller.cancel(e.ws, jid)
        with self.assertRaises(StaleLease):
            execution.evaluate(e.ws, cid, trusted_local_authorization=AUTH, guard=controller.guard_for(jid, "A", j["fence"]))
        self.assertEqual(controller.get_job(e.ws, jid)["state"], "CANCELLED")
        self.assertIsNone(controller.claim(e.ws, "B", now=2))
        self.assertNotEqual(candidates.get_state(e.ws, cid)["status"], "CERTIFIED")

    def test_recovered_evidence_ready_candidate_certifies_without_reevaluating(self):
        e = self.env()
        cid = e.candidate()
        jid = controller.enqueue(e.ws, cid)["id"]
        controller.claim(e.ws, "A", lease_s=1, now=10)
        e.evaluate(cid)  # A finished evaluation then died before certifying
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "EVIDENCE_READY")
        r = controller.run_one(e.ws, worker("B"), now=1000)
        self.assertEqual(r["candidate_status"], "CERTIFIED")
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"], 1)
        self.assertEqual(controller.get_job(e.ws, jid)["attempts"], 2)

    def test_job_events_are_append_only(self):
        e = self.env()
        jid = controller.enqueue(e.ws, e.candidate())["id"]
        with e.ws.db.tx() as c:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("DELETE FROM job_events WHERE job_id=?", (jid,))


def _proc(root, name, q):
    ws = Workspace(root)
    res = controller.run_until_idle(ws, worker(name))
    q.put([(r["job"], r["outcome"], r.get("candidate_status")) for r in res])


class MultiProcessTests(VepTestCase):
    def test_four_real_processes_certify_each_candidate_exactly_once(self):
        e = self.env(budget="5.00")
        cids = [e.candidate({f"mod{i}.py": f"V = {i}\n"}) for i in range(8)]
        for c in cids:
            controller.enqueue(e.ws, c)
        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        procs = [ctx.Process(target=_proc, args=(str(e.root), f"p{i}", q)) for i in range(4)]
        for p in procs:
            p.start()
        results = [q.get(timeout=300) for _ in procs]
        for p in procs:
            p.join(timeout=60)
            self.assertEqual(p.exitcode, 0)
        flat = [r for rs in results for r in rs]
        self.assertEqual(len(flat), 8)
        self.assertEqual(len({r[0] for r in flat}), 8)  # no job ran twice
        self.assertTrue(all(r[1:] == ("SUCCEEDED", "CERTIFIED") for r in flat))
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"], 8)
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM evidence").fetchone()["n"], 8)
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM reservations WHERE state='SETTLED'").fetchone()["n"], 8)
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM jobs WHERE attempts<>1").fetchone()["n"], 0)
