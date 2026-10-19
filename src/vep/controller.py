"""Durable execution controller: SQLite-backed job queue with leases and fencing tokens.

Each job drives one Candidate through evaluate (and optionally certify). Safety properties are enforced
where state is committed, not where work is scheduled:

* A claim increments the job's `fence`. Every commit made on behalf of a job (evidence, rejection,
  certificate) runs a guard inside the committing transaction that requires state=LEASED, the same owner
  and the same fence; a stale owner gets StaleLease and changes nothing.
* Jobs are idempotent on (candidate, kind). Settlement and certification are already unique per
  candidate in the underlying tables, so a replayed job cannot settle or certify twice.
* Recovery never retries work whose outcome is unknown: a lease that expires while the candidate is
  BUDGET_RESERVED/EVALUATING marks the reservation UNCERTAIN, rejects the candidate (WORKER_LOST) and fails
  the job. Only pre-execution failures are retried, up to max_attempts.

Cancellation is cooperative: a running subprocess is not killed; its result is discarded at the commit
boundary. This is a single-host SQLite controller; it makes no distributed-scale claim.
"""
from __future__ import annotations

import json
import sqlite3
import time
from decimal import Decimal
from typing import Any, Protocol

from . import budgets, candidates, certificates, execution
from .canonical import sha256_hex
from .errors import BudgetError, StaleLease, StateError, VepError
from .policies import load_policy
from .workspace import Workspace, utcnow

JOB_STATES = ("QUEUED", "LEASED", "SUCCEEDED", "FAILED", "CANCELLED")
TERMINAL = ("SUCCEEDED", "FAILED", "CANCELLED")
MODES = ("trusted-local", "isolated")
DEFAULT_MAX_ATTEMPTS = 3
LEASE_MARGIN_S = 60
TRANSIENT = (sqlite3.OperationalError, OSError)
PRE_EXECUTION = ("PROPOSED", "POLICY_CHECKED")


def job_id_for(candidate_id: str, kind: str = "evaluate") -> str:
    return "job-" + sha256_hex(f"vep.job.v1\0{candidate_id}\0{kind}".encode())[:32]


def _event(c: sqlite3.Connection, job_id: str, event: str, worker: str | None = None,
           fence: int | None = None, detail: str = "") -> None:
    c.execute("INSERT INTO job_events(job_id,event,worker,fence,detail,at) VALUES(?,?,?,?,?,?)",
              (job_id, event, worker, fence, detail, utcnow()))


def get_job(ws: Workspace, job_id: str) -> dict:
    with ws.db.read() as c:
        row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if row is None:
        raise StateError(f"unknown job {job_id}")
    return dict(row)


def list_jobs(ws: Workspace, state: str | None = None) -> list[dict]:
    with ws.db.read() as c:
        q, a = ("SELECT * FROM jobs WHERE state=? ORDER BY created_at, id", (state,)) if state \
            else ("SELECT * FROM jobs ORDER BY created_at, id", ())
        return [dict(r) for r in c.execute(q, a)]


def events(ws: Workspace, job_id: str) -> list[dict]:
    with ws.db.read() as c:
        return [dict(r) for r in c.execute("SELECT * FROM job_events WHERE job_id=? ORDER BY seq", (job_id,))]


# ------------------------------------------------------------------ enqueue / admission
def enqueue(ws: Workspace, candidate_id: str, *, mode: str = "trusted-local", auto_certify: bool = True,
            max_attempts: int = DEFAULT_MAX_ATTEMPTS, kind: str = "evaluate") -> dict:
    """Idempotent: enqueueing the same (candidate, kind) again returns the existing job unchanged."""
    if mode not in MODES:
        raise VepError(f"unknown mode {mode!r}")
    if not 1 <= max_attempts <= 10:
        raise VepError("max_attempts must be in [1, 10]")
    cand = ws.get_object(candidate_id, "Candidate")
    objective = ws.get_object(cand["objective_id"], "Objective")
    jid = job_id_for(candidate_id, kind)
    with ws.db.read() as c:
        if c.execute("SELECT 1 FROM jobs WHERE id=?", (jid,)).fetchone():
            return get_job(ws, jid)
    # budget-aware admission: refuse work that cannot be funded (the real reservation happens at execution)
    policy = load_policy(ws, objective["policy_id"])
    need = Decimal(policy["limits"]["evaluation_cost_micro_usd"]) / Decimal(1_000_000)
    acct = f"objective:{objective.id}"
    avail = budgets.available(ws, acct)  # raises/returns for unknown account per budgets semantics
    if avail < need:
        raise BudgetError(f"admission refused: {acct} has {avail} available, evaluation needs {need}")
    with ws.db.tx() as c:
        c.execute("INSERT OR IGNORE INTO jobs(id,objective_id,candidate_id,kind,mode,auto_certify,state,max_attempts,created_at)"
                  " VALUES(?,?,?,?,?,?, 'QUEUED', ?, ?)",
                  (jid, objective.id, candidate_id, kind, mode, int(auto_certify), max_attempts, utcnow()))
        _event(c, jid, "ENQUEUED", detail=f"mode={mode} max_attempts={max_attempts}")
    return get_job(ws, jid)


# ------------------------------------------------------------------ lease protocol
def _now(now: float | None) -> float:
    return time.time() if now is None else now


def claim(ws: Workspace, worker_id: str, *, lease_s: float | None = None, now: float | None = None,
          mode: str | None = None) -> dict | None:
    """Atomically lease the oldest QUEUED job. Returns the job (with its fence) or None."""
    t = _now(now)
    recover(ws, now=t)
    with ws.db.tx() as c:
        q = "SELECT * FROM jobs WHERE state='QUEUED'" + (" AND mode=?" if mode else "") + " ORDER BY created_at, id LIMIT 1"
        row = c.execute(q, (mode,) if mode else ()).fetchone()
        if row is None:
            return None
        if lease_s is None:
            pol = load_policy(ws, ws.get_object(row["objective_id"], "Objective")["policy_id"])
            lease_s = pol["limits"]["timeout_s"] + LEASE_MARGIN_S
        fence = row["fence"] + 1
        c.execute("UPDATE jobs SET state='LEASED', owner=?, fence=?, attempts=attempts+1, lease_expires=? WHERE id=?",
                  (worker_id, fence, t + lease_s, row["id"]))
        _event(c, row["id"], "CLAIMED", worker_id, fence, f"attempt={row['attempts'] + 1} lease_s={lease_s}")
        return dict(c.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())


def assert_fence(c: sqlite3.Connection, job_id: str, worker_id: str, fence: int) -> None:
    """Commit-boundary ownership check. Runs inside the committing transaction."""
    row = c.execute("SELECT state, owner, fence FROM jobs WHERE id=?", (job_id,)).fetchone()
    if row is None or row["state"] != "LEASED" or row["owner"] != worker_id or row["fence"] != fence:
        have = None if row is None else f"{row['state']}/{row['owner']}/fence={row['fence']}"
        raise StaleLease(f"STALE_LEASE: {worker_id}/fence={fence} does not hold {job_id} (now {have})")


def guard_for(job_id: str, worker_id: str, fence: int):
    return lambda c: assert_fence(c, job_id, worker_id, fence)


def heartbeat(ws: Workspace, job_id: str, worker_id: str, fence: int, lease_s: float, now: float | None = None) -> None:
    with ws.db.tx() as c:
        assert_fence(c, job_id, worker_id, fence)
        c.execute("UPDATE jobs SET lease_expires=? WHERE id=?", (_now(now) + lease_s, job_id))
        _event(c, job_id, "HEARTBEAT", worker_id, fence)


def complete(ws: Workspace, job_id: str, worker_id: str, fence: int, result: dict) -> dict:
    """Idempotent: repeating the identical completion returns the recorded job; a different one is refused."""
    blob = json.dumps(result, sort_keys=True, default=str)
    with ws.db.tx() as c:
        row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row and row["state"] == "SUCCEEDED" and row["owner"] == worker_id and row["fence"] == fence:
            if row["result"] == blob:
                return dict(row)
            raise StaleLease("conflicting second completion of an already-completed job")
        assert_fence(c, job_id, worker_id, fence)
        c.execute("UPDATE jobs SET state='SUCCEEDED', result=?, lease_expires=NULL WHERE id=?", (blob, job_id))
        _event(c, job_id, "SUCCEEDED", worker_id, fence, str(result.get("candidate_status", "")))
        return dict(c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def fail(ws: Workspace, job_id: str, worker_id: str, fence: int, failure_class: str, *,
         retryable: bool, detail: str = "") -> dict:
    with ws.db.tx() as c:
        assert_fence(c, job_id, worker_id, fence)
        row = c.execute("SELECT attempts, max_attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
        if retryable and row["attempts"] < row["max_attempts"]:
            c.execute("UPDATE jobs SET state='QUEUED', owner=NULL, lease_expires=NULL, failure_class=? WHERE id=?",
                      (failure_class, job_id))
            _event(c, job_id, "REQUEUED", worker_id, fence, f"{failure_class}: {detail}")
        else:
            c.execute("UPDATE jobs SET state='FAILED', lease_expires=NULL, failure_class=? WHERE id=?",
                      (failure_class, job_id))
            _event(c, job_id, "FAILED", worker_id, fence, f"{failure_class}: {detail}")
        return dict(c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def cancel(ws: Workspace, job_id: str) -> dict:
    """Mark a non-terminal job CANCELLED. A running worker's commits are then refused by the fence."""
    with ws.db.tx() as c:
        row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise StateError(f"unknown job {job_id}")
        if row["state"] in TERMINAL:
            return dict(row)
        c.execute("UPDATE jobs SET state='CANCELLED', lease_expires=NULL WHERE id=?", (job_id,))
        _event(c, job_id, "CANCELLED", row["owner"], row["fence"])
    _settle_abandoned_candidate(ws, row["candidate_id"], "CANCELLED")
    return get_job(ws, job_id)


def _settle_abandoned_candidate(ws: Workspace, candidate_id: str, reason: str) -> None:
    """Outcome unknown for a candidate left mid-evaluation: hold funds as UNCERTAIN, reject, never re-run."""
    st = candidates.get_state(ws, candidate_id)
    if st["status"] in ("BUDGET_RESERVED", "EVALUATING"):
        try:
            budgets.mark_uncertain(ws, f"eval:{candidate_id}")
        except BudgetError:
            pass
        try:
            candidates.transition(ws, candidate_id, "REJECTED", st["version"], "vep-controller", f"WORKER_LOST:{reason}")
        except StateError:
            pass  # the (now-fenced-out) worker finished a transition first; the state machine stays consistent


def recover(ws: Workspace, now: float | None = None) -> list[dict]:
    """Resolve expired leases. Safe to call from any process, repeatedly."""
    t = _now(now)
    with ws.db.read() as c:
        expired = [dict(r) for r in c.execute("SELECT * FROM jobs WHERE state='LEASED' AND lease_expires < ?", (t,))]
    actions = []
    for job in expired:
        unknown_outcome = False
        st = candidates.get_state(ws, job["candidate_id"])["status"]
        with ws.db.tx() as c:
            cur = c.execute("SELECT state, fence FROM jobs WHERE id=?", (job["id"],)).fetchone()
            if cur["state"] != "LEASED" or cur["fence"] != job["fence"]:
                continue  # someone else resolved it
            if st in PRE_EXECUTION or (st == "EVIDENCE_READY" and job["auto_certify"]):
                if job["attempts"] < job["max_attempts"]:
                    c.execute("UPDATE jobs SET state='QUEUED', owner=NULL, lease_expires=NULL, failure_class='LEASE_EXPIRED' WHERE id=?",
                              (job["id"],))
                    _event(c, job["id"], "REQUEUED", job["owner"], job["fence"], "lease expired before side effects")
                    actions.append({"job": job["id"], "action": "REQUEUED"})
                else:
                    c.execute("UPDATE jobs SET state='FAILED', lease_expires=NULL, failure_class='LEASE_EXPIRED_ATTEMPTS_EXHAUSTED' WHERE id=?",
                              (job["id"],))
                    _event(c, job["id"], "FAILED", job["owner"], job["fence"], "attempts exhausted")
                    actions.append({"job": job["id"], "action": "FAILED_EXHAUSTED"})
            elif st in ("CERTIFIED", "REJECTED", "EVIDENCE_READY"):
                c.execute("UPDATE jobs SET state='SUCCEEDED', lease_expires=NULL, result=? WHERE id=?",
                          (json.dumps({"candidate_status": st, "recovered": True}, sort_keys=True), job["id"]))
                _event(c, job["id"], "SUCCEEDED", job["owner"], job["fence"], f"recovered; candidate {st}")
                actions.append({"job": job["id"], "action": "SUCCEEDED_RECOVERED"})
            else:  # BUDGET_RESERVED / EVALUATING: outcome unknown, side effects may have occurred
                unknown_outcome = True
                c.execute("UPDATE jobs SET state='FAILED', lease_expires=NULL, failure_class='WORKER_LOST_AFTER_EXECUTION_STARTED' WHERE id=?",
                          (job["id"],))
                _event(c, job["id"], "FAILED", job["owner"], job["fence"], "worker lost mid-evaluation; not retried")
                actions.append({"job": job["id"], "action": "FAILED_UNKNOWN_OUTCOME"})
        if unknown_outcome:
            _settle_abandoned_candidate(ws, job["candidate_id"], "lease expired")
    return actions


# ------------------------------------------------------------------ workers
class Worker(Protocol):
    name: str
    mode: str

    def run(self, ws: Workspace, job: dict, guard) -> dict: ...


def _pipeline(ws: Workspace, job: dict, guard, **eval_kw) -> dict:
    cid = job["candidate_id"]
    st = candidates.get_state(ws, cid)["status"]
    out: dict[str, Any] = {"candidate_id": cid}
    if st in ("PROPOSED", "POLICY_CHECKED"):
        r = execution.evaluate(ws, cid, guard=guard, **eval_kw)
        out.update({"verdict": r.get("verdict"), "evidence_id": r.get("evidence_id"), "reason": r.get("reason"),
                    "trust_level": r.get("trust_level")})
        st = r["status"]
    if st == "EVIDENCE_READY" and job["auto_certify"]:
        cert = certificates.certify(ws, cid, guard=guard)
        out["certificate_id"] = cert.id
        st = "CERTIFIED"
    out["candidate_status"] = st
    return out


class LocalToolWorker:
    """Deterministic in-process worker running the protected evaluator in trusted-local mode.

    NO security isolation. Requires the explicit trusted-local authorization string.
    """
    mode = "trusted-local"

    def __init__(self, name: str, trusted_local_authorization: str | None):
        self.name = name
        self._auth = trusted_local_authorization

    def run(self, ws: Workspace, job: dict, guard) -> dict:
        return _pipeline(ws, job, guard, mode="trusted-local", trusted_local_authorization=self._auth,
                         actor=self.name)


class IsolatedWorker:
    """Runs the evaluator through the verified-isolation path. Fails closed: never falls back to the host."""
    mode = "isolated"

    def __init__(self, name: str, image: str | None, attestation: dict | None):
        self.name, self._image, self._attestation = name, image, attestation

    def run(self, ws: Workspace, job: dict, guard) -> dict:
        return _pipeline(ws, job, guard, mode="isolated", image=self._image, attestation=self._attestation,
                         actor=self.name)


def run_one(ws: Workspace, worker: Worker, *, lease_s: float | None = None, now: float | None = None) -> dict | None:
    """Claim and execute at most one job. Returns a summary, or None if nothing was runnable."""
    job = claim(ws, worker.name, lease_s=lease_s, now=now, mode=worker.mode)
    if job is None:
        return None
    jid, fence = job["id"], job["fence"]
    try:
        result = worker.run(ws, job, guard_for(jid, worker.name, fence))
    except StaleLease as exc:
        j = get_job(ws, jid)
        if j["state"] == "CANCELLED":
            _settle_abandoned_candidate(ws, job["candidate_id"], "cancelled")
        return {"job": jid, "outcome": "STALE", "detail": str(exc)}
    except BaseException as exc:  # noqa: BLE001 - classify, record, and re-raise only for control-flow exceptions
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        cls = exc.__class__.__name__
        cand_status = candidates.get_state(ws, job["candidate_id"])["status"]
        retryable = isinstance(exc, TRANSIENT) and cand_status in PRE_EXECUTION
        try:
            fail(ws, jid, worker.name, fence, cls, retryable=retryable, detail=str(exc)[:500])
        except StaleLease:
            return {"job": jid, "outcome": "STALE", "detail": "lost lease while failing"}
        return {"job": jid, "outcome": "REQUEUED" if retryable and get_job(ws, jid)["state"] == "QUEUED" else "FAILED",
                "failure_class": cls, "detail": str(exc)[:500]}
    try:
        complete(ws, jid, worker.name, fence, result)
    except StaleLease as exc:
        return {"job": jid, "outcome": "STALE", "detail": str(exc)}
    return {"job": jid, "outcome": "SUCCEEDED", **result}


def run_until_idle(ws: Workspace, worker: Worker, max_jobs: int | None = None) -> list[dict]:
    done = []
    while max_jobs is None or len(done) < max_jobs:
        r = run_one(ws, worker)
        if r is None:
            break
        done.append(r)
    return done
