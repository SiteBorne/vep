"""Candidates and the transactional state machine; work claims; composition checks."""
from __future__ import annotations

import sqlite3
from typing import Any

from .errors import PolicyViolation, StateError
from .objects import VEPObject
from .policies import check_candidate, load_policy
from .snapshots import diff, entries_of, make_snapshot_object, verify_snapshot
from .workspace import Workspace, utcnow

STATES = ["PROPOSED", "POLICY_CHECKED", "BUDGET_RESERVED", "EVALUATING", "EVIDENCE_READY", "CERTIFIED", "REJECTED"]
ALLOWED = {
    "PROPOSED": {"POLICY_CHECKED", "REJECTED"},
    "POLICY_CHECKED": {"BUDGET_RESERVED", "REJECTED"},
    "BUDGET_RESERVED": {"EVALUATING", "REJECTED"},
    "EVALUATING": {"EVIDENCE_READY", "REJECTED"},
    "EVIDENCE_READY": {"CERTIFIED", "REJECTED"},
    "CERTIFIED": set(),
    "REJECTED": set(),
}


def register_candidate(ws: Workspace, objective_id: str, snapshot_id: str, author: str,
                       base_snapshot_id: str | None = None, parent_candidate_id: str | None = None,
                       work_claim_id: str | None = None) -> VEPObject:
    objective = ws.get_object(objective_id, "Objective")
    snap = ws.get_object(snapshot_id, "Snapshot")
    verify_snapshot(ws, snap)
    ws.get_object(base_snapshot_id or objective["base_snapshot_id"], "Snapshot")
    fields: dict[str, Any] = {
        "objective_id": objective_id, "base_snapshot_id": base_snapshot_id or objective["base_snapshot_id"],
        "snapshot_id": snapshot_id, "author": author, "created_at": utcnow()}
    if parent_candidate_id:
        ws.get_object(parent_candidate_id, "Candidate")
        fields["parent_candidate_id"] = parent_candidate_id
    if work_claim_id:
        ws.get_object(work_claim_id, "WorkClaim")
        fields["work_claim_id"] = work_claim_id
    cand = VEPObject.create("Candidate", fields)
    ws.put_object(cand)
    with ws.db.tx() as c:
        c.execute("INSERT OR IGNORE INTO candidates(id,objective_id,snapshot_id,status,version,created_at)"
                  " VALUES(?,?,?, 'PROPOSED', 0, ?)", (cand.id, objective_id, snapshot_id, utcnow()))
        c.execute("INSERT OR IGNORE INTO transitions(candidate_id,from_status,to_status,to_version,actor,reason,at)"
                  " VALUES(?,NULL,'PROPOSED',0,?,?,?)", (cand.id, author, "registered", utcnow()))
    return cand


def get_state(ws: Workspace, candidate_id: str) -> dict:
    with ws.db.read() as c:
        row = c.execute("SELECT * FROM candidates WHERE id=?", (candidate_id,)).fetchone()
    if row is None:
        raise StateError(f"unknown candidate {candidate_id}")
    return dict(row)


def history(ws: Workspace, candidate_id: str) -> list[dict]:
    with ws.db.read() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM transitions WHERE candidate_id=? ORDER BY seq", (candidate_id,))]


def transition(ws: Workspace, candidate_id: str, to_status: str, expected_version: int,
               actor: str, reason: str, proof_id: str | None = None, conn: sqlite3.Connection | None = None) -> int:
    """Compare-and-swap transition. Rejects stale versions and illegal edges. Returns new version."""
    if to_status not in STATES:
        raise StateError(f"unknown status {to_status!r}")

    def run(c: sqlite3.Connection) -> int:
        row = c.execute("SELECT status, version FROM candidates WHERE id=?", (candidate_id,)).fetchone()
        if row is None:
            raise StateError(f"unknown candidate {candidate_id}")
        if row["version"] != expected_version:
            raise StateError(f"stale version: expected {expected_version}, current {row['version']}")
        if to_status not in ALLOWED[row["status"]]:
            raise StateError(f"illegal transition {row['status']} -> {to_status}")
        new_v = expected_version + 1
        try:
            cur = c.execute("UPDATE candidates SET status=?, version=? WHERE id=? AND version=?",
                            (to_status, new_v, candidate_id, expected_version))
            if cur.rowcount != 1:
                raise StateError("concurrent modification")
            c.execute("INSERT INTO transitions(candidate_id,from_status,to_status,to_version,actor,reason,proof_id,at)"
                      " VALUES(?,?,?,?,?,?,?,?)",
                      (candidate_id, row["status"], to_status, new_v, actor, reason, proof_id, utcnow()))
        except sqlite3.IntegrityError as exc:
            raise StateError(f"invariant rejected transition: {exc}") from exc
        return new_v

    if conn is not None:
        return run(conn)
    with ws.db.tx() as c:
        return run(c)


def check_policy(ws: Workspace, candidate_id: str, actor: str = "vep-policy-checker") -> list[str]:
    """PROPOSED -> POLICY_CHECKED, or REJECTED with recorded violations."""
    st = get_state(ws, candidate_id)
    cand = ws.get_object(candidate_id, "Candidate")
    objective = ws.get_object(cand["objective_id"], "Objective")
    policy = load_policy(ws, objective["policy_id"])
    base = ws.get_object(objective["base_snapshot_id"], "Snapshot")
    snap = ws.get_object(cand["snapshot_id"], "Snapshot")
    verify_snapshot(ws, snap)
    violations = check_candidate(policy, base, snap)
    if violations:
        transition(ws, candidate_id, "REJECTED", st["version"], actor, "; ".join(violations))
        return violations
    transition(ws, candidate_id, "POLICY_CHECKED", st["version"], actor, "policy ok", proof_id=policy.id)
    return []


# --- work claims & composition (F19) -------------------------------------
def create_work_claim(ws: Workspace, objective_id: str, claimant: str, paths: list[str],
                      expires_at: str) -> VEPObject:
    obj = ws.get_object(objective_id, "Objective")
    claim = VEPObject.create("WorkClaim", {
        "objective_id": objective_id, "claimant": claimant, "base_snapshot_id": obj["base_snapshot_id"],
        "paths": sorted(set(paths)), "created_at": utcnow(), "expires_at": expires_at})
    ws.put_object(claim)
    return claim


def claims_overlap(a: VEPObject, b: VEPObject) -> list[str]:
    def covers(x: str, y: str) -> bool:
        return x == y or y.startswith(x.rstrip("/") + "/") or x.startswith(y.rstrip("/") + "/")
    return sorted({x for x in a["paths"] for y in b["paths"] if covers(x, y)})


def compose(ws: Workspace, base_id: str, cand_a_id: str, cand_b_id: str) -> dict:
    """Three-way merge of two candidates over a common base.

    Returns {'conflicts': [...], 'snapshot': Snapshot|None}. A composed snapshot is a NEW
    source identity: neither candidate's evidence or certificate applies to it.
    """
    base = ws.get_object(base_id, "Snapshot")
    a = ws.get_object(ws.get_object(cand_a_id, "Candidate")["snapshot_id"], "Snapshot")
    b = ws.get_object(ws.get_object(cand_b_id, "Candidate")["snapshot_id"], "Snapshot")
    eb, ea, ebb = entries_of(base), entries_of(a), entries_of(b)
    out: dict[str, dict] = dict(eb)
    conflicts = []
    for path in sorted(set(eb) | set(ea) | set(ebb)):
        va, vb, v0 = ea.get(path), ebb.get(path), eb.get(path)
        ca, cb = va != v0, vb != v0
        if ca and cb and va != vb:
            conflicts.append(path)
            continue
        chosen = va if ca else vb
        if ca or cb:
            if chosen is None:
                out.pop(path, None)
            else:
                out[path] = chosen
    if conflicts:
        return {"conflicts": conflicts, "snapshot": None}
    snap = make_snapshot_object([out[p] for p in sorted(out)])
    ws.put_object(snap)
    return {"conflicts": [], "snapshot": snap}


__all__ = ["register_candidate", "get_state", "history", "transition", "check_policy", "create_work_claim",
           "claims_overlap", "compose", "STATES", "ALLOWED", "PolicyViolation", "diff"]
