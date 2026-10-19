"""Exact-snapshot certification and independent verification."""
from __future__ import annotations

from pathlib import Path

from . import candidates
from .errors import StateError, VerificationFailed
from .evidence import KeyStore, load_signed, store_signed
from .objects import VEPObject
from .policies import load_policy
from .snapshots import tree_snapshot_id
from .workspace import Workspace, utcnow


def certify(ws: Workspace, candidate_id: str) -> VEPObject:
    st = candidates.get_state(ws, candidate_id)
    if st["status"] != "EVIDENCE_READY":
        raise StateError(f"candidate must be EVIDENCE_READY to certify (is {st['status']})")
    cand = ws.get_object(candidate_id, "Candidate")
    objective = ws.get_object(cand["objective_id"], "Objective")
    with ws.db.read() as c:
        row = c.execute("SELECT id, envelope_digest FROM evidence WHERE candidate_id=? AND verdict='PASS'",
                        (candidate_id,)).fetchone()
    if row is None:
        raise VerificationFailed("no PASS evidence")
    ev = load_signed(ws, row["envelope_digest"], "Evidence")  # re-verifies signature + integrity
    expect = {"candidate_id": candidate_id, "objective_id": objective.id, "snapshot_id": cand["snapshot_id"],
              "policy_id": objective["policy_id"]}
    for k, v in expect.items():
        if ev[k] != v:
            raise VerificationFailed(f"evidence {k} does not match candidate")
    if ev.id != row["id"] or ev["staged_tree_snapshot_id"] != cand["snapshot_id"]:
        raise VerificationFailed("evidence binding mismatch")
    keystore = KeyStore(ws)
    cert = VEPObject.create("Certificate", {
        **expect, "evidence_id": ev.id, "evidence_envelope_digest": row["envelope_digest"],
        "issuer_key_id": keystore.key_id(), "issued_at": utcnow()})
    env_digest = store_signed(ws, cert, keystore)
    with ws.db.tx() as c:
        c.execute("INSERT INTO certificates(id,candidate_id,objective_id,snapshot_id,policy_id,evidence_id,envelope_digest)"
                  " VALUES(?,?,?,?,?,?,?)", (cert.id, candidate_id, objective.id, cand["snapshot_id"],
                                             objective["policy_id"], ev.id, env_digest))
        candidates.transition(ws, candidate_id, "CERTIFIED", st["version"], "vep-certifier",
                              "certificate issued", cert.id, conn=c)
    return cert


def verify_certificate(ws: Workspace, certificate_id: str, *, current_root: Path | None = None,
                       expect_objective_id: str | None = None, expect_policy_id: str | None = None) -> dict:
    """Cryptographically verify a certificate, its evidence, and every binding.

    If current_root is given the live source tree must hash to the certified snapshot.
    Raises VerificationFailed otherwise; never returns a partial success.
    """
    with ws.db.read() as c:
        row = c.execute("SELECT envelope_digest FROM certificates WHERE id=?", (certificate_id,)).fetchone()
    if row is None:
        raise VerificationFailed(f"unknown certificate {certificate_id}")
    cert = load_signed(ws, row["envelope_digest"], "Certificate")
    if cert.id != certificate_id:
        raise VerificationFailed("certificate identity mismatch")
    ev = load_signed(ws, cert["evidence_envelope_digest"], "Evidence")
    checks = ["certificate signature", "evidence signature"]
    if ev.id != cert["evidence_id"]:
        raise VerificationFailed("evidence identity mismatch")
    for k in ("candidate_id", "objective_id", "snapshot_id", "policy_id"):
        if ev[k] != cert[k]:
            raise VerificationFailed(f"evidence/certificate {k} mismatch")
    if ev["verdict"] != "PASS" or ev["tests_passed"] < 1 or ev["tests_skipped"] >= ev["tests_run"] or ev["tests_failed"]:
        raise VerificationFailed("evidence does not establish a passing run")
    if ev["staged_tree_snapshot_id"] != cert["snapshot_id"]:
        raise VerificationFailed("evidence was not produced from the certified snapshot")
    cand = ws.get_object(cert["candidate_id"], "Candidate")
    objective = ws.get_object(cert["objective_id"], "Objective")
    if cand["snapshot_id"] != cert["snapshot_id"] or objective["policy_id"] != cert["policy_id"]:
        raise VerificationFailed("candidate/objective no longer matches certificate bindings")
    load_policy(ws, cert["policy_id"])
    checks += ["evidence binding", "candidate/objective/policy binding"]
    if expect_objective_id and expect_objective_id != cert["objective_id"]:
        raise VerificationFailed("certificate was issued for a different objective")
    if expect_policy_id and expect_policy_id != cert["policy_id"]:
        raise VerificationFailed("certificate was issued under a different policy")
    if current_root is not None:
        now = tree_snapshot_id(Path(current_root))
        if now != cert["snapshot_id"]:
            raise VerificationFailed(f"SOURCE_CHANGED: current tree {now} != certified {cert['snapshot_id']}")
        checks.append("current source equals certified snapshot")
    return {"certificate_id": cert.id, "snapshot_id": cert["snapshot_id"], "policy_id": cert["policy_id"],
            "objective_id": cert["objective_id"], "checks_passed": checks,
            "isolation_of_evidence": ev["isolation"]}
