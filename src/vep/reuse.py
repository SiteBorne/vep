"""Exact-input evidence reuse with a verifiable derivation chain.

Distinctions (see docs/EVIDENCE_REUSE.md):
  build-cache hit      a cached build output (`vep build`); never evidence of correctness
  signed evidence      what the protected evaluator signed for ONE candidate; never moved to another candidate
  DerivedAttestation   a new signed claim "candidate X has the same source, policy, runner, evaluator and environment as candidate Y, whose signed PASS
                       evidence is E"; it names E by id and envelope digest. It is NOT a certificate and does not change any candidate's status.
Reuse is EXACT only: same snapshot id, same frozen policy id, same runner digest, same evaluator id, same execution environment, same trust level.
Nothing is inferred from dependency graphs, and nothing is skipped inside a run. The chain is verified independently in Python and Node.
"""
from __future__ import annotations

import json

from . import execution, trust, versions
from .canonical import canonical_bytes, sha256_hex
from .errors import StateError, VerificationFailed
from .evidence import KeyStore, load_signed, store_signed
from .objects import VEPObject
from .policies import load_policy
from .snapshots import verify_snapshot
from .workspace import Workspace, utcnow


def _env_digest(ev: VEPObject) -> str:
    return sha256_hex(canonical_bytes(ev["execution_environment"]))


def _current_env(trust_level: str) -> dict | None:
    import sys
    if trust_level == "TRUSTED_LOCAL":
        return {"kind": "host-subprocess", "python": sys.version.split()[0], "platform": sys.platform, "python_flags": "-I", "isolation": "none"}
    return None  # isolated environments are described by an attestation; reuse for them is not offered


def find_original(ws: Workspace, candidate_id: str) -> tuple[VEPObject, str, list[str]]:
    """The first signed PASS evidence from another candidate that matches every exact-input condition, or raises with the reasons."""
    cand = ws.get_object(candidate_id, "Candidate")
    objective = ws.get_object(cand["objective_id"], "Objective")
    policy = load_policy(ws, objective["policy_id"])
    with ws.db.read() as c:
        rows = c.execute("SELECT id, envelope_digest, candidate_id FROM evidence WHERE verdict='PASS' AND candidate_id<>? AND snapshot_id=? AND policy_id=? ORDER BY rowid",
                         (candidate_id, cand["snapshot_id"], policy.id)).fetchall()
    reasons: list[str] = []
    if not rows:
        raise StateError("NO_REUSABLE_EVIDENCE: no PASS evidence exists for this exact snapshot and policy")
    for r in rows:
        ev = load_signed(ws, r["envelope_digest"], "Evidence")  # re-verifies signature and integrity
        why = []
        if ev.schema_version < 2:
            why.append("LEGACY_EVIDENCE")
        else:
            tl = trust.trust_level_of(ev)
            if tl != "TRUSTED_LOCAL":
                why.append("TRUST_LEVEL_NOT_REUSABLE")
            if ev["staged_tree_snapshot_id"] != cand["snapshot_id"]:
                why.append("STAGED_TREE_MISMATCH")
            if ev["runner_digest"] != execution.runner_digest():
                why.append("RUNNER_CHANGED")
            if ev["evaluator_id"] != versions.evaluator_id(tl):
                why.append("EVALUATOR_CHANGED")
            if ev["execution_environment"] != _current_env(tl):
                why.append("ENVIRONMENT_CHANGED")
            if policy.get("required_trust") == "ISOLATED_VERIFIED":
                why.append("POLICY_REQUIRES_ISOLATED")
        if not why:
            return ev, r["envelope_digest"], reasons
        reasons.append(f"{ev.id}: {','.join(why)}")
    raise StateError("NO_REUSABLE_EVIDENCE: " + "; ".join(reasons))


def derive(ws: Workspace, candidate_id: str) -> tuple[VEPObject, str]:
    """Issue (idempotently) a DerivedAttestation for `candidate_id`. Executes nothing."""
    key = f"derived:{candidate_id}"
    with ws.db.read() as c:
        row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if row:
        digest = row["value"]
        return load_signed(ws, digest, "DerivedAttestation"), digest
    cand = ws.get_object(candidate_id, "Candidate")
    objective = ws.get_object(cand["objective_id"], "Objective")
    verify_snapshot(ws, ws.get_object(cand["snapshot_id"], "Snapshot"))
    ev, ev_digest, _ = find_original(ws, candidate_id)
    ks = KeyStore(ws)
    att = VEPObject.create("DerivedAttestation", {
        "candidate_id": candidate_id, "objective_id": objective.id, "snapshot_id": cand["snapshot_id"], "policy_id": objective["policy_id"],
        "original_evidence_id": ev.id, "original_evidence_envelope_digest": ev_digest,
        "original_candidate_id": ev["candidate_id"], "original_objective_id": ev["objective_id"], "reuse_mode": "EXACT_INPUT",
        "trust_level": trust.trust_level_of(ev), "evaluator_id": ev["evaluator_id"], "runner_digest": ev["runner_digest"],
        "environment_digest": _env_digest(ev), "issuer_key_id": ks.key_id(), "issued_at": utcnow()})
    digest = store_signed(ws, att, ks)
    with ws.db.tx() as c:
        c.execute("INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)", (key, digest))
        digest = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()["value"]
    return load_signed(ws, digest, "DerivedAttestation"), digest


def check_chain(att: VEPObject, ev: VEPObject, ev_envelope) -> str:
    """Bindings between an attestation and the original evidence (shared by workspace and portable verification). Returns the trust level."""
    from .conformance import Reject
    if sha256_hex(canonical_bytes(ev_envelope)) != att["original_evidence_envelope_digest"]:
        raise Reject("EVIDENCE_DIGEST_MISMATCH")
    if ev.id != att["original_evidence_id"]:
        raise Reject("IDENTITY_MISMATCH")
    if ev.schema_version < 2:
        raise Reject("LEGACY_EVIDENCE_NOT_REUSABLE")
    if ev["candidate_id"] != att["original_candidate_id"] or ev["objective_id"] != att["original_objective_id"]:
        raise Reject("DERIVATION_ORIGIN_MISMATCH")
    if att["candidate_id"] == ev["candidate_id"]:
        raise Reject("NOT_DERIVED", "the attestation names the evidence's own candidate; verify the certificate instead")
    for k in ("snapshot_id", "policy_id"):
        if ev[k] != att[k]:
            raise Reject("BINDING_MISMATCH", k)
    if ev["staged_tree_snapshot_id"] != att["snapshot_id"]:
        raise Reject("EVIDENCE_SNAPSHOT_MISMATCH")
    tl = trust.trust_level_of(ev)
    if tl == "UNVERIFIED" or att["trust_level"] != tl or att["evaluator_id"] != ev["evaluator_id"]:
        raise Reject("TRUST_BINDING_MISMATCH")
    if att["runner_digest"] != ev["runner_digest"]:
        raise Reject("RUNNER_BINDING_MISMATCH")
    if att["environment_digest"] != _env_digest(ev):
        raise Reject("ENVIRONMENT_BINDING_MISMATCH")
    if ev["verdict"] != "PASS" or ev["tests_passed"] < 1 or ev["tests_skipped"] >= ev["tests_run"] or ev["tests_failed"]:
        raise Reject("EVIDENCE_NOT_PASSING")
    return tl


def export_bundle(ws: Workspace, candidate_id: str) -> dict:
    att, digest = derive(ws, candidate_id)
    ev_digest = att["original_evidence_envelope_digest"]
    return {"bundle_version": 3,
            "attestation_envelope": json.loads(ws.cas.get(digest)),
            "evidence_envelope": json.loads(ws.cas.get(ev_digest))}
