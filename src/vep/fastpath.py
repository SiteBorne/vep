"""Agent iteration fast path: three outcomes that are never substituted for one another.

    FRESH_CERTIFICATE     the protected evaluation ran for this candidate; signed evidence and an exact-snapshot certificate exist
    DERIVED_ATTESTATION   identical source, policy, runner, evaluator and environment as a candidate that already has signed PASS evidence;
                          a DerivedAttestation names the original proof. Not a certificate; nothing was executed
    ADVISORY_FEEDBACK     fast, unprotected feedback from the tests that the static import graph says a change can affect. Heuristic, never evidence;
                          it changes no candidate state and can never become a certificate

The caller states the contract with `mode`; the result always carries `outcome`, `assurance`, and whether anything was executed. A mode never falls back to a
weaker outcome by itself: `reuse_only` returns NO_REUSABLE_EVIDENCE rather than evaluating, `fresh` always evaluates, `reuse_if_identical` is the explicit opt-in
that may use a derived attestation and otherwise performs the fresh protected evaluation (reported as such), and `advisory` is advisory.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from . import candidates, controller, depgraph, execution, reuse
from .errors import PolicyViolation, StateError
from .policies import load_policy
from .workspace import Workspace

MODES = ("fresh", "reuse_only", "reuse_if_identical", "advisory")


def _base(candidate_id: str, mode: str, **kw) -> dict:
    return {"candidate_id": candidate_id, "mode": mode, **kw}


def verify(ws: Workspace, candidate_id: str, *, mode: str = "fresh", worker_name: str = "fastpath", root: Path | None = None,
           previous_snapshot_id: str | None = None, timeout_s: int = 300) -> dict:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    t0 = time.perf_counter()
    if mode == "advisory":
        out = advisory(ws, candidate_id, root=root, previous_snapshot_id=previous_snapshot_id, timeout_s=timeout_s)
        out["elapsed_s"] = round(time.perf_counter() - t0, 4)
        return out
    if mode in ("reuse_only", "reuse_if_identical"):
        try:
            att, digest = reuse.derive(ws, candidate_id)
            return _base(candidate_id, mode, outcome="DERIVED_ATTESTATION", assurance="DERIVED_EXACT_INPUT (not a certificate)", executed=False, certificate_id=None,
                         attestation_id=att.id, original_evidence_id=att["original_evidence_id"], original_candidate_id=att["original_candidate_id"],
                         elapsed_s=round(time.perf_counter() - t0, 4), candidate_status=candidates.get_state(ws, candidate_id)["status"])
        except StateError as exc:
            if not str(exc).startswith("NO_REUSABLE_EVIDENCE"):
                raise
            if mode == "reuse_only":
                return _base(candidate_id, mode, outcome="NO_REUSABLE_EVIDENCE", assurance=None, executed=False, certificate_id=None, reason=str(exc)[:300],
                             elapsed_s=round(time.perf_counter() - t0, 4), candidate_status=candidates.get_state(ws, candidate_id)["status"])
    # fresh protected evaluation (explicit `fresh`, or the declared fallback of `reuse_if_identical`)
    controller.enqueue(ws, candidate_id)
    res = controller.run_one(ws, controller.LocalToolWorker(worker_name, execution.TRUSTED_LOCAL_AUTH))
    st = res.get("candidate_status") if res else None
    out = _base(candidate_id, mode, executed=True, elapsed_s=round(time.perf_counter() - t0, 4), candidate_status=st,
                reuse_attempted=mode == "reuse_if_identical")
    if st == "CERTIFIED":
        out.update(outcome="FRESH_CERTIFICATE", assurance="PROTECTED_EVALUATION (TRUSTED_LOCAL certificate)", certificate_id=res["certificate_id"], evidence_id=res.get("evidence_id"))
    else:
        out.update(outcome="REJECTED" if st == "REJECTED" else "FAILED", assurance=None, certificate_id=None, reason=str(res)[:300])
    return out


def affected_tests(ws: Workspace, candidate_id: str, previous_snapshot_id: str) -> tuple[list[str], str]:
    st = candidates.get_state(ws, candidate_id)
    graph = depgraph.build_graph(ws, st["snapshot_id"])
    impact = depgraph.impact(ws, graph, previous_snapshot_id, st["snapshot_id"])
    paths = sorted(impact["affected_by_static_analysis"])
    return [p for p in paths if p.rsplit("/", 1)[-1].startswith("test") and p.endswith(".py")], st["snapshot_id"]


def advisory(ws: Workspace, candidate_id: str, *, root: Path | None, previous_snapshot_id: str | None, timeout_s: int = 300) -> dict:
    """Run only the tests the static import graph says the change can affect, in the caller's working tree, unprotected. Heuristic by construction."""
    if root is None or previous_snapshot_id is None:
        raise ValueError("advisory feedback needs the working tree `root` and the `previous_snapshot_id` to diff against")
    tests, snap_id = affected_tests(ws, candidate_id, previous_snapshot_id)
    mods = [t[:-3].replace("/", ".") for t in tests]
    if not mods:
        rc, ran = 0, 0
    else:
        r = subprocess.run([sys.executable, "-I", "-m", "unittest", *mods], cwd=root, capture_output=True, text=True, timeout=timeout_s)
        rc, ran = r.returncode, len(mods)
    return _base(candidate_id, "advisory", outcome="ADVISORY_FEEDBACK", assurance="ADVISORY_ONLY (heuristic selection; not evidence, not a certificate)", executed=True, certificate_id=None,
                 advisory_pass=rc == 0, test_modules_run=ran, selection="static import graph; dynamic imports and non-Python dependencies are not seen",
                 candidate_status=candidates.get_state(ws, candidate_id)["status"])
