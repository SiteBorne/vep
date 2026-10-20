"""Application services shared by every external surface (MCP server, A2A adapter, Claude hooks).

Surfaces translate protocol messages into these calls and nothing else; no domain rule lives in an adapter. Every function returns a
bounded, JSON-serializable dict and raises ServiceError with a stable code. Authority is configured by the operator who starts the
server (never by the caller); nothing here lets a caller assert a verdict, and certification happens only inside the controller after a
protected evaluation.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

from . import budgets, candidates, certificates, conformance, controller, execution, git_adapter, isolation, objectives, policies, snapshots, versions
from .errors import (AuthorizationError, BudgetError, ExecutionError, FalseGreen, IsolationUnavailable, ObjectNotFound, PolicyViolation, SchemaError,
                     StateError, VepError, VerificationFailed)
from .workspace import Workspace

ERROR_CODES = ("VEP_E_INVALID_ARGUMENT", "VEP_E_NOT_FOUND", "VEP_E_NOT_AUTHORIZED", "VEP_E_EVALUATION_DISABLED", "VEP_E_STATE", "VEP_E_BUDGET",
               "VEP_E_POLICY", "VEP_E_VERIFICATION_FAILED", "VEP_E_ISOLATION_UNAVAILABLE", "VEP_E_INTERNAL")
AUTHORITIES = ("read", "register", "evaluate", "export")
ID_RE = re.compile(r"^[a-z]+-[0-9a-f]{64}$")
JOB_RE = re.compile(r"^job-[0-9a-f]{32}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_PAGE = 200
MAX_ARTIFACT_PAGE = 4000
MAX_TEXT = 2000


class ServiceError(Exception):
    def __init__(self, code: str, message: str, **detail: Any):
        super().__init__(message)
        assert code in ERROR_CODES, code
        self.code, self.message, self.detail = code, message[:MAX_TEXT], detail

    def to_dict(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message, **self.detail}}


@dataclass
class Context:
    """Operator-configured authority for one server process. Callers cannot change it."""
    root: Path
    authority: frozenset[str] = frozenset({"read"})
    trusted_local_execution: bool = False   # the operator's explicit acknowledgement that candidate code runs unisolated on this host
    actor: str = "vep-service"
    _worker: "EvaluationWorker | None" = field(default=None, repr=False)

    def ws(self) -> Workspace:
        try:
            return Workspace(self.root)
        except VepError as exc:
            raise ServiceError("VEP_E_NOT_FOUND", str(exc)) from exc

    def need(self, authority: str) -> None:
        if authority not in self.authority:
            raise ServiceError("VEP_E_NOT_AUTHORIZED", f"this server was not started with the '{authority}' authority", required=authority,
                               granted=sorted(self.authority))

    def worker(self) -> "EvaluationWorker":
        if self._worker is None:
            self._worker = EvaluationWorker(self)
        return self._worker


def ident(value: Any, kind: str | None = None, name: str = "id") -> str:
    if not isinstance(value, str) or not ID_RE.match(value) or (kind and not value.startswith(kind + "-")):
        raise ServiceError("VEP_E_INVALID_ARGUMENT", f"{name} is not a valid {kind or 'object'} id")
    return value


def _guard(fn):
    """Translate domain exceptions into stable service errors; unknown failures become VEP_E_INTERNAL without leaking details."""
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except ServiceError:
            raise
        except ObjectNotFound as exc:
            raise ServiceError("VEP_E_NOT_FOUND", str(exc)) from exc
        except (SchemaError, ValueError) as exc:
            raise ServiceError("VEP_E_INVALID_ARGUMENT", str(exc)) from exc
        except BudgetError as exc:
            raise ServiceError("VEP_E_BUDGET", str(exc)) from exc
        except (PolicyViolation, FalseGreen) as exc:
            raise ServiceError("VEP_E_POLICY", str(exc)) from exc
        except StateError as exc:
            raise ServiceError("VEP_E_NOT_FOUND" if str(exc).startswith("unknown ") else "VEP_E_STATE", str(exc)) from exc
        except IsolationUnavailable as exc:
            raise ServiceError("VEP_E_ISOLATION_UNAVAILABLE", str(exc)) from exc
        except AuthorizationError as exc:
            raise ServiceError("VEP_E_NOT_AUTHORIZED", str(exc)) from exc
        except VerificationFailed as exc:
            raise ServiceError("VEP_E_VERIFICATION_FAILED", str(exc)) from exc
        except (ExecutionError, VepError, sqlite3.Error) as exc:
            raise ServiceError("VEP_E_INTERNAL", f"{exc.__class__.__name__}") from exc
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ---------------------------------------------------------------- idempotency
def _idem(ws: Workspace, scope: str, key: str | None, produce) -> dict:
    """Run `produce` at most once per (scope, key); repeats return the stored result."""
    if key is None:
        return produce()
    if not KEY_RE.match(key):
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "idempotency_key must match [A-Za-z0-9._:-]{1,128}")
    mkey = f"idem:{scope}:{key}"
    with ws.db.read() as c:
        row = c.execute("SELECT value FROM meta WHERE key=?", (mkey,)).fetchone()
    if row:
        return {**json.loads(row["value"]), "idempotent_replay": True}
    result = produce()
    with ws.db.tx() as c:
        c.execute("INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)", (mkey, json.dumps(result, sort_keys=True)))
        stored = c.execute("SELECT value FROM meta WHERE key=?", (mkey,)).fetchone()["value"]
    return json.loads(stored)


# ---------------------------------------------------------------- reads
@_guard
def status(ctx: Context) -> dict:
    ctx.need("read")
    ws = ctx.ws()
    with ws.db.read() as c:
        by_status = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM candidates GROUP BY status")}
        jobs = {r["state"]: r["n"] for r in c.execute("SELECT state, COUNT(*) n FROM jobs GROUP BY state")}
        n_obj = c.execute("SELECT COUNT(*) n FROM objects WHERE type='Objective'").fetchone()["n"]
        n_cert = c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"]
    return {"ok": True, "versions": {"package": versions.PACKAGE_VERSION, "protocol": versions.PROTOCOL_VERSION, "database_schema": versions.DB_SCHEMA_VERSION},
            "objectives": n_obj, "candidates_by_status": by_status, "jobs_by_state": jobs, "certificates": n_cert,
            "git": {k: v for k, v in git_adapter.inspect(ws.root).items() if k != "status"},
            "isolation": isolation.probe().to_dict()["status"],
            "server_authority": sorted(ctx.authority), "evaluation_enabled": "evaluate" in ctx.authority and ctx.trusted_local_execution,
            "execution_mode": "trusted-local (NO security isolation)",
            "next_action": "vep_objective_create" if n_obj == 0 else "vep_candidate_register"}


@_guard
def objective_summary(ctx: Context, objective_id: str) -> dict:
    ctx.need("read")
    ws = ctx.ws()
    obj = ws.get_object(ident(objective_id, "obj", "objective_id"), "Objective")
    pol = policies.load_policy(ws, obj["policy_id"])
    return {"ok": True, "objective_id": obj.id, "title": obj["title"][:200], "base_snapshot_id": obj["base_snapshot_id"], "policy_id": pol.id,
            "created_at": obj["created_at"], "required_test_files": len(pol["required_tests"]), "required_trust": pol.get("required_trust"),
            "evaluator": {k: pol["evaluator"].get(k) for k in ("kind", "start_dir", "min_tests")}, "limits": pol["limits"],
            "protected_patterns": pol["protected_patterns"][:20]}


@_guard
def policy_summary(ctx: Context, policy_id: str) -> dict:
    ctx.need("read")
    pol = policies.load_policy(ctx.ws(), ident(policy_id, "pol", "policy_id"))
    return {"ok": True, "policy_id": pol.id, "name": pol["name"], "evaluator": pol["evaluator"], "limits": pol["limits"], "required_tests": sorted(pol["required_tests"])[:MAX_PAGE],
            "required_test_count": len(pol["required_tests"]), "protected_patterns": pol["protected_patterns"], "required_trust": pol.get("required_trust")}


@_guard
def candidate_state(ctx: Context, candidate_id: str) -> dict:
    ctx.need("read")
    ws = ctx.ws()
    st = candidates.get_state(ws, ident(candidate_id, "cand", "candidate_id"))
    with ws.db.read() as c:
        cert = c.execute("SELECT id FROM certificates WHERE candidate_id=?", (candidate_id,)).fetchone()
        ev = c.execute("SELECT id, verdict, trust_level FROM evidence WHERE candidate_id=?", (candidate_id,)).fetchone()
    return {"ok": True, "candidate_id": candidate_id, "status": st["status"], "version": st["version"], "objective_id": st["objective_id"], "snapshot_id": st["snapshot_id"],
            "evidence": None if ev is None else {"evidence_id": ev["id"], "verdict": ev["verdict"], "trust_level": ev["trust_level"]},
            "certificate_id": cert["id"] if cert else None,
            "next_action": {"PROPOSED": "vep_evaluate", "POLICY_CHECKED": "vep_evaluate", "CERTIFIED": "vep_export_evidence", "REJECTED": "vep_explain_failure"}.get(st["status"], "vep_job_status")}


@_guard
def history(ctx: Context, candidate_id: str, offset: int = 0, limit: int = 50) -> dict:
    ctx.need("read")
    offset, limit = _page(offset, limit)
    rows = candidates.history(ctx.ws(), ident(candidate_id, "cand", "candidate_id"))
    page = rows[offset:offset + limit]
    return {"ok": True, "candidate_id": candidate_id, "total": len(rows), "offset": offset, "entries": [
        {"seq": r["seq"], "from": r["from_status"], "to": r["to_status"], "actor": r["actor"], "reason": r["reason"][:300], "proof_id": r["proof_id"], "at": r["at"]} for r in page],
        "next_offset": offset + limit if offset + limit < len(rows) else None}


@_guard
def evidence_summary(ctx: Context, evidence_id: str) -> dict:
    ctx.need("read")
    ws = ctx.ws()
    ev = ws.get_object(ident(evidence_id, "evd", "evidence_id"), "Evidence")
    f = ev.fields
    return {"ok": True, "evidence_id": ev.id, "schema_version": ev.schema_version, "candidate_id": f["candidate_id"], "snapshot_id": f["snapshot_id"], "policy_id": f["policy_id"],
            "verdict": f["verdict"], "trust_level": f.get("trust_level"), "evaluator_id": f.get("evaluator_id"),
            "tests": {k: f[k] for k in ("tests_discovered", "tests_run", "tests_passed", "tests_failed", "tests_skipped")},
            "started_at": f["started_at"], "finished_at": f["finished_at"],
            "handles": {"stdout": f["stdout_digest"], "stderr": f["stderr_digest"]},
            "note": "full output is not inlined; page it with vep_read_artifact using a handle"}


def _page(offset: Any, limit: Any) -> tuple[int, int]:
    if isinstance(offset, bool) or isinstance(limit, bool) or not isinstance(offset, int) or not isinstance(limit, int) or offset < 0 or not 1 <= limit <= MAX_PAGE:
        raise ServiceError("VEP_E_INVALID_ARGUMENT", f"offset must be >= 0 and limit within 1..{MAX_PAGE}")
    return offset, limit


@_guard
def budget_status(ctx: Context, objective_id: str) -> dict:
    ctx.need("read")
    ws = ctx.ws()
    ident(objective_id, "obj", "objective_id")
    return {"ok": True, **budgets.report(ws, f"objective:{objective_id}"), "note": "amounts are USD; local compute is measured elsewhere and not monetized"}


@_guard
def read_artifact(ctx: Context, digest: str, offset: int = 0, limit: int = MAX_ARTIFACT_PAGE) -> dict:
    """Page through a stored execution log. Only digests referenced by this workspace's evidence are readable."""
    ctx.need("read")
    if not isinstance(digest, str) or not DIGEST_RE.match(digest):
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "digest must be 64 lowercase hex characters")
    if isinstance(offset, bool) or isinstance(limit, bool) or not isinstance(offset, int) or not isinstance(limit, int) or offset < 0 or not 1 <= limit <= MAX_ARTIFACT_PAGE:
        raise ServiceError("VEP_E_INVALID_ARGUMENT", f"offset >= 0 and 1 <= limit <= {MAX_ARTIFACT_PAGE}")
    ws = ctx.ws()
    refs = _artifact_digests(ws)
    if digest not in refs:
        raise ServiceError("VEP_E_NOT_FOUND", "no evidence in this workspace references that digest")
    data = ws.cas.get(digest)
    chunk = data[offset:offset + limit]
    return {"ok": True, "digest": digest, "total_bytes": len(data), "offset": offset, "text": chunk.decode("utf-8", "replace"),
            "next_offset": offset + limit if offset + limit < len(data) else None}


def _artifact_digests(ws: Workspace) -> set[str]:
    out: set[str] = set()
    with ws.db.read() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM evidence")]
    for i in ids:
        f = ws.get_object(i, "Evidence").fields
        out.update((f["stdout_digest"], f["stderr_digest"]))
    return out


# ---------------------------------------------------------------- writes (authority-gated)
@_guard
def objective_create(ctx: Context, title: str, description: str = "", budget: str = "1.00", idempotency_key: str | None = None) -> dict:
    """Snapshot the current tree, freeze the default acceptance policy (existing tests protected by digest) and open a budget."""
    ctx.need("register")
    if not isinstance(title, str) or not 1 <= len(title) <= 200 or not isinstance(description, str) or len(description) > 4000:
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "title must be 1..200 characters; description at most 4000")
    ws = ctx.ws()

    def produce():
        base = snapshots.take_snapshot(ws)
        pol = policies.make_policy(ws, base, name="default")
        obj = objectives.create_objective(ws, title, description, base.id, pol.id, created_by=ctx.actor)
        budgets.create_account(ws, f"objective:{obj.id}", "objective", budget)
        return {"ok": True, "objective_id": obj.id, "policy_id": pol.id, "base_snapshot_id": base.id, "required_test_files": len(pol["required_tests"]),
                "next_action": "vep_candidate_register after making the change"}
    return _idem(ws, "objective_create", idempotency_key, produce)


@_guard
def candidate_register(ctx: Context, objective_id: str, author: str = "agent", idempotency_key: str | None = None) -> dict:
    """Register the CURRENT working tree as a candidate. It stays PROPOSED: registering never evaluates or certifies anything."""
    ctx.need("register")
    ident(objective_id, "obj", "objective_id")
    if not isinstance(author, str) or not 1 <= len(author) <= 120:
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "author must be 1..120 characters")
    ws = ctx.ws()

    def produce():
        snap = snapshots.take_snapshot(ws)
        cand = candidates.register_candidate(ws, objective_id, snap.id, author)
        violations = candidates.check_policy(ws, cand.id)
        return {"ok": True, "candidate_id": cand.id, "snapshot_id": snap.id, "status": candidates.get_state(ws, cand.id)["status"],
                "policy_violations": violations, "next_action": "vep_explain_failure" if violations else "vep_evaluate"}
    return _idem(ws, "candidate_register", idempotency_key, produce)


class EvaluationWorker:
    """Background worker that runs queued jobs through the durable controller. Exists only when the operator enabled evaluation."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="vep-eval-worker", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        import time
        worker = controller.LocalToolWorker(f"{self.ctx.actor}-worker", execution.TRUSTED_LOCAL_AUTH)
        ws = self.ctx.ws()
        while not self._stop.is_set():
            try:
                if controller.run_one(ws, worker) is None:
                    time.sleep(0.2)
            except Exception:  # noqa: BLE001 - the controller records failures; the loop must survive them
                time.sleep(1.0)

    def stop(self) -> None:
        self._stop.set()


@_guard
def evaluate(ctx: Context, candidate_id: str) -> dict:
    """Queue a protected evaluation. Idempotent per candidate. The caller never supplies a verdict or the execution authorization."""
    ctx.need("evaluate")
    if not ctx.trusted_local_execution:
        raise ServiceError("VEP_E_EVALUATION_DISABLED", "evaluation runs candidate code unisolated; the operator must start the server with --trusted-local-execution")
    ws = ctx.ws()
    job = controller.enqueue(ws, ident(candidate_id, "cand", "candidate_id"), mode="trusted-local")
    ctx.worker()
    return {"ok": True, **_job_view(ws, job), "next_action": "vep_job_status"}


def _job_view(ws: Workspace, job: dict, events_limit: int = 0) -> dict:
    result = json.loads(job["result"]) if job.get("result") else None
    out = {"job_id": job["id"], "candidate_id": job["candidate_id"], "state": job["state"], "attempts": job["attempts"], "max_attempts": job["max_attempts"],
           "failure_class": job["failure_class"], "mode": job["mode"]}
    if result:
        out["result"] = {k: result.get(k) for k in ("candidate_status", "verdict", "trust_level", "evidence_id", "certificate_id", "reason") if result.get(k) is not None}
    if events_limit:
        out["events"] = [{"event": e["event"], "worker": e["worker"], "detail": (e["detail"] or "")[:200], "at": e["at"]} for e in controller.events(ws, job["id"])[-events_limit:]]
    return out


@_guard
def job_status(ctx: Context, job_id: str | None = None, candidate_id: str | None = None) -> dict:
    ctx.need("read")
    ws = ctx.ws()
    if (job_id is None) == (candidate_id is None):
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "give exactly one of job_id or candidate_id")
    if job_id is not None:
        if not isinstance(job_id, str) or not JOB_RE.match(job_id):
            raise ServiceError("VEP_E_INVALID_ARGUMENT", "job_id is not a valid job id")
        jid = job_id
    else:
        jid = controller.job_id_for(ident(candidate_id, "cand", "candidate_id"))
    try:
        job = controller.get_job(ws, jid)
    except StateError as exc:
        raise ServiceError("VEP_E_NOT_FOUND", str(exc)) from exc
    view = _job_view(ws, job, events_limit=10)
    terminal = job["state"] in controller.TERMINAL
    view["next_action"] = ("vep_explain_failure" if (job["state"] == "FAILED" or (view.get("result", {}).get("candidate_status") == "REJECTED"))
                           else "vep_export_evidence" if view.get("result", {}).get("certificate_id") else "vep_job_status" if not terminal else "vep_candidate_state")
    return {"ok": True, **view}


@_guard
def cancel_job(ctx: Context, job_id: str) -> dict:
    """Cancel a non-terminal job (idempotent on terminal jobs). A running worker's later commits are refused by the lease fence."""
    ctx.need("evaluate")
    if not isinstance(job_id, str) or not JOB_RE.match(job_id):
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "job_id is not a valid job id")
    ws = ctx.ws()
    try:
        return {"ok": True, **_job_view(ws, controller.cancel(ws, job_id))}
    except StateError as exc:
        raise ServiceError("VEP_E_NOT_FOUND", str(exc)) from exc


@_guard
def verify_certificate(ctx: Context, certificate_id: str, require_trust: str = "TRUSTED_LOCAL", check_current_source: bool = False) -> dict:
    """Verify against THIS workspace's own key registry. This is not an external trust anchor; use a trust policy for relying-party checks."""
    ctx.need("read")
    if require_trust not in ("TRUSTED_LOCAL", "ISOLATED_VERIFIED"):
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "require_trust must be TRUSTED_LOCAL or ISOLATED_VERIFIED")
    ws = ctx.ws()
    ident(certificate_id, "cert", "certificate_id")
    try:
        r = certificates.verify_certificate(ws, certificate_id, current_root=ws.root if check_current_source else None, require_trust=require_trust)
    except VerificationFailed as exc:
        return {"ok": True, "valid": False, "code": "VEP_E_VERIFICATION_FAILED", "reason": str(exc)[:300], "assurance": "WORKSPACE_KEY_REGISTRY"}
    return {"ok": True, "valid": True, "assurance": "WORKSPACE_KEY_REGISTRY", "trust_level": r["trust_level"], "snapshot_id": r["snapshot_id"], "objective_id": r["objective_id"],
            "policy_id": r["policy_id"], "evaluator_id": r["evaluator_id"], "checks_passed": r["checks_passed"], "current_source_checked": check_current_source,
            "note": "valid against this workspace's own signing keys only; relying parties should verify an exported bundle against their own trust policy"}


@_guard
def export_evidence(ctx: Context, certificate_id: str, bundle_version: int = 2) -> dict:
    """Write a portable bundle under .vep/exports and return a handle (path, size, hash), not the bundle."""
    ctx.need("export")
    if bundle_version not in (1, 2):
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "bundle_version must be 1 or 2")
    ws = ctx.ws()
    b = conformance.export_bundle(ws, ident(certificate_id, "cert", "certificate_id"), version=bundle_version)
    data = json.dumps(b, indent=1, sort_keys=True).encode()
    out = ws.state / "exports"
    out.mkdir(exist_ok=True)
    path = out / f"{certificate_id}.v{bundle_version}.bundle.json"
    path.write_bytes(data)
    return {"ok": True, "certificate_id": certificate_id, "bundle_version": bundle_version, "path": str(path.relative_to(ws.root)), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "assurance": "INTERNAL_CONSISTENCY_ONLY" if bundle_version == 1 else "needs a relying-party trust policy (vep conformance verify --trust-policy)",
            "next_action": "give the file and your trust policy to the relying party"}


REASON_HELP = {
    "REQUIRED_TEST_MODIFIED": ("A test that existed when the objective was created was changed or deleted.", "Restore the protected test file; add new tests as new files instead."),
    "RUNNER_SHADOWING": ("A new or changed file would shadow a module the test runner depends on.", "Rename the module or directory so it does not shadow standard-library or runner names."),
    "STATIC_AUDIT_FAILED": ("A static audit rule of the frozen policy failed.", "Fix the reported rule violations in the candidate."),
    "FALSE_GREEN": ("The run looked successful but could not establish that the required tests passed.", "Make sure the required test files actually run and are not all skipped."),
    "TOO_FEW_PASSING_TESTS": ("Fewer tests passed than the policy requires, so no passing evidence exists.", "Fix the failing tests; if all of them fail, the change likely broke core behaviour."),
    "ZERO_TESTS": ("No tests were discovered and executed.", "Check the evaluator start directory and test file pattern."),
    "ALL_SKIPPED": ("Every test was skipped.", "Remove the skip condition or run on a platform where the tests execute."),
    "REQUIRED_SUITE_NOT_EXECUTED": ("A required test file did not run.", "Check imports and discovery for that file."),
    "CODE_UNDER_TEST_SHADOWED": ("The tests imported an installed copy of the code instead of the candidate.", "Evaluate in an environment where the project is not installed."),
    "TIMEOUT": ("The evaluation exceeded its time limit.", "Speed up the tests or raise the policy timeout in a new objective."),
    "WORKSPACE_MUTATED_DURING_EVALUATION": ("The tests modified the source tree while running.", "Make the tests write only to temporary directories."),
    "VEP_STATE_TAMPERED": ("The tests touched VEP's own state.", "Do not access the .vep directory from tests."),
    "tests failed": ("One or more tests failed.", "See the failing tests in the evidence output and fix them."),
}


@_guard
def explain_failure(ctx: Context, candidate_id: str | None = None, job_id: str | None = None) -> dict:
    ctx.need("read")
    ws = ctx.ws()
    if candidate_id is None and job_id is not None:
        if not isinstance(job_id, str) or not JOB_RE.match(job_id):
            raise ServiceError("VEP_E_INVALID_ARGUMENT", "job_id is not a valid job id")
        try:
            candidate_id = controller.get_job(ws, job_id)["candidate_id"]
        except StateError as exc:
            raise ServiceError("VEP_E_NOT_FOUND", str(exc)) from exc
    if candidate_id is None:
        raise ServiceError("VEP_E_INVALID_ARGUMENT", "give candidate_id or job_id")
    ident(candidate_id, "cand", "candidate_id")
    st = candidates.get_state(ws, candidate_id)
    hist = candidates.history(ws, candidate_id)
    reason = hist[-1]["reason"] if hist else ""
    job = None
    try:
        job = controller.get_job(ws, controller.job_id_for(candidate_id))
    except StateError:
        pass
    specific = [k for k in REASON_HELP if k != "tests failed" and k in reason]
    code = max(specific, key=len) if specific else ("tests failed" if "tests failed" in reason else None)  # the most specific known code wins
    out: dict[str, Any] = {"ok": True, "candidate_id": candidate_id, "status": st["status"], "failed": st["status"] == "REJECTED" or bool(job and job["state"] == "FAILED"),
                           "reason_code": code, "recorded_reason": reason[:500]}
    if job and job["failure_class"]:
        out["job_failure_class"] = job["failure_class"]
        out["job_detail"] = (controller.events(ws, job["id"])[-1]["detail"] or "")[:500]
        code = code or job["failure_class"]
    if code in REASON_HELP:
        out["invariant"], out["remedy"] = REASON_HELP[code]
    with ws.db.read() as c:
        ev = c.execute("SELECT id FROM evidence WHERE candidate_id=?", (candidate_id,)).fetchone()
    if ev:
        e = ws.get_object(ev["id"], "Evidence")
        out["evidence_id"] = e.id
        out["tests"] = {k: e[k] for k in ("tests_run", "tests_passed", "tests_failed", "tests_skipped")}
        stderr = ws.cas.get(e["stderr_digest"]).decode("utf-8", "replace")
        failing = [l.strip()[:300] for l in stderr.splitlines() if re.search(r" \.\.\. (FAIL|ERROR)$", l)]
        out["failing_tests_preview"] = failing[:20]
        out["failing_tests_total"] = len(failing)
        out["handles"] = {"stdout": e["stdout_digest"], "stderr": e["stderr_digest"]}
    out["next_action"] = ("fix the candidate, then vep_candidate_register again" if out["failed"] else "nothing failed; see vep_candidate_state")
    return out
