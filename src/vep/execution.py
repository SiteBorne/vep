"""Protected local evaluator: staging, restricted command grammar, false-green detection, evidence.

SECURITY BOUNDARY: this evaluator runs candidate code in an ordinary host subprocess. It is NOT a
sandbox. It is disabled unless the caller passes an explicit trusted-local-execution authorization.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from decimal import Decimal
from pathlib import Path
from typing import Any

from . import audits as audits_mod
from . import budgets, candidates
from .canonical import canonical_bytes, sha256_hex, strict_loads
from .errors import (AuthorizationError, BudgetError, ExecutionError, FalseGreen, IsolationUnavailable,
                     PolicyViolation, StateError, VepError)
from .evidence import KeyStore, store_signed
from .isolation import probe
from .objects import VEPObject
from .policies import load_policy
from .snapshots import make_writable, materialize, tree_snapshot_id, verify_snapshot
from .workspace import Workspace, utcnow

TRUSTED_LOCAL_AUTH = "I-ACCEPT-NON-ISOLATED-EXECUTION"
RUNNER_PATH = Path(__file__).with_name("_runner.py")


def runner_digest() -> str:
    return sha256_hex(RUNNER_PATH.read_bytes())


# ---------------------------------------------------------------- action cache
def cached_evidence(ws: Workspace, action_id: str) -> VEPObject | None:
    """Return previously signed PASS evidence for an identical Action, or None.

    The Action id covers the input snapshot, policy and runner digests, so any change to source,
    policy or runner misses the cache. Hits are re-verified (signature + CAS integrity + binding);
    a tampered cache entry raises VerificationFailed instead of being reused (F11).
    """
    from .evidence import load_signed
    with ws.db.read() as c:
        row = c.execute("SELECT e.envelope_digest, e.action_id FROM action_cache a JOIN evidence e "
                        "ON e.id=a.evidence_id WHERE a.action_id=?", (action_id,)).fetchone()
    if row is None:
        return None
    ev = load_signed(ws, row["envelope_digest"], "Evidence")
    if ev["action_id"] != action_id or ev["verdict"] != "PASS":
        from .errors import VerificationFailed
        raise VerificationFailed("cached evidence does not match action")
    return ev


# ---------------------------------------------------------------- math helpers
def order_tests(tests: list[tuple[str, Decimal, Decimal]]) -> list[str]:
    """Order tests to minimize expected time-to-first-failure.

    Each item is (id, cost, p_fail) with p_fail in (0,1]. For a series of independent checks
    stopped at the first failure, sorting by p_fail/cost descending minimizes expected cost
    (exchange argument; see docs/EVIDENCE.md). Ties break by id for determinism.
    """
    for _, cost, p in tests:
        if cost <= 0 or not (0 <= p <= 1):
            raise VepError("cost must be > 0 and p_fail in [0,1]")
    return [t[0] for t in sorted(tests, key=lambda t: (-(t[2] / t[1]), t[0]))]


# ---------------------------------------------------------------- command grammar
def build_argv(policy: VEPObject, staged: Path, scratch: Path) -> tuple[list[str], Path]:
    ev = policy["evaluator"]
    report = scratch / "report.json"
    if ev["kind"] == "unittest":
        cfg = {"root": str(staged), "start_dir": ev.get("start_dir", "tests"),
               "pattern": ev.get("pattern", "test*.py"), "import_roots": ev.get("import_roots", ["."]),
               "report_path": str(report)}
        import json
        return [sys.executable, "-I", str(RUNNER_PATH), json.dumps(cfg, sort_keys=True)], report
    empty_ini = scratch / "empty.ini"
    empty_ini.write_text("[pytest]\n")
    roots = " ".join(str((staged / r).resolve()) for r in ev.get("import_roots", ["."]))
    if len(roots.split()) != len(ev.get("import_roots", ["."])):
        raise ExecutionError("staging path contains whitespace; pytest pythonpath cannot represent it")
    report = scratch / "junit.xml"
    return [sys.executable, "-I", "-m", "pytest", "-c", str(empty_ini), f"--rootdir={staged}",
            "--noconftest", "-p", "no:cacheprovider", "--import-mode=append", "-o", f"pythonpath={roots}",
            f"--junitxml={report}", "-q", *ev["targets"]], report


def _safe_env(scratch: Path) -> dict[str, str]:
    (scratch / "home").mkdir(exist_ok=True)
    (scratch / "tmp").mkdir(exist_ok=True)
    return {"PATH": "/usr/bin:/bin", "HOME": str(scratch / "home"), "TMPDIR": str(scratch / "tmp"),
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "LANG": "C.UTF-8",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}


# ---------------------------------------------------------------- report validation
def parse_unittest_report(path: Path) -> dict:
    try:
        rep = strict_loads(path.read_bytes())
    except Exception as exc:
        raise FalseGreen(f"MALFORMED_REPORT: {exc}") from exc
    keys = ["passed", "failed", "errors", "skipped", "expected_failures", "unexpected_successes"]
    if not isinstance(rep, dict) or rep.get("kind") != "unittest" or not all(isinstance(rep.get(k), list) for k in keys) \
            or not isinstance(rep.get("run"), int) or not isinstance(rep.get("discovered"), int):
        raise FalseGreen("MALFORMED_REPORT: missing fields")
    return rep


def parse_junit_report(path: Path) -> dict:
    try:
        root = ET.parse(path).getroot()
    except Exception as exc:
        raise FalseGreen(f"MALFORMED_REPORT: {exc}") from exc
    out: dict[str, Any] = {"kind": "pytest", "passed": [], "failed": [], "errors": [], "skipped": [],
                           "expected_failures": [], "unexpected_successes": []}
    for tc in root.iter("testcase"):
        tid = f"{tc.get('classname', '')}.{tc.get('name', '')}".strip(".")
        kids = {c.tag for c in tc}
        bucket = "failed" if "failure" in kids else "errors" if "error" in kids else \
            "skipped" if "skipped" in kids else "passed"
        out[bucket].append(tid)
    total = sum(len(out[k]) for k in ("passed", "failed", "errors", "skipped"))
    out["run"] = out["discovered"] = total
    return out


def _covers(module_path: str, ids: list[str]) -> bool:
    parts = module_path[:-3].split("/")
    prefixes = [".".join(parts[k:]) + "." for k in range(len(parts))]
    return any(i.startswith(p) for i in ids for p in prefixes)


def validate_report(rep: dict, policy: VEPObject, exit_code: int) -> tuple[str, dict]:
    """Return (verdict, counts). Raises FalseGreen for results that cannot establish success."""
    ev = policy["evaluator"]
    passed, failed, errors, skipped = rep["passed"], rep["failed"], rep["errors"], rep["skipped"]
    bad = len(failed) + len(errors) + len(rep["unexpected_successes"])
    all_ids = passed + failed + errors + skipped + rep["expected_failures"] + rep["unexpected_successes"]
    if len(all_ids) != rep["run"]:
        raise FalseGreen("REPORT_INCONSISTENT: outcome list does not match run count")
    if rep["run"] > rep["discovered"] and rep["kind"] == "unittest":
        raise FalseGreen("REPORT_INCONSISTENT: ran more tests than discovered")
    if rep["run"] == 0:
        raise FalseGreen("ZERO_TESTS: no tests were discovered and executed")
    if len(skipped) == rep["run"]:
        raise FalseGreen("ALL_SKIPPED: every test was skipped")
    if exit_code == 0 and bad:
        raise FalseGreen("EXIT_REPORT_MISMATCH: exit 0 but report lists failures")
    for path in policy["required_tests"]:
        if not _covers(path, all_ids):
            raise FalseGreen(f"REQUIRED_SUITE_NOT_EXECUTED:{path}")
        if not _covers(path, passed + failed + errors + rep["expected_failures"] + rep["unexpected_successes"]):
            raise FalseGreen(f"REQUIRED_SUITE_ALL_SKIPPED:{path}")
    counts = {"discovered": rep["discovered"], "run": rep["run"], "passed": len(passed),
              "failed": len(failed) + len(errors) + len(rep["unexpected_successes"]), "skipped": len(skipped)}
    if len(passed) < ev.get("min_tests", 1):
        raise FalseGreen(f"TOO_FEW_PASSING_TESTS:{len(passed)}<{ev.get('min_tests', 1)}")
    verdict = "PASS" if exit_code == 0 and bad == 0 else "FAIL"
    return verdict, counts


# ---------------------------------------------------------------- pipeline
def _run_limited(argv: list[str], cwd: Path, env: dict, scratch: Path, timeout: int, max_bytes: int) -> tuple[int, bytes, bytes, bool]:
    out_p, err_p = scratch / "stdout.txt", scratch / "stderr.txt"
    timed_out = False
    with open(out_p, "wb") as fo, open(err_p, "wb") as fe:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe,
                                start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = proc.wait()
    return code, out_p.read_bytes()[:max_bytes], err_p.read_bytes()[:max_bytes], timed_out


def _cand_account(ws: Workspace, objective_id: str, candidate_id: str) -> str:
    objective_acct = f"objective:{objective_id}"
    with ws.db.read() as c:
        if c.execute("SELECT 1 FROM accounts WHERE id=?", (objective_acct,)).fetchone() is None:
            raise BudgetError(f"no budget authorized for {objective_id}: create an objective account first")
    acct = f"candidate:{candidate_id}"
    cap = budgets.report(ws, objective_acct)["available"]
    budgets.create_account(ws, acct, "candidate", cap, parent_id=objective_acct)
    return acct


def evaluate(ws: Workspace, candidate_id: str, *, trusted_local_authorization: str | None = None,
             mode: str = "trusted-local", actor: str = "vep-evaluator") -> dict:
    # 0. authorization / isolation gates (before any state change or execution)
    if mode == "isolated":
        p = probe()
        raise IsolationUnavailable(
            f"{p.status}: containerized evaluation is not implemented in this MVP "
            f"({'; '.join(p.reasons) or 'runtime present'}); no host fallback")
    if mode != "trusted-local":
        raise VepError(f"unknown mode {mode!r}")
    if trusted_local_authorization != TRUSTED_LOCAL_AUTH:
        raise AuthorizationError("non-isolated local execution requires explicit trusted-local authorization; "
                                 "this mode provides NO security isolation")
    # 1-5. identity, snapshot, policy, evaluator config, required suite
    st = candidates.get_state(ws, candidate_id)
    cand = ws.get_object(candidate_id, "Candidate")
    objective = ws.get_object(cand["objective_id"], "Objective")
    policy = load_policy(ws, objective["policy_id"])
    snap = ws.get_object(cand["snapshot_id"], "Snapshot")
    if st["status"] == "PROPOSED":
        viol = candidates.check_policy(ws, candidate_id)
        if viol:
            raise PolicyViolation("; ".join(viol))
        st = candidates.get_state(ws, candidate_id)
    if st["status"] != "POLICY_CHECKED":
        raise StateError(f"candidate must be POLICY_CHECKED to evaluate (is {st['status']})")
    verify_snapshot(ws, snap)
    if st["objective_id"] != objective.id or st["snapshot_id"] != snap.id:
        raise StateError("candidate row does not match its immutable object")
    # static audits from the frozen policy, on the exact candidate snapshot
    if policy["audits"]:
        results = audits_mod.run_audits_on_snapshot(ws, snap, policy["audits"])
        failing = {k: v for k, v in results.items() if v}
        if failing:
            candidates.transition(ws, candidate_id, "REJECTED", st["version"], actor,
                                  "STATIC_AUDIT_FAILED:" + ";".join(f for v in failing.values() for f in v))
            raise PolicyViolation(f"static audit failed: {failing}")
    # 6-7. budget (fail closed; idempotent key prevents duplicate spend)
    cost_micro = policy["limits"]["evaluation_cost_micro_usd"]
    acct = _cand_account(ws, objective.id, candidate_id)
    rkey = f"eval:{candidate_id}"
    budgets.reserve(ws, acct, Decimal(cost_micro) / Decimal(1_000_000), rkey)
    v = candidates.transition(ws, candidate_id, "BUDGET_RESERVED", st["version"], actor, "budget reserved", proof_id=rkey)
    keystore = KeyStore(ws)
    key_before = keystore.file_digest()
    action = VEPObject.create("Action", {
        "argv": ["<runner>", policy["evaluator"]["kind"]], "input_snapshot_id": snap.id,
        "policy_id": policy.id, "runner_digest": runner_digest(), "env": {},
        "isolation": "NONE_TRUSTED_LOCAL"})
    ws.put_object(action)
    v = candidates.transition(ws, candidate_id, "EVALUATING", v, actor, "staging", proof_id=action.id)
    scratch = Path(tempfile.mkdtemp(prefix="vep-eval-"))
    staged = scratch / "src"
    try:
        # 8. staging boundary: outside workspace and state dir
        for forbidden in (ws.root, ws.state):
            if scratch.resolve() == forbidden or forbidden in scratch.resolve().parents:
                raise ExecutionError("staging directory lies inside the workspace; refusing")
        materialize(ws, snap, staged)
        if tree_snapshot_id(staged, excludes=()) != snap.id:
            raise ExecutionError("staged tree does not match snapshot")
        started = utcnow()
        argv, report_path = build_argv(policy, staged, scratch)
        code, out, err, timed_out = _run_limited(
            argv, staged, _safe_env(scratch), scratch, policy["limits"]["timeout_s"],
            policy["limits"]["max_output_bytes"])
        finished = utcnow()
        # post-run integrity: workspace mutation (F05), VEP state (F06)
        mutated = tree_snapshot_id(staged, excludes=()) != snap.id
        key_tampered = keystore.file_digest() != key_before
        reject_reason = None
        counts: dict = {}
        verdict = "FAIL"
        rep: dict = {"passed": [], "failed": [], "errors": [], "skipped": [], "expected_failures": [],
                     "unexpected_successes": []}
        if timed_out:
            reject_reason = "TIMEOUT"
        elif mutated:
            reject_reason = "WORKSPACE_MUTATED_DURING_EVALUATION"
        elif key_tampered:
            reject_reason = "VEP_STATE_TAMPERED"
        else:
            try:
                rep = parse_unittest_report(report_path) if policy["evaluator"]["kind"] == "unittest" \
                    else parse_junit_report(report_path)
                verdict, counts = validate_report(rep, policy, code)
            except FalseGreen as exc:
                reject_reason = f"FALSE_GREEN:{exc}"
        if reject_reason:
            budgets.settle(ws, rkey, Decimal(cost_micro) / Decimal(1_000_000), f"eval-settle:{candidate_id}")
            candidates.transition(ws, candidate_id, "REJECTED", v, actor, reject_reason)
            return {"candidate_id": candidate_id, "status": "REJECTED", "reason": reject_reason}
        ids_digest = sha256_hex(canonical_bytes(sorted(
            rep["passed"] + rep["failed"] + rep["errors"] + rep["skipped"])))
        evidence = VEPObject.create("Evidence", {
            "candidate_id": candidate_id, "objective_id": objective.id, "snapshot_id": snap.id,
            "policy_id": policy.id, "action_id": action.id, "runner_digest": runner_digest(),
            "argv": ["<protected-runner>", policy["evaluator"]["kind"]], "exit_code": code, "verdict": verdict,
            "tests_discovered": counts["discovered"], "tests_run": counts["run"],
            "tests_passed": counts["passed"], "tests_failed": counts["failed"],
            "tests_skipped": counts["skipped"], "executed_ids_digest": ids_digest,
            "stdout_digest": ws.cas.put(out), "stderr_digest": ws.cas.put(err),
            "staged_tree_snapshot_id": snap.id, "isolation": "NONE_TRUSTED_LOCAL",
            "started_at": started, "finished_at": finished, "budget_reservation": rkey})
        env_digest = store_signed(ws, evidence, keystore)
        with ws.db.tx() as c:
            c.execute("INSERT INTO evidence(id,candidate_id,objective_id,snapshot_id,policy_id,action_id,verdict,envelope_digest)"
                      " VALUES(?,?,?,?,?,?,?,?)", (evidence.id, candidate_id, objective.id, snap.id, policy.id,
                                                    action.id, verdict, env_digest))
            budgets.settle(ws, rkey, Decimal(cost_micro) / Decimal(1_000_000), f"eval-settle:{candidate_id}", conn=c)
            if verdict == "PASS":
                c.execute("INSERT OR REPLACE INTO action_cache(action_id,evidence_id) VALUES(?,?)", (action.id, evidence.id))
                candidates.transition(ws, candidate_id, "EVIDENCE_READY", v, actor, "evidence PASS", evidence.id, conn=c)
            else:
                candidates.transition(ws, candidate_id, "REJECTED", v, actor, "tests failed", evidence.id, conn=c)
        return {"candidate_id": candidate_id, "status": "EVIDENCE_READY" if verdict == "PASS" else "REJECTED",
                "verdict": verdict, "evidence_id": evidence.id, "counts": counts,
                "isolation": "NONE_TRUSTED_LOCAL (no security isolation)"}
    except BaseException as exc:
        # outcome unknown: keep funds held as UNCERTAIN, never leave the candidate stuck in EVALUATING
        cur = candidates.get_state(ws, candidate_id)
        if cur["status"] == "EVALUATING":
            try:
                budgets.mark_uncertain(ws, rkey)
            except BudgetError:
                pass
            candidates.transition(ws, candidate_id, "REJECTED", cur["version"], actor,
                                  f"EVALUATOR_ERROR:{exc.__class__.__name__}")
        raise
    finally:
        make_writable(scratch)
        shutil.rmtree(scratch, ignore_errors=True)
