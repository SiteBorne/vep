"""vep command-line interface. Every subcommand calls the real implementation modules."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from decimal import Decimal
from pathlib import Path

from . import (audits, budgets, builds, cache_planner, candidates, certificates, conformance, context, controller, depgraph, execution, git_adapter,
               isolation, objectives, policies, routing, simulation, snapshots, tokens, versions)
from .canonical import strict_loads
from .errors import AuthorizationError, VepError
from .evidence import KeyStore
from .workspace import Workspace

EXIT_UNEXPECTED = 70


def _emit(args, data) -> None:
    field = getattr(args, "field", None)
    if field:
        if not isinstance(data, dict) or field not in data:
            raise KeyError(f"no field {field!r} in output")
        print(data[field])
        return
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
    elif isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        print(data)


def _ws(args) -> Workspace:
    return Workspace(args.root)


def _load_json(path: str):
    return json.loads(Path(path).read_text(), parse_float=str)


def cmd_init(a):
    ws = Workspace.init(a.root)
    kid = KeyStore(ws).ensure()
    _emit(a, {"workspace": str(ws.root), "signing_key_id": kid, "note": "private key is stored under .vep/keys (0600) and is never printed"})


def cmd_status(a):
    ws = _ws(a)
    with ws.db.read() as c:
        counts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM candidates GROUP BY status")}
        nobj = c.execute("SELECT COUNT(*) n FROM objects WHERE type='Objective'").fetchone()["n"]
        ncert = c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"]
    _emit(a, {"workspace": str(ws.root), "objectives": nobj, "candidates_by_status": counts,
              "certificates": ncert, "git": git_adapter.inspect(ws.root),
              "isolation": isolation.probe().to_dict()["status"],
              "execution_mode": "trusted-local only (no security isolation)"})


def cmd_snapshot(a):
    ws = _ws(a)
    snap = snapshots.take_snapshot(ws, Path(a.path) if a.path else None)
    _emit(a, {"snapshot_id": snap.id, "files": len(snap["entries"])})


def cmd_diff(a):
    ws = _ws(a)
    if a.candidate:
        cand = ws.get_object(a.candidate, "Candidate")
        old, new = cand["base_snapshot_id"], cand["snapshot_id"]
    else:
        old, new = a.old, a.new
    _emit(a, snapshots.diff(ws.get_object(old, "Snapshot"), ws.get_object(new, "Snapshot")))


def cmd_objective(a):
    ws = _ws(a)
    if a.action == "list":
        return _emit(a, objectives.list_objectives(ws))
    if a.action == "show":
        return _emit(a, ws.get_object(a.id, "Objective").fields)
    base = a.base or snapshots.take_snapshot(ws).id
    base_snap = ws.get_object(base, "Snapshot")
    evaluator = _load_json(a.evaluator_file) if a.evaluator_file else None
    audit_specs = _load_json(a.audit_file) if a.audit_file else None
    if evaluator and "min_tests" in evaluator:
        evaluator["min_tests"] = int(evaluator["min_tests"])
    pol = policies.make_policy(ws, base_snap, name=a.policy_name, evaluator=evaluator, audits=audit_specs)
    obj = objectives.create_objective(ws, a.title, a.description, base, pol.id)
    if a.budget:
        budgets.create_account(ws, f"objective:{obj.id}", "objective", a.budget)
    _emit(a, {"objective_id": obj.id, "policy_id": pol.id, "base_snapshot_id": base,
              "required_tests": sorted(pol["required_tests"])})


def cmd_candidate(a):
    ws = _ws(a)
    if a.action == "create":
        snap = a.snapshot or snapshots.take_snapshot(ws).id
        c = candidates.register_candidate(ws, a.objective, snap, a.author)
        return _emit(a, {"candidate_id": c.id, "snapshot_id": snap, "status": "PROPOSED"})
    if a.action == "check":
        v = candidates.check_policy(ws, a.id)
        _emit(a, {"candidate_id": a.id, "violations": v, "state": candidates.get_state(ws, a.id)["status"]})
        return 3 if v else 0
    if a.action == "show":
        return _emit(a, {"state": candidates.get_state(ws, a.id), "history": candidates.history(ws, a.id)})
    with ws.db.read() as c:
        _emit(a, [dict(r) for r in c.execute("SELECT id,status,version FROM candidates ORDER BY created_at, id")])


def cmd_evaluate(a):
    ws = _ws(a)
    auth = execution.TRUSTED_LOCAL_AUTH if a.trusted_local_execution else None
    att = json.loads(Path(a.attestation_file).read_text()) if a.attestation_file else None
    r = execution.evaluate(ws, a.candidate, trusted_local_authorization=auth,
                           mode="isolated" if a.isolated else "trusted-local", image=a.image, attestation=att)
    _emit(a, r)
    return 0 if r["status"] == "EVIDENCE_READY" else 3


def cmd_run(a):
    ws = _ws(a)
    job = controller.enqueue(ws, a.candidate, mode="isolated" if a.isolated else "trusted-local",
                             auto_certify=not a.no_certify, max_attempts=a.max_attempts)
    if a.isolated:
        att = json.loads(Path(a.attestation_file).read_text()) if a.attestation_file else None
        w = controller.IsolatedWorker("vep-cli-isolated", a.image, att)
    else:
        w = controller.LocalToolWorker("vep-cli-local", execution.TRUSTED_LOCAL_AUTH if a.trusted_local_execution else None)
    r = controller.run_one(ws, w)
    out = {"job": controller.get_job(ws, job["id"]), "run": r}
    _emit(a, out)
    return 0 if r and r.get("outcome") == "SUCCEEDED" and r.get("candidate_status") in ("CERTIFIED", "EVIDENCE_READY") else 3


def cmd_build(a):
    ws = _ws(a)
    if a.action == "stats":
        _emit(a, builds.stats(ws))
        return 0
    if not a.trusted_local_execution:
        raise AuthorizationError("build actions run commands as the invoking user with no isolation; "
                                 "pass --trusted-local-execution to authorize")
    argv = json.loads(a.argv_json or "null")
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        raise ValueError("--argv-json must be a non-empty JSON array of strings")
    action = builds.BuildAction(tuple(argv), a.snapshot, tuple(a.output), timeout_s=a.timeout,
                                cache_policy="none" if a.no_cache else "deterministic",
                                verify_determinism=not a.no_verify_determinism)
    r = builds.run(ws, action, use_cache=not a.no_cache)
    r["action_id"] = builds.action_id(action)
    _emit(a, r)
    return 0 if r["failure"] is None else 3


def cmd_jobs(a):
    ws = _ws(a)
    if a.action == "list":
        _emit(a, controller.list_jobs(ws))
    elif a.action == "recover":
        _emit(a, controller.recover(ws))
    else:
        if not a.job:
            raise ValueError("--job is required")
        if a.action == "show":
            _emit(a, {"job": controller.get_job(ws, a.job), "events": controller.events(ws, a.job)})
        else:
            _emit(a, controller.cancel(ws, a.job))


def cmd_graph(a):
    ws = _ws(a)
    g = depgraph.build_graph(ws, a.snapshot)
    if a.old:
        g = {"graph": g, "impact": depgraph.impact(ws, g, a.old, a.snapshot)}
    _emit(a, g)


def cmd_compose(a):
    r = depgraph.compose_candidates(_ws(a), a.objective, a.candidate_a, a.candidate_b)
    _emit(a, r)
    return 0 if r["status"] == "TEXTUALLY_CLEAN" else 3


def cmd_conformance(a):
    from . import trustpolicy
    if a.action == "export":
        b = conformance.export_bundle(_ws(a), a.certificate, a.require_trust, version=a.bundle_version)
        if a.out:
            Path(a.out).write_text(json.dumps(b, indent=1, sort_keys=True))
            _emit(a, {"bundle": a.out, "certificate_id": a.certificate, "bundle_version": a.bundle_version})
        else:
            _emit(a, b)
        return 0
    if a.action == "trust-policy":  # a trust policy naming THIS workspace's signing key as the only issuer (the owner is the relying party)
        ws = _ws(a)
        ks = KeyStore(ws)
        with ws.db.read() as c:
            row = c.execute("SELECT public_key_hex FROM trusted_keys WHERE key_id=?", (ks.key_id(),)).fetchone()
        if not a.snapshot:
            raise ValueError("--snapshot is required: a trust policy must state the source snapshot it expects")
        pol = trustpolicy.make_policy(a.name, [trustpolicy.issuer(bytes.fromhex(row["public_key_hex"]))], [a.evaluator], a.require_trust,
                                      snapshot_id=a.snapshot, objective_id=a.objective, policy_id=a.policy, evidence_versions=(2,), certificate_versions=(2,))
        _emit(a, pol)
        return 0
    if a.action == "verify":
        bundle = json.loads(Path(a.bundle).read_text())
        if a.trust_policy:
            if not a.now:
                raise ValueError("--now (the relying party's UTC time, YYYY-MM-DDTHH:MM:SSZ) is required with --trust-policy")
            r = trustpolicy.verify_authorized(bundle, json.loads(Path(a.trust_policy).read_text()), a.now)
        elif a.internal_only:
            r = conformance.verify_bundle(bundle)
            r["warning"] = "internal consistency only: the bundle supplied its own keys and expectations; this does NOT establish that any trusted party issued it"
        else:
            raise ValueError("specify --trust-policy FILE --now TIME for authorized verification, or --internal-only to accept an internal-consistency result")
    else:
        suite = conformance.load_suite(a.suite)
        bad = [v["id"] for v in suite["vectors"] if not conformance.check_vector(v, conformance.run_vector(v))]
        r = {"valid": not bad, "vectors": len(suite["vectors"]), "disagreements": bad, "verifier": "reference (python)", "suite_version": suite["suite_version"]}
    _emit(a, r)
    return 0 if r["valid"] else 4


def cmd_certify(a):
    ws = _ws(a)
    cert = certificates.certify(ws, a.candidate)
    _emit(a, {"certificate_id": cert.id, "snapshot_id": cert["snapshot_id"]})


def cmd_verify(a):
    ws = _ws(a)
    r = certificates.verify_certificate(ws, a.certificate, current_root=None if a.historical else ws.root,
                                        expect_objective_id=a.objective, expect_policy_id=a.policy,
                                        require_trust=a.require_trust)
    r["mode"] = "historical" if a.historical else "current-source"
    _emit(a, r)


def cmd_budget(a):
    ws = _ws(a)
    if a.action == "create":
        _emit(a, budgets.create_account(ws, a.account, a.kind, a.limit, a.parent))
    elif a.action == "reserve":
        _emit(a, budgets.reserve(ws, a.account, a.amount, a.key))
    elif a.action == "settle":
        _emit(a, budgets.settle(ws, a.key, a.amount, a.settle_key or a.key + ":settle"))
    elif a.action == "release":
        _emit(a, budgets.release(ws, a.key))
    elif a.action == "uncertain":
        _emit(a, budgets.mark_uncertain(ws, a.key))
    elif a.action == "show":
        _emit(a, budgets.report(ws, a.account))
    else:
        _emit(a, budgets.history(ws, a.account))


def cmd_tokens(a):
    ws = _ws(a)
    if a.action == "total":
        return _emit(a, tokens.totals(ws, a.candidate))
    u = _load_json(a.usage_file)
    r = tokens.make_receipt(candidate_id=a.candidate, attempt=a.attempt, idempotency_key=a.key,
                            context_id=a.context, **{k: (int(v) if k.endswith("tokens") or k == "reasoning_tokens_in_output" else v)
                                                    for k, v in u.items()})
    _emit(a, tokens.record_receipt(ws, r, a.reservation))


def cmd_context(a):
    ws = _ws(a)
    m = context.build_context(ws, a.snapshot, a.policy, a.max_tokens, required=a.require, requested=a.path,
                              keyword_query=a.keyword)
    _emit(a, {"context_id": m.id, **m.fields})


def cmd_route(a):
    models = [routing.ModelOption.from_dict(m) for m in _load_json(a.models_file)]
    r = routing.select(models, routing.Task.from_dict(_load_json(a.task_file)))
    _emit(a, r)
    return 0 if r["decision"] == "SELECTED" else 3


def cmd_cache(a):
    ci = cache_planner.CacheInputs.build(
        prefix_tokens=a.prefix_tokens, suffix_tokens=a.suffix_tokens, output_tokens=a.output_tokens,
        ordinary_input_price=a.input_price, output_price=a.output_price,
        cache_write_multiplier=a.write_multiplier, cache_read_multiplier=a.read_multiplier,
        expected_reuses=a.reuses, cache_lifetime_s=a.lifetime, request_interval_s=a.interval,
        estimated_hit_probability=a.hit_probability)
    _emit(a, cache_planner.plan(ci))


def cmd_audit(a):
    spec = _load_json(a.audit_file)
    specs = spec if isinstance(spec, list) else [spec]
    out = {}
    for s in specs:
        target = Path(a.target or s.get("file", ""))
        out[s.get("id", "unnamed")] = audits.run_audits_on_file(target, s)
    _emit(a, out)
    return 3 if any(out.values()) else 0


def cmd_version(a):
    _emit(a, versions.summary())


def cmd_isolation(a):
    if a.action == "detect":
        return _emit(a, isolation.detect_capabilities(a.image))
    if a.action == "verify":
        if not a.image:
            raise ValueError("--image is required")
        att = isolation.verify_runtime(a.image)
        if a.out:
            Path(a.out).write_text(json.dumps(att, indent=1, sort_keys=True))
        _emit(a, att)
        return 0 if att["status"] == "ISOLATED_VERIFIED" else 8
    if a.action == "probe":
        r = isolation.probe(a.image)
        _emit(a, r.to_dict())
        return 0 if r.status == isolation.RUNTIME_PRESENT else 8
    plan = isolation.build_plan(a.image, a.source, a.cmd)
    _emit(a, {"argv": plan, "executed": False})


def cmd_simulate(a):
    p = simulation.SimParams(n_tasks=a.tasks, seed=a.seed)
    _emit(a, simulation.run_report(p, with_sensitivity=a.sensitivity))


def cmd_claude(a):
    from . import claude_code
    if a.action == "plugin":
        if not a.out:
            raise ValueError("--out DIR is required for `claude plugin`")
        _emit(a, claude_code.write_plugin(a.out, version=versions.PACKAGE_VERSION)); return 0
    if a.action == "status":
        _emit(a, claude_code.status(a.root)); return 0
    if a.action == "uninstall":
        _emit(a, claude_code.uninstall(a.root, dry_run=a.dry_run)); return 0
    authority = tuple(x for x in a.authority.split(",") if x) if a.authority else (
        claude_code.AUTHORITY_EVALUATING if a.allow_evaluate else claude_code.AUTHORITY_DEFAULT)
    r = claude_code.install(a.root, authority=authority, trusted_local=a.allow_evaluate, hooks=not a.no_hooks, claude_md=not a.no_claude_md,
                            force=a.force, dry_run=a.dry_run, command=a.mcp_command.split() if a.mcp_command else None)
    _emit(a, r)
    return 3 if r["status"] == "CONFLICT" else 0


def _common(sp):
    sp.add_argument("--json", action="store_true", help="machine-readable JSON output")
    sp.add_argument("--root", default=".", help="workspace root (default: cwd)")
    sp.add_argument("--field", help="print only this top-level field of the result (for scripting)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vep", description="Verified Evolution Protocol reference MVP "
                                "(local, trusted-code only; not a production sandbox).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_, description=help_)
        _common(sp)
        sp.set_defaults(fn=fn)
        return sp

    add("init", cmd_init, "create .vep state and the Ed25519 signing key")
    add("version", cmd_version, "show package, protocol, schema and format versions")
    add("status", cmd_status, "show workspace status")
    s = add("snapshot", cmd_snapshot, "take a source snapshot"); s.add_argument("--path")
    s = add("diff", cmd_diff, "diff two snapshots or a candidate against its base")
    s.add_argument("old", nargs="?"); s.add_argument("new", nargs="?"); s.add_argument("--candidate")
    s = add("objective", cmd_objective, "create/list/show objectives (freezes the acceptance policy)")
    s.add_argument("action", choices=["create", "list", "show"]); s.add_argument("--id")
    s.add_argument("--title", default="objective"); s.add_argument("--description", default="")
    s.add_argument("--base"); s.add_argument("--policy-name", default="default")
    s.add_argument("--evaluator-file"); s.add_argument("--audit-file")
    s.add_argument("--budget", help="also create the objective budget account with this USD limit (e.g. 1.00)")
    s = add("candidate", cmd_candidate, "register/check/show/list candidates")
    s.add_argument("action", choices=["create", "check", "show", "list"]); s.add_argument("--id")
    s.add_argument("--objective"); s.add_argument("--snapshot"); s.add_argument("--author", default="agent")
    s = add("run", cmd_run, "enqueue a candidate and run it through the durable controller (evaluate, then certify)")
    s.add_argument("--candidate", required=True); s.add_argument("--trusted-local-execution", action="store_true")
    s.add_argument("--isolated", action="store_true"); s.add_argument("--image"); s.add_argument("--attestation-file")
    s.add_argument("--no-certify", action="store_true"); s.add_argument("--max-attempts", type=int, default=3)
    s = add("jobs", cmd_jobs, "inspect, recover or cancel controller jobs")
    s.add_argument("action", choices=["list", "show", "recover", "cancel"]); s.add_argument("--job")
    s = add("graph", cmd_graph, "dependency graph of a snapshot (static imports only); --old adds change impact (prioritisation only)")
    s.add_argument("--snapshot", required=True); s.add_argument("--old")
    s = add("compose", cmd_compose, "compose two candidates; a clean merge still needs full evaluation")
    s.add_argument("--objective", required=True); s.add_argument("candidate_a"); s.add_argument("candidate_b")
    s = add("conformance", cmd_conformance, "export a portable certificate bundle, verify one (authorized by a trust policy, or internal-only), or run the frozen vectors")
    s.add_argument("action", choices=["export", "verify", "vectors", "trust-policy"]); s.add_argument("--certificate"); s.add_argument("--bundle")
    s.add_argument("--out"); s.add_argument("--suite", default="conformance/vectors/suite-1.1.json")
    s.add_argument("--bundle-version", type=int, choices=[1, 2], default=2, help="2 (default): no embedded keys, needs a trust policy; 1: legacy self-contained bundle")
    s.add_argument("--trust-policy"); s.add_argument("--now"); s.add_argument("--internal-only", action="store_true")
    s.add_argument("--name", default="local-workspace"); s.add_argument("--evaluator", default="vep-local-evaluator/*"); s.add_argument("--snapshot")
    s.add_argument("--objective"); s.add_argument("--policy")
    s.add_argument("--require-trust", default="TRUSTED_LOCAL", choices=["TRUSTED_LOCAL", "ISOLATED_VERIFIED"])
    s = add("build", cmd_build, "run a content-addressed build action over a snapshot, with verified result cache")
    s.add_argument("action", choices=["run", "stats"]); s.add_argument("--snapshot"); s.add_argument("--output", action="append", default=[])
    s.add_argument("--timeout", type=int, default=300); s.add_argument("--trusted-local-execution", action="store_true")
    s.add_argument("--no-cache", action="store_true"); s.add_argument("--no-verify-determinism", action="store_true")
    s.add_argument("--argv-json", help='command as a JSON array of strings; argv[0] is "{python}" or an absolute path (no shell)')
    s = add("evaluate", cmd_evaluate, "run the protected evaluator (requires explicit trusted-local authorization)")
    s.add_argument("--candidate", required=True)
    s.add_argument("--trusted-local-execution", action="store_true",
                   help="acknowledge: runs candidate code on this host WITHOUT security isolation")
    s.add_argument("--isolated", action="store_true", help="request container isolation (fails closed if unavailable)")
    s.add_argument("--image", help="digest-pinned local image for --isolated")
    s.add_argument("--attestation-file", help="output of `vep isolation verify` for --image")
    s = add("certify", cmd_certify, "issue a signed certificate for EVIDENCE_READY candidate")
    s.add_argument("--candidate", required=True)
    s = add("verify", cmd_verify, "verify a certificate (against current source unless --historical)")
    s.add_argument("--certificate", required=True); s.add_argument("--historical", action="store_true")
    s.add_argument("--objective"); s.add_argument("--policy")
    s.add_argument("--require-trust", choices=["TRUSTED_LOCAL", "ISOLATED_VERIFIED"], default="TRUSTED_LOCAL",
                   help="minimum evidence trust level to accept (default TRUSTED_LOCAL; reported in the output)")
    s = add("budget", cmd_budget, "transactional budgets")
    s.add_argument("action", choices=["create", "reserve", "settle", "release", "uncertain", "show", "history"])
    s.add_argument("--account"); s.add_argument("--kind", default="objective"); s.add_argument("--limit")
    s.add_argument("--parent"); s.add_argument("--amount"); s.add_argument("--key"); s.add_argument("--settle-key")
    s = add("tokens", cmd_tokens, "record token receipts (usage supplied by the caller)")
    s.add_argument("action", choices=["record", "total"]); s.add_argument("--candidate", required=True)
    s.add_argument("--usage-file"); s.add_argument("--attempt", type=int, default=0)
    s.add_argument("--key"); s.add_argument("--reservation"); s.add_argument("--context")
    s = add("context", cmd_context, "build a ContextManifest")
    s.add_argument("--snapshot", required=True); s.add_argument("--policy", required=True)
    s.add_argument("--max-tokens", type=int, required=True)
    s.add_argument("--require", action="append", default=[]); s.add_argument("--path", action="append", default=[])
    s.add_argument("--keyword")
    s = add("route", cmd_route, "offline model routing policy engine")
    s.add_argument("--models-file", required=True); s.add_argument("--task-file", required=True)
    s = add("cache", cmd_cache, "prompt-cache economics")
    s.add_argument("--prefix-tokens", type=int, required=True); s.add_argument("--suffix-tokens", type=int, default=0)
    s.add_argument("--output-tokens", type=int, default=0); s.add_argument("--input-price", required=True)
    s.add_argument("--output-price", default="0"); s.add_argument("--write-multiplier", required=True)
    s.add_argument("--read-multiplier", required=True); s.add_argument("--reuses", type=int, required=True)
    s.add_argument("--lifetime"); s.add_argument("--interval"); s.add_argument("--hit-probability", default="1")
    s = add("audit", cmd_audit, "run static readiness/consistency audits on a JSON file")
    s.add_argument("--audit-file", required=True); s.add_argument("--target")
    s = add("isolation", cmd_isolation, "probe or plan Docker+gVisor isolation (offline)")
    s.add_argument("action", choices=["probe", "plan", "detect", "verify"]); s.add_argument("--image"); s.add_argument("--out")
    s.add_argument("--source"); s.add_argument("--cmd", nargs="+")
    s = add("claude", cmd_claude, "install/inspect/remove the Claude Code integration (.mcp.json, Skill, CLAUDE.md block, guard hook) or write a plugin")
    s.add_argument("action", choices=["install", "status", "uninstall", "plugin"]); s.add_argument("--out")
    s.add_argument("--authority", help="comma-separated read,register,evaluate,export (default read,register)")
    s.add_argument("--allow-evaluate", action="store_true", help="grant evaluate+export and --trusted-local-execution: candidate code runs unisolated on this host")
    s.add_argument("--no-hooks", action="store_true"); s.add_argument("--no-claude-md", action="store_true")
    s.add_argument("--force", action="store_true", help="replace conflicting files/entries (a backup is kept)"); s.add_argument("--dry-run", action="store_true")
    s.add_argument("--mcp-command", help="command (and leading args) that starts the server, default vep-mcp or `python -m vep.mcp_server`")
    s = add("simulate", cmd_simulate, "seeded synthetic cost/reliability simulation")
    s.add_argument("--tasks", type=int, default=20000); s.add_argument("--seed", type=int, default=20261019)
    s.add_argument("--sensitivity", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc = args.fn(args)
        return int(rc or 0)
    except VepError as exc:
        print(f"vep: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError, KeyError, TypeError, ArithmeticError, sqlite3.Error) as exc:
        print(f"vep: error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
