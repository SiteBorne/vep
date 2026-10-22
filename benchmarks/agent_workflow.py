"""Agent-scale coding-workflow benchmark: deterministic traces of an autonomous coding agent's verification requests on a real project, run through six systems.

    python benchmarks/agent_workflow.py --project pyflakes --src <clone> --evalpy <py without vep> --testmon-py <py with pytest-testmon> \
        --opt-flags staging_fast,verified_handoff --reps 5 --out benchmarks/results/agent-workflow-<tag>.json [--scenarios T1 T4 ...] [--include-large]

Systems (assurance differs and is reported on every row):
  DIRECT_SEQ     python -I -m unittest discover, one candidate after another          exit code only
  DIRECT_PAR     same, candidates run in parallel (W workers)                          exit code only
  TESTMON        pytest --testmon on one evolving working tree                         heuristic selection; advisory
  VEP_BASE       VEP protected fresh certification, optimizations OFF                  fresh certificate + independent authorized verification
  VEP_OPT        VEP protected fresh certification, flags in --opt-flags               fresh certificate + independent authorized verification
  VEP_REUSE      VEP_OPT + explicit `reuse_if_identical`                              derived attestation when eligible, else fresh certificate (reported per step)
  VEP_ADVISORY   VEP_OPT + advisory feedback first, then the fresh certificate          time to first feedback is the advisory run; authorization is still the fresh certificate
Metrics are separate: time to first feedback, time to the verdict, time to independently authorized acceptance (None where the system cannot provide one), CPU seconds,
largest-child RSS, evaluations avoided, eligibility of each request for reuse, correctness against the trace's expected outcome.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import paired as P  # noqa: E402
import envinfo  # noqa: E402
from profile_scale import make_project  # noqa: E402

SPECS = P.SPECS
DRIVER = HERE / "agent_driver.py"
SCENARIOS = {
    "T01_cold_first_verification": ["clean:pass"],
    "T02_same_source_reverification": ["clean:pass", "clean:pass"],
    "T03_small_correct_change": ["clean:pass", "benign:pass"],
    "T04_incorrect_change_and_revision": ["clean:pass", "mutant:fail", "clean:pass"],
    "T05_protected_test_modification": ["clean:pass", "protected_edit:policy_reject"],
    "T06_revert_to_verified_snapshot": ["clean:pass", "benign:pass", "clean:pass"],
    "T07_multiple_independent_candidates": ["clean:pass", "extra0:pass", "extra1:pass", "extra2:pass", "extra3:pass"],
    "T08_repeated_registration": ["clean:pass", "clean:pass", "clean:pass"],
    "T09_concurrent_workers": ["clean:pass", "BATCH:extra0,extra1,extra2,extra3"],
    "T10_cache_corruption": ["clean:pass", "CORRUPT:extra0"],
    "T11_cancel_retry_recovery": ["clean:pass", "CANCEL:extra0"],
    "T12_large_tree_tiny_change": ["LARGE:clean:pass", "LARGE:tiny:pass"],
}
SYSTEMS = ["DIRECT_SEQ", "DIRECT_PAR", "TESTMON", "VEP_BASE", "VEP_OPT", "VEP_REUSE", "VEP_ADVISORY"]
ASSUR = {"DIRECT_SEQ": "NONE_EXIT_CODE_ONLY", "DIRECT_PAR": "NONE_EXIT_CODE_ONLY", "TESTMON": "HEURISTIC_SELECTION_NO_CERTIFICATE", "VEP_BASE": "VEP_PROTECTED_FRESH_CERTIFICATE",
         "VEP_OPT": "VEP_PROTECTED_FRESH_CERTIFICATE", "VEP_REUSE": "FRESH_CERTIFICATE_OR_DERIVED_ATTESTATION (per step)", "VEP_ADVISORY": "ADVISORY_FIRST_THEN_FRESH_CERTIFICATE"}


class Ctx:
    def __init__(self, a, project, src):
        self.a, self.project, self.src = a, project, Path(src)
        self.spec = SPECS[project]
        self.tmp = Path(tempfile.mkdtemp(prefix="vep-aw-"))
        self.n = 0

    def tree(self, kind: str) -> Path:
        self.n += 1
        d = self.tmp / f"t{self.n}"
        if kind.startswith("LARGE"):
            d.mkdir(); make_project(d, 5000)
            if kind.endswith("tiny"):
                (d / "pkg" / "d0" / "m0.py").write_text((d / "pkg" / "d0" / "m0.py").read_text() + "# tiny\n")
            return d
        shutil.copytree(self.src, d, ignore=shutil.ignore_patterns(".git"))
        if kind == "mutant":
            m = self.spec["mutant"]; p = d / m["path"]; p.write_text(p.read_text().replace(m["old"], m["new"], 1))
        elif kind == "benign":
            b = self.spec["benign"]; (d / b["path"]).write_text(b["content"])
        elif kind.startswith("extra"):
            i = kind[5:]
            (d / self.spec["benign"]["path"].replace("vep_extra", f"vep_extra{i}")).write_text(self.spec["benign"]["content"].replace("VepExtra", f"VepExtra{i}"))
        elif kind == "protected_edit":
            start = self.spec["evaluator"]["start_dir"]
            excl = {x["path"] for x in self.spec.get("required_exclude", [])}
            t = sorted(p for p in (d / start).rglob("test*.py") if str(p.relative_to(d)) not in excl)[0]
            t.write_text(t.read_text() + "\n# edited by the agent\n")
        return d


def steps_for(ctx: Ctx, spec: list[str]) -> list[dict]:
    out = []
    for s in spec:
        if s.startswith("BATCH:"):
            out.append({"label": "batch4", "kind": "batch", "trees": [str(ctx.tree(k)) for k in s[6:].split(",")]})
        elif s.startswith("CORRUPT:"):
            t = ctx.tree(s[8:]); out.append({"label": "corrupt:" + s[8:], "kind": "corrupt_then_verify", "tree": str(t), "corrupt_path": ctx.spec["benign"]["path"].replace("vep_extra", "vep_extra" + s[13:]), "expect": "corruption_rejected"})
        elif s.startswith("CANCEL:"):
            out.append({"label": "cancel_retry:" + s[7:], "kind": "cancel_retry", "tree": str(ctx.tree(s[7:])), "expect": "pass"})
        else:
            parts = s.split(":")
            large = parts[0] == "LARGE"
            kind, exp = (parts[1], parts[2]) if large else (parts[0], parts[1])
            out.append({"label": ("large_" if large else "") + kind, "kind": "verify", "tree": str(ctx.tree("LARGE" + (":tiny" if kind == "tiny" else "") if large else kind)), "expect": exp})
    return out


def run_direct(ctx, evalpy, tree, large=False):
    cmd = [evalpy, *ctx.spec["direct_cmd"]] if not large else [evalpy, "-I", "-m", "unittest", "discover", "-s", "tests", "-p", "test*.py", "-t", "."]
    rc, w, c, r, _ = P.run_proc(cmd, Path(tree))
    return {"rc": rc, "wall": w, "cpu": c, "rss": r}


def baseline_system(ctx, system, steps, a, large):
    res = []
    if system == "TESTMON":
        work = ctx.tmp / "testmon-work"; shutil.copytree(steps[0]["tree"], work, ignore=shutil.ignore_patterns(".git")) if steps[0]["kind"] == "verify" else None
    for st in steps:
        if st["kind"] not in ("verify", "batch"):
            res.append({"label": st["label"], "not_applicable": "no direct/incremental analogue (VEP lifecycle step)"}); continue
        if st["kind"] == "batch":
            trees = st["trees"]
            if system == "DIRECT_SEQ":
                t0 = time.perf_counter(); rs = [run_direct(ctx, a.evalpy, t) for t in trees]; wall = time.perf_counter() - t0
            elif system == "DIRECT_PAR":
                t0 = time.perf_counter()
                with ThreadPoolExecutor(a.workers) as ex:
                    rs = list(ex.map(lambda t: run_direct(ctx, a.evalpy, t), trees))
                wall = time.perf_counter() - t0
            else:
                res.append({"label": st["label"], "not_applicable": "single working tree"}); continue
            res.append({"label": st["label"], "wall_s": wall, "feedback_s": wall / len(trees) if system == "DIRECT_PAR" else None, "verdict_s": wall, "authorized_s": None,
                        "cpu_s": sum(r["cpu"] for r in rs), "rss_mb": max(r["rss"] for r in rs), "outcome_ok": all(r["rc"] == 0 for r in rs), "jobs_per_s": len(trees) / wall})
            continue
        if system == "DIRECT_PAR":
            res.append({"label": st["label"], "not_applicable": "single candidate: identical to DIRECT_SEQ"}); continue
        if system == "TESTMON":
            shutil.copytree(st["tree"], work, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git"))
            rc, w, c, r, _ = P.run_proc([a.testmon_py, "-m", "pytest", "--testmon", "-q", "-x", *ctx.spec["pytest_targets"]], work)
            rc = 0 if rc in (0, 5) else rc
        else:
            d = run_direct(ctx, a.evalpy, st["tree"], large=bool(st["label"].startswith("large_"))); rc, w, c, r = d["rc"], d["wall"], d["cpu"], d["rss"]
        want_pass = st["expect"] == "pass"
        res.append({"label": st["label"], "wall_s": w, "feedback_s": w, "verdict_s": w, "authorized_s": None, "cpu_s": c, "rss_mb": r,
                    "outcome_ok": (rc == 0) == want_pass if st["expect"] != "policy_reject" else None,
                    "note": "protected-test edits are not detected by this system" if st["expect"] == "policy_reject" and rc == 0 else None})
    return res


def vep_system(ctx, system, steps, a, large):
    flags = "none" if system == "VEP_BASE" else a.opt_flags
    ws = ctx.tmp / f"ws{ctx.n}-{system}"
    base_tree = Path(steps[0]["tree"]) if steps[0]["kind"] == "verify" else None
    if base_tree is None:
        base_tree = Path(ctx.tree("clean"))
    env = dict(os.environ, VEP_PERF=flags)
    proj = "synthetic" if large else ctx.project
    subprocess.run([a.evalpy, str(DRIVER), "setup", "--ws", str(ws), "--tree", str(base_tree), "--project", proj], check=True, capture_output=True, env=env)
    sf = ctx.tmp / f"steps-{system}.json"; sf.write_text(json.dumps(steps))
    argv = [a.evalpy, str(DRIVER), "trace", "--ws", str(ws), "--steps", str(sf), "--workers", str(a.workers if any(s["kind"] == "batch" for s in steps) and system != "VEP_BASE" else 1),
            "--system", {"VEP_BASE": "fresh", "VEP_OPT": "fresh", "VEP_REUSE": "reuse", "VEP_ADVISORY": "advisory"}[system]]
    t0 = time.perf_counter()
    p = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _, status, ru = os.wait4(p.pid, 0)
    out, err = p.stdout.read(), p.stderr.read()
    total = time.perf_counter() - t0
    try:
        j = json.loads(out.strip().splitlines()[-1])
    except Exception:
        return [{"label": "ALL", "error": f"driver failed: {err[-300:]}"}], total
    rows = []
    for st, r in zip(steps, j["steps"]):
        exp = st.get("expect")
        ok = None
        if st["kind"] in ("verify", "cancel_retry"):
            passed = r["outcome"] in ("FRESH_CERTIFICATE", "DERIVED_ATTESTATION")
            ok = passed if exp == "pass" else (r["outcome"] == "REJECTED")
            if r.get("authorized") is False:
                ok = False
        elif st["kind"] == "corrupt_then_verify":
            ok = not r["certificate"]
        elif st["kind"] == "batch":
            ok = r["certified"] == r["candidates"]
        rows.append({**r, "rss_mb": j["peak_rss_children_mb"], "outcome_ok": ok})
    return rows, total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True); ap.add_argument("--src", required=True); ap.add_argument("--evalpy", required=True); ap.add_argument("--testmon-py", required=True)
    ap.add_argument("--opt-flags", default="staging_fast,verified_handoff"); ap.add_argument("--reps", type=int, default=5); ap.add_argument("--warmups", type=int, default=1)
    ap.add_argument("--workers", type=int, default=4); ap.add_argument("--scenarios", nargs="*"); ap.add_argument("--include-large", action="store_true")
    ap.add_argument("--systems", nargs="*", default=SYSTEMS); ap.add_argument("--seed", type=int, default=20261019); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    import random
    rng = random.Random(a.seed)
    names = [n for n in SCENARIOS if (not a.scenarios or any(n.startswith(s) for s in a.scenarios)) and (a.include_large or "LARGE" not in " ".join(SCENARIOS[n]))]
    doc = {"kind": "agent workflow benchmark", "project": a.project, "project_commit": SPECS[a.project]["commit"], "opt_flags": a.opt_flags, "workers": a.workers, "reps": a.reps, "warmups": a.warmups,
           "seed": a.seed, "host": {"platform": platform.platform(), "cpus": os.cpu_count(), "python": platform.python_version(), "load_avg_1m_at_start": os.getloadavg()[0], **envinfo.env_probe()},
           "assurance": ASSUR, "scenarios": {}}
    for sc in names:
        large = "LARGE" in " ".join(SCENARIOS[sc])
        raws = []
        for rep in range(a.warmups + a.reps):
            ctx = Ctx(a, a.project, a.src)
            steps = steps_for(ctx, SCENARIOS[sc])
            order = [s for s in a.systems if not (large and s in ("TESTMON",))]
            rng.shuffle(order)
            rec = {"rep": rep, "warmup": rep < a.warmups, "order": order, "env": envinfo.env_probe(), "systems": {}}
            for s in order:
                try:
                    if s.startswith("VEP"):
                        rows, total = vep_system(ctx, s, steps, a, large)
                    else:
                        rows, total = baseline_system(ctx, s, steps, a, large), None
                except Exception as exc:  # recorded, never dropped
                    rows, total = [{"label": "ALL", "error": repr(exc)[:300]}], None
                rec["systems"][s] = {"steps": rows, "driver_total_s": total}
            subprocess.run(["chmod", "-R", "u+w", str(ctx.tmp)], capture_output=True); shutil.rmtree(ctx.tmp, ignore_errors=True)
            raws.append(rec)
            print(f"{sc} rep {rep}: " + " ".join(f"{k}={sum((x.get('wall_s') or 0) for x in v['steps']):.2f}" for k, v in rec["systems"].items()), flush=True)
        doc["scenarios"][sc] = {"trace": SCENARIOS[sc], "raw": raws}
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
